#pragma once
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include "smali/Validate.hpp"

// Edited source files: export (feature 2) and the per-file edit report /
// diff (feature 3).
//
// Everything here operates on source text held in memory - the edited
// workspace's original and current text of each file. Nothing reads an APK,
// executes anything or produces a package: the export writes the edited
// source files as plain text files into a directory the user picked, and
// that is all it does. It does not call apksigner, zipalign, apktool or any
// other build tool, never touches a keystore, and the output is not an
// installable artifact.
namespace edits {

// One file of the edited workspace.
struct EditedFile {
    std::string path;      // workspace-relative, '/'-separated ("smali/com/app/Main.smali")
    std::string original;  // text before the first edit
    std::string edited;    // current text (unsaved edits included)
    // Smali text to validate in place of `edited`, when the edited text is a
    // fragment (a single-method listing): the full class with the edited
    // method spliced in - see spliceMethod(). Diagnostics are mapped back to
    // `edited`'s lines; those outside the fragment are dropped.
    std::optional<std::string> validationText;
    int validationLineOffset = 0;  // fragment line i == validationText line i + offset
    int fragmentLines = 0;         // lines of `edited` covered by the mapping
    bool changed() const { return original != edited; }
    bool isSmali() const;          // by extension (".smali")
};

// ---------------------------------------------------------------------------
// Feature 2: export
// ---------------------------------------------------------------------------

struct ExportOptions {
    bool overwrite = false;         // replace files that already exist in the destination
    bool includeUnchanged = false;  // also write files whose text equals the original
    bool writePatch = true;         // also write "edits.patch" (unified diff of every exported file)
};

struct ExportItem {
    enum class Status { Written, Unchanged, Exists, InvalidPath, Failed };
    std::string path;     // EditedFile::path
    std::string written;  // sanitised relative path inside the destination (Written / Exists)
    Status status = Status::Failed;
    std::string reason;   // human-readable detail for Failed / InvalidPath
};

struct ExportResult {
    std::vector<ExportItem> items;  // one per input file, input order
    int written = 0;
    int failed = 0;  // Exists + InvalidPath + Failed
    bool patchWritten = false;
    std::string error;  // destination-level failure (not a directory, cannot create it)
    bool ok() const { return error.empty() && failed == 0; }
};

// Writes each changed file's edited text to `destDir`/<path>. Paths pass
// through the SafePath sanitiser, so a crafted name can never escape
// `destDir`. Creates `destDir` (and sub-directories) as needed; never
// overwrites an existing file unless `options.overwrite`. Text is written
// byte for byte (no newline conversion).
ExportResult exportEdits(std::span<const EditedFile> files, const std::filesystem::path& destDir,
                         const ExportOptions& options = {});

// ---------------------------------------------------------------------------
// Feature 3: per-file report / diff
// ---------------------------------------------------------------------------

// Unified diff ("--- a/path", "+++ b/path", "@@ -l,n +l,n @@" hunks) with
// `context` lines of context; empty when the texts are equal. A missing
// final newline is marked with "\ No newline at end of file".
std::string unifiedDiff(std::string_view path, std::string_view original, std::string_view edited, int context = 3);

struct FileReport {
    std::string path;
    bool changed = false;
    int added = 0;    // lines
    int removed = 0;  // lines
    int hunks = 0;
    std::string diff;  // unifiedDiff() of the file
    bool validated = false;  // smali checked against the universe
    std::vector<smali::Diagnostic> errors;    // lines refer to `edited`
    std::vector<smali::Diagnostic> warnings;
};

struct EditReport {
    std::vector<FileReport> files;  // input order
    int changedFiles = 0, added = 0, removed = 0, errors = 0, warnings = 0;
};

// Diffs every file; smali files are also validated - together, as one set -
// against `universe` when it is given (null: no validation).
EditReport buildReport(std::span<const EditedFile> files, const smali::ClassUniverse* universe);

// Plain-text rendering: a summary table, then each changed file's
// diagnostics and diff. Stable output (the tests compare it).
std::string renderText(const EditReport& report);

// ---------------------------------------------------------------------------
// Smali fragments
// ---------------------------------------------------------------------------

struct Spliced {
    std::string text;      // the class text with the method replaced
    int lineOffset = 0;    // fragment line i (0-based) == text line i + lineOffset
    int fragmentLines = 0; // lines of the fragment
};

// Replaces, in a full class listing, the method whose ".method" line names
// the same method (name + prototype) as the fragment's first ".method" line
// with the fragment's ".method ... .end method" block. Lines of the fragment
// before ".method" (ApkSpy's "# signature" header) are mapped too. nullopt
// when the fragment has no method block or the class has no such method.
std::optional<Spliced> spliceMethod(std::string_view classText, std::string_view fragment);

}  // namespace edits
