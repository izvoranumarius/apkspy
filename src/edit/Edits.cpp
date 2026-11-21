#include "edit/Edits.hpp"
#include <algorithm>
#include <cstdio>
#include <fstream>
#include <system_error>
#include "core/SafePath.hpp"

namespace edits {

namespace fs = std::filesystem;

bool EditedFile::isSmali() const {
    constexpr std::string_view ext = ".smali";
    return path.size() >= ext.size() && path.compare(path.size() - ext.size(), ext.size(), ext) == 0;
}

namespace {

// Lines without their '\n' (a '\r' stays part of the line, so CRLF changes
// show up in the diff). `lastHasNewline` is false when the text does not
// end with '\n' (and is not empty).
struct Lines {
    std::vector<std::string_view> v;
    bool lastHasNewline = true;
};

Lines split(std::string_view s) {
    Lines out;
    size_t pos = 0;
    while (pos < s.size()) {
        size_t e = s.find('\n', pos);
        if (e == std::string_view::npos) {
            out.v.push_back(s.substr(pos));
            out.lastHasNewline = false;
            break;
        }
        out.v.push_back(s.substr(pos, e - pos));
        pos = e + 1;
    }
    return out;
}

enum class Op : char { Equal = ' ', Delete = '-', Insert = '+' };
struct Edit {
    Op op;
    int a, b;  // line index in A (Equal / Delete) and B (Equal / Insert)
};

// Myers' O(ND) diff; falls back to "delete all, insert all" of the middle
// part when more than `maxD` edits are needed.
std::vector<Edit> diffLines(const std::vector<std::string_view>& A, const std::vector<std::string_view>& B, int maxD = 4000) {
    const int n = static_cast<int>(A.size()), m = static_cast<int>(B.size());
    int head = 0;
    while (head < n && head < m && A[head] == B[head]) ++head;
    int tail = 0;
    while (tail < n - head && tail < m - head && A[n - 1 - tail] == B[m - 1 - tail]) ++tail;
    const int N = n - head - tail, M = m - head - tail;  // sizes of the middle part

    std::vector<Edit> out;
    for (int i = 0; i < head; ++i) out.push_back({Op::Equal, i, i});

    std::vector<Edit> mid;
    const int limit = std::min(maxD, N + M);
    const int off = limit + 1;
    std::vector<int> v(static_cast<size_t>(2 * off + 1), 0);
    std::vector<std::vector<int>> trace;
    bool found = N == 0 && M == 0;
    int dFound = 0;
    for (int d = 0; !found && d <= limit; ++d) {
        trace.push_back(v);
        for (int k = -d; k <= d; k += 2) {
            int x;
            if (k == -d || (k != d && v[off + k - 1] < v[off + k + 1])) x = v[off + k + 1];
            else x = v[off + k - 1] + 1;
            int y = x - k;
            while (x < N && y < M && A[head + x] == B[head + y]) ++x, ++y;
            v[off + k] = x;
            if (x >= N && y >= M) {
                found = true;
                dFound = d;
                break;
            }
        }
    }
    if (N == 0 && M == 0) {
        // nothing in the middle
    } else if (found) {
        int x = N, y = M;
        for (int d = dFound; d > 0; --d) {
            const std::vector<int>& pv = trace[static_cast<size_t>(d)];
            const int k = x - y;
            int prevK;
            if (k == -d || (k != d && pv[off + k - 1] < pv[off + k + 1])) prevK = k + 1;
            else prevK = k - 1;
            const int prevX = pv[off + prevK];
            const int prevY = prevX - prevK;
            while (x > prevX && y > prevY) --x, --y, mid.push_back({Op::Equal, head + x, head + y});
            if (x == prevX) --y, mid.push_back({Op::Insert, -1, head + y});
            else --x, mid.push_back({Op::Delete, head + x, -1});
        }
        while (x > 0 && y > 0) --x, --y, mid.push_back({Op::Equal, head + x, head + y});
        std::reverse(mid.begin(), mid.end());
    } else {
        for (int i = 0; i < N; ++i) mid.push_back({Op::Delete, head + i, -1});
        for (int j = 0; j < M; ++j) mid.push_back({Op::Insert, -1, head + j});
    }
    // Within each changed run, deletions first, then insertions.
    for (size_t i = 0; i < mid.size();) {
        if (mid[i].op == Op::Equal) {
            out.push_back(mid[i++]);
            continue;
        }
        size_t j = i;
        while (j < mid.size() && mid[j].op != Op::Equal) ++j;
        for (size_t k = i; k < j; ++k)
            if (mid[k].op == Op::Delete) out.push_back(mid[k]);
        for (size_t k = i; k < j; ++k)
            if (mid[k].op == Op::Insert) out.push_back(mid[k]);
        i = j;
    }
    for (int t = 0; t < tail; ++t) out.push_back({Op::Equal, n - tail + t, m - tail + t});
    return out;
}

struct DiffStats {
    std::string text;
    int added = 0, removed = 0, hunks = 0;
};

DiffStats makeDiff(std::string_view path, std::string_view original, std::string_view edited, int context) {
    DiffStats s;
    if (original == edited) return s;
    const Lines A = split(original), B = split(edited);
    const std::vector<Edit> ops = diffLines(A.v, B.v);
    const int nA = static_cast<int>(A.v.size()), nB = static_cast<int>(B.v.size());
    context = std::max(context, 0);

    s.text = "--- a/" + std::string(path) + "\n+++ b/" + std::string(path) + "\n";
    const auto lineOut = [&](const Edit& e) {
        const bool fromA = e.op != Op::Insert;
        const int idx = fromA ? e.a : e.b;
        const Lines& L = fromA ? A : B;
        s.text += static_cast<char>(e.op);
        s.text += L.v[static_cast<size_t>(idx)];
        s.text += '\n';
        if (idx + 1 == static_cast<int>(L.v.size()) && !L.lastHasNewline) s.text += "\\ No newline at end of file\n";
    };
    // An Equal line that is the last line of exactly one side differs in its
    // newline: treat it as a change so the marker shows up.
    std::vector<Edit> fixed;
    for (const Edit& e : ops) {
        if (e.op == Op::Equal) {
            const bool lastA = e.a + 1 == nA, lastB = e.b + 1 == nB;
            const bool nlA = !lastA || A.lastHasNewline, nlB = !lastB || B.lastHasNewline;
            if (nlA != nlB) {
                fixed.push_back({Op::Delete, e.a, -1});
                fixed.push_back({Op::Insert, -1, e.b});
                continue;
            }
        }
        fixed.push_back(e);
    }
    // Hunks: changed indices grouped when separated by <= 2*context equal lines.
    const int total = static_cast<int>(fixed.size());
    int i = 0;
    while (i < total) {
        while (i < total && fixed[i].op == Op::Equal) ++i;
        if (i >= total) break;
        int start = std::max(0, i - context);
        int end = i;  // exclusive end of the last change seen
        int j = i;
        while (j < total) {
            if (fixed[j].op != Op::Equal) {
                end = j + 1;
                ++j;
                continue;
            }
            int k = j;
            while (k < total && fixed[k].op == Op::Equal) ++k;
            if (k >= total || k - j > 2 * context) break;
            j = k;
        }
        const int stop = std::min(total, end + context);
        // Header line numbers.
        int aStart = -1, bStart = -1, aCount = 0, bCount = 0;
        for (int x = start; x < stop; ++x) {
            const Edit& e = fixed[x];
            if (e.op != Op::Insert) {
                if (aStart < 0) aStart = e.a;
                ++aCount;
            }
            if (e.op != Op::Delete) {
                if (bStart < 0) bStart = e.b;
                ++bCount;
            }
        }
        // Empty side: the line before the hunk (0 when at the start).
        const auto before = [&](bool sideA) {
            for (int x = start - 1; x >= 0; --x) {
                const Edit& e = fixed[x];
                if (sideA && e.op != Op::Insert) return e.a + 1;
                if (!sideA && e.op != Op::Delete) return e.b + 1;
            }
            return 0;
        };
        const int aLine = aCount ? aStart + 1 : before(true);
        const int bLine = bCount ? bStart + 1 : before(false);
        char hdr[96];
        std::snprintf(hdr, sizeof hdr, "@@ -%d,%d +%d,%d @@\n", aLine, aCount, bLine, bCount);
        s.text += hdr;
        for (int x = start; x < stop; ++x) {
            lineOut(fixed[x]);
            if (fixed[x].op == Op::Insert) ++s.added;
            if (fixed[x].op == Op::Delete) ++s.removed;
        }
        ++s.hunks;
        i = stop;
    }
    return s;
}

bool writeFile(const fs::path& p, std::string_view text) {
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    out.close();
    return static_cast<bool>(out);
}

// ".method <flags> name(proto)ret" -> "name(proto)ret"; empty when not a method line.
std::string methodKey(std::string_view line) {
    size_t p = line.find_first_not_of(" \t");
    if (p == std::string_view::npos) return {};
    line.remove_prefix(p);
    if (line.rfind(".method", 0) != 0 || (line.size() > 7 && line[7] != ' ' && line[7] != '\t')) return {};
    while (!line.empty() && (line.back() == ' ' || line.back() == '\t' || line.back() == '\r')) line.remove_suffix(1);
    const size_t sp = line.find_last_of(" \t");
    return sp == std::string_view::npos ? std::string() : std::string(line.substr(sp + 1));
}

bool isEndMethod(std::string_view line) {
    size_t p = line.find_first_not_of(" \t");
    return p != std::string_view::npos && line.substr(p).rfind(".end method", 0) == 0;
}

}  // namespace

// ---------------------------------------------------------------------------

ExportResult exportEdits(std::span<const EditedFile> files, const fs::path& destDir, const ExportOptions& options) {
    ExportResult r;
    std::error_code ec;
    if (fs::exists(destDir, ec) && !fs::is_directory(destDir, ec)) {
        r.error = "destination is not a directory";
        return r;
    }
    fs::create_directories(destDir, ec);
    if (ec || !fs::is_directory(destDir, ec)) {
        r.error = "cannot create the destination directory";
        return r;
    }
    std::string patch;
    for (const EditedFile& f : files) {
        ExportItem item;
        item.path = f.path;
        std::string rel;
        if (!f.changed() && !options.includeUnchanged) {
            item.status = ExportItem::Status::Unchanged;
        } else if (!safepath::relativePath(f.path, rel)) {
            item.status = ExportItem::Status::InvalidPath;
            item.reason = "no usable path";
        } else {
            item.written = rel;
            const fs::path target = destDir / fs::path(std::u8string(rel.begin(), rel.end()));
            if (fs::exists(target, ec) && !options.overwrite) {
                item.status = ExportItem::Status::Exists;
                item.reason = "already exists";
            } else {
                fs::create_directories(target.parent_path(), ec);
                if (writeFile(target, f.edited)) {
                    item.status = ExportItem::Status::Written;
                    if (f.changed()) patch += makeDiff(f.path, f.original, f.edited, 3).text;
                } else {
                    item.status = ExportItem::Status::Failed;
                    item.reason = "cannot write the file";
                }
            }
        }
        if (item.status == ExportItem::Status::Written) ++r.written;
        else if (item.status != ExportItem::Status::Unchanged) ++r.failed;
        r.items.push_back(std::move(item));
    }
    if (options.writePatch && !patch.empty()) {
        const fs::path p = destDir / "edits.patch";
        if (fs::exists(p, ec) && !options.overwrite) {
            r.error = "edits.patch already exists";
        } else if (writeFile(p, patch)) {
            r.patchWritten = true;
        } else {
            r.error = "cannot write edits.patch";
        }
    }
    return r;
}

std::string unifiedDiff(std::string_view path, std::string_view original, std::string_view edited, int context) {
    return makeDiff(path, original, edited, context).text;
}

EditReport buildReport(std::span<const EditedFile> files, const smali::ClassUniverse* universe) {
    EditReport rep;
    for (const EditedFile& f : files) {
        FileReport fr;
        fr.path = f.path;
        fr.changed = f.changed();
        DiffStats d = makeDiff(f.path, f.original, f.edited, 3);
        fr.added = d.added;
        fr.removed = d.removed;
        fr.hunks = d.hunks;
        fr.diff = std::move(d.text);
        rep.files.push_back(std::move(fr));
    }
    if (universe) {
        std::vector<smali::SourceFile> set;
        std::vector<size_t> owner;
        for (size_t i = 0; i < files.size(); ++i)
            if (files[i].isSmali()) {
                set.push_back({files[i].path, files[i].validationText ? *files[i].validationText : files[i].edited});
                owner.push_back(i);
                rep.files[i].validated = true;
            }
        if (!set.empty()) {
            const smali::ValidationResult v = smali::validate(set, *universe);
            const auto place = [&](const smali::Diagnostic& diag, bool error) {
                for (size_t k = 0; k < set.size(); ++k) {
                    if (set[k].path != diag.file) continue;
                    const EditedFile& f = files[owner[k]];
                    smali::Diagnostic d = diag;
                    if (f.validationText) {
                        const int line0 = d.line - 1 - f.validationLineOffset;
                        if (line0 < 0 || line0 >= f.fragmentLines) return;  // outside the edited fragment
                        d.line = line0 + 1;
                    }
                    (error ? rep.files[owner[k]].errors : rep.files[owner[k]].warnings).push_back(std::move(d));
                    return;
                }
            };
            for (const auto& e : v.errors) place(e, true);
            for (const auto& w : v.warnings) place(w, false);
        }
    }
    for (const FileReport& fr : rep.files) {
        if (fr.changed) ++rep.changedFiles;
        rep.added += fr.added;
        rep.removed += fr.removed;
        rep.errors += static_cast<int>(fr.errors.size());
        rep.warnings += static_cast<int>(fr.warnings.size());
    }
    return rep;
}

std::string renderText(const EditReport& report) {
    std::string out;
    char buf[256];
    std::snprintf(buf, sizeof buf, "Edit report: %d changed file(s), +%d -%d, %d error(s), %d warning(s)\n\n", report.changedFiles,
                  report.added, report.removed, report.errors, report.warnings);
    out += buf;
    for (const FileReport& f : report.files) {
        if (!f.changed) continue;
        std::snprintf(buf, sizeof buf, "  +%-5d -%-5d %3zu E %3zu W  ", f.added, f.removed, f.errors.size(), f.warnings.size());
        out += buf;
        out += f.path;
        out += '\n';
    }
    for (const FileReport& f : report.files) {
        if (!f.changed) continue;
        out += "\n== " + f.path + " ==\n";
        if (!f.validated && f.path.size() > 6 && f.path.ends_with(".smali")) out += "(not validated)\n";
        const auto diag = [&](const smali::Diagnostic& d, const char* sev) {
            std::snprintf(buf, sizeof buf, "%s:%d:%d: %s [%s] ", f.path.c_str(), d.line, d.column, sev, smali::checkName(d.check));
            out += buf;
            out += d.message;
            out += '\n';
        };
        for (const auto& d : f.errors) diag(d, "error");
        for (const auto& d : f.warnings) diag(d, "warning");
        out += f.diff;
    }
    return out;
}

std::optional<Spliced> spliceMethod(std::string_view classText, std::string_view fragment) {
    const Lines F = split(fragment);
    int fStart = -1, fEnd = -1;
    std::string key;
    for (int i = 0; i < static_cast<int>(F.v.size()); ++i) {
        if (fStart < 0) {
            key = methodKey(F.v[i]);
            if (!key.empty()) fStart = i;
        } else if (isEndMethod(F.v[i])) {
            fEnd = i;
            break;
        }
    }
    if (fStart < 0 || fEnd < 0) return std::nullopt;

    const Lines C = split(classText);
    int cStart = -1, cEnd = -1;
    for (int i = 0; i < static_cast<int>(C.v.size()); ++i) {
        if (cStart < 0) {
            if (methodKey(C.v[i]) == key) cStart = i;
        } else if (isEndMethod(C.v[i])) {
            cEnd = i;
            break;
        }
    }
    if (cStart < 0 || cEnd < 0) return std::nullopt;

    Spliced s;
    const auto append = [&](std::string_view l) {
        s.text += l;
        s.text += '\n';
    };
    for (int i = 0; i < cStart; ++i) append(C.v[i]);
    for (int i = fStart; i <= fEnd; ++i) append(F.v[i]);
    for (int i = cEnd + 1; i < static_cast<int>(C.v.size()); ++i) append(C.v[i]);
    s.lineOffset = cStart - fStart;
    s.fragmentLines = static_cast<int>(F.v.size());
    return s;
}

}  // namespace edits
