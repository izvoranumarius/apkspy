#pragma once
#include <cstdint>
#include <string>
#include <vector>

// Android App Bundles (.aab) keep each module's AndroidManifest.xml as an aapt2 protobuf (`XmlNode`), not as the
// binary XML an APK holds. This converts it to binary XML so the rest of ApkSpy (manifest viewer, Overview,
// permissions, components) reads a bundle's manifest the way it reads an APK's.
namespace protoxml {

// `pb` is the serialized XmlNode. On success `axml` holds a binary AndroidManifest.xml. Attribute values keep their
// types when the protobuf carries them (references, integers, booleans, floats), otherwise they are strings.
bool toBinaryXml(const std::vector<uint8_t>& pb, std::vector<uint8_t>& axml, std::string& error);

// An aapt2 protobuf resource table (`resources.pb`, a serialized ResourceTable) as a binary resources.arsc: every
// entry with its type and name, in every configuration, including styles, arrays, plurals and attributes.
// (Styleables are compile-time only and have no entry in an APK's table either.)
bool toArsc(const std::vector<uint8_t>& pb, std::vector<uint8_t>& arsc, std::string& error);

}  // namespace protoxml
