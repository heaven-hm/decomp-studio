// Import PCRecomp's Ghidra ExportFunctions output into a provenance-bearing
// interchange record. Analysis is performed by Ghidra, not by this parser.
#include "core/common/sha256.hpp"
#include <cctype>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

static std::string trim(std::string s) {
  const auto first = s.find_first_not_of(" \t\r\n");
  return first == std::string::npos ? "" : s.substr(first, s.find_last_not_of(" \t\r\n") - first + 1);
}
static std::string quoted(const std::string& s) {
  std::ostringstream out;
  out << '"';
  for (unsigned char c : s) {
    if (c == '"' || c == '\\') out << '\\' << c;
    else if (c < 0x20) { const char* hex = "0123456789abcdef"; out << "\\u00" << hex[c >> 4] << hex[c & 15]; }
    else out << c;
  }
  return out.str() + '"';
}
int main(int argc, char** argv) {
  if (argc != 4) {
    std::cerr << "usage: ghidra-import <binary> <ExportFunctions output> <ghidra version>\n";
    return 2;
  }
  std::ifstream binary(argv[1], std::ios::binary), input(argv[2], std::ios::binary);
  if (!binary || !input) { std::cerr << "cannot read binary or Ghidra export\n"; return 1; }
  std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(binary)), {});
  std::vector<unsigned char> export_bytes((std::istreambuf_iterator<char>(input)), {});
  std::istringstream export_stream(std::string(export_bytes.begin(), export_bytes.end()));
  std::vector<std::vector<std::string>> rows;
  std::string line;
  while (std::getline(export_stream, line)) {
    if (line.empty() || line[0] == '#') continue;
    std::vector<std::string> fields;
    std::istringstream stream(line);
    std::string field;
    while (std::getline(stream, field, '|')) fields.push_back(trim(field));
    if (fields.size() != 6 || fields[0].empty() ||
        fields[0].find_first_not_of("0123456789abcdefABCDEF") != std::string::npos ||
        fields[1].find_first_not_of("0123456789") != std::string::npos || fields[1].empty() ||
        fields[2].find_first_not_of("0123456789") != std::string::npos || fields[2].empty()) {
      std::cerr << "invalid Ghidra export row: " << line << '\n'; return 1;
    }
    rows.push_back(fields);
  }
  if (rows.empty()) { std::cerr << "Ghidra export contains no functions\n"; return 1; }
  std::cout << "{\"schema_version\":1,\"binary_sha256\":" << quoted(recomp::common::sha256(bytes))
            << ",\"export_sha256\":" << quoted(recomp::common::sha256(export_bytes))
            << ",\"provider_claim\":\"Ghidra\",\"provider_version_claim\":" << quoted(argv[3])
            << ",\"export_format\":\"pcrecomp ExportFunctions\","
               "\"binary_export_association\":\"unverified\","
               "\"verification\":\"unverified\",\"functions\":[";
  bool first = true;
  for (const auto& row : rows) {
    if (!first) std::cout << ',';
    first = false;
    std::cout << "{\"address\":" << quoted(row[0]) << ",\"body_bytes\":" << row[1]
              << ",\"references\":" << row[2] << ",\"calling_convention\":" << quoted(row[3])
              << ",\"flags\":" << quoted(row[4]) << ",\"name\":" << quoted(row[5])
              << ",\"confidence\":\"unknown\",\"verification\":\"unverified\"}";
  }
  std::cout << "]}\n";
}
