// Report export pipeline (native ingest worker).
//
// CWE-778 exception-family fixture for feature 0087. `.cpp` is absent from the
// skill's extension gate today, so nothing here is scanned by the shipped
// detector. Markers: `EXPECT: finding` / `EXPECT: clean`, trailing on the
// handler header or on the comment line immediately above it.
// EXPECTATIONS.md records the line numbers.

#include <syslog.h>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace reporting {

namespace {
constexpr std::size_t kMaxManifestBytes = 1U << 20U;
}  // namespace

struct Cursor {
  std::string id;
  std::uint64_t updated_at = 0;
};

Cursor ParseCursor(const std::string& raw) {
  Cursor cursor;
  try {
    const auto doc = nlohmann::json::parse(raw);
    cursor.id = doc.at("id").get<std::string>();
    cursor.updated_at = doc.at("updated_at").get<std::uint64_t>();
  } catch (...) {  // EXPECT: finding -- id=cpp_catch_all -- catch-all leaves a default-constructed cursor behind
    cursor.id.clear();
  }
  return cursor;
}

std::vector<std::string> ReadManifest(const std::string& path) {
  std::vector<std::string> entries;
  try {
    std::ifstream in(path);
    in.exceptions(std::ifstream::failbit | std::ifstream::badbit);
    std::string line;
    while (std::getline(in, line)) {
      entries.push_back(line);
    }
  } catch (const std::ios_base::failure& e) {  // EXPECT: clean -- id=cpp_logs -- by-const-ref handler records the failure
    spdlog::error("manifest {} unreadable: {}", path, e.what());
  }
  return entries;
}

bool TouchMarker(const std::string& path) {
  // EXPECT: clean -- id=cpp_header_line_log -- defect B1: the whole handler,
  // including the syslog call, is on the header line.
  try { std::ofstream(path, std::ios::app) << '\n'; } catch (const std::exception& e) { syslog(LOG_ERR, "marker %s not writable: %s", path.c_str(), e.what()); return false; }
  return true;
}

std::uint64_t ParseSize(const std::string& raw) {
  try {
    return std::stoull(raw);
  } catch (const std::invalid_argument& e) {  // EXPECT: clean -- id=cpp_rethrow -- wrapped and propagated
    throw std::runtime_error("manifest size field is not a number: " + raw);
  }
}

std::size_t CountRows(const std::string& path) {
  try {
    std::ifstream in(path);
    return static_cast<std::size_t>(std::count(std::istreambuf_iterator<char>(in),
                                               std::istreambuf_iterator<char>(), '\n'));
  } catch (const std::exception& e) {  // EXPECT: finding -- id=cpp_scope_leak -- defect
    return 0;                          // B2: the log call below is RecordExportSize()'s
  }
}

void RecordExportSize(const std::string& path, std::size_t rows) {
  spdlog::info("export {} contains {} rows", path, rows);
}

std::string ReadTruncated(const std::string& path) {
  std::string body;
  try {
    std::ifstream in(path);
    std::ostringstream buffer;
    buffer << in.rdbuf();
    body = buffer.str().substr(0, kMaxManifestBytes);
  } catch (const std::exception& e) {  // EXPECT: finding -- id=cpp_swallow_by_value_default -- body swallows and returns an empty document
    body.clear();
  }
  return body;
}

}  // namespace reporting
