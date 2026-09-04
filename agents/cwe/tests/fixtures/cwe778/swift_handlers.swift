//
//  CursorStore.swift
//  Reporting
//
//  CWE-778 exception-family fixture for feature 0087. `.swift` is absent from
//  the skill's extension gate today and `_CATCH_LINE` cannot match Swift's
//  parenthesis-less `catch`, so nothing here is scanned by the shipped
//  detector. Markers: `EXPECT: finding` / `EXPECT: clean`, trailing on the
//  handler header or on the comment line immediately above it.
//  EXPECTATIONS.md records the line numbers.
//

import Foundation
import os

enum CursorError: Error {
    case missing(String)
    case unreadable(String, underlying: Error)
}

struct Cursor: Codable {
    let id: String
    let updatedAt: Date
}

final class CursorStore {

    private let root: URL
    private let log = Logger(subsystem: "dev.example.reporting", category: "cursor")

    init(root: URL) {
        self.root = root
    }

    func readCursor(name: String) -> Cursor? {
        do {
            let data = try Data(contentsOf: path(for: name))
            return try JSONDecoder().decode(Cursor.self, from: data)
        } catch { // EXPECT: finding -- id=swift_swallow -- bare `catch` returns nil with no record
            return nil
        }
    }

    func writeCursor(_ cursor: Cursor, name: String) {
        do {
            let data = try JSONEncoder().encode(cursor)
            try data.write(to: path(for: name), options: .atomic)
        } catch let error as EncodingError { // EXPECT: clean -- id=swift_typed_catch_logs -- typed catch records the failure
            log.error("cursor \(name, privacy: .public) could not be encoded: \(error)")
        } catch { // EXPECT: clean -- id=swift_catch_all_logs -- the catch-all arm records the failure too
            log.error("cursor \(name, privacy: .public) could not be written: \(error)")
        }
    }

    func touchMarker(name: String) -> Bool {
        // EXPECT: clean -- id=swift_header_line_log -- defect B1: the whole
        // handler, os_log call included, is on the header line.
        do { try Data().write(to: path(for: name)) } catch { os_log("marker not writable: %{public}@", "\(error)"); return false }
        return true
    }

    func requireCursor(name: String) throws -> Cursor {
        do {
            let data = try Data(contentsOf: path(for: name))
            return try JSONDecoder().decode(Cursor.self, from: data)
        } catch let error as DecodingError { // EXPECT: clean -- id=swift_rethrow -- wrapped and propagated
            throw CursorError.unreadable(name, underlying: error)
        }
    }

    func countRows(in exportFile: URL) -> Int {
        do {
            let body = try String(contentsOf: exportFile, encoding: .utf8)
            return body.split(separator: "\n").count
        } catch { // EXPECT: finding -- id=swift_scope_leak -- defect B2: the log
            return 0 // call below belongs to recordExportSize(), not to this handler
        }
    }

    func recordExportSize(_ exportFile: URL, rows: Int) {
        log.info("export \(exportFile.lastPathComponent, privacy: .public) has \(rows) rows")
    }

    func cachedManifest(at url: URL) -> String {
        // EXPECT: finding -- id=swift_try_optional -- `try?` collapses the error
        // to nil, so a read failure is indistinguishable from an empty file.
        let body = try? String(contentsOf: url, encoding: .utf8)

        return body ?? ""
    }

    private func path(for name: String) -> URL {
        root.appendingPathComponent("\(name).cursor")
    }
}
