package com.example.reporting

import java.io.File
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.time.format.DateTimeParseException
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory

/**
 * Export cursor storage for the reporting service.
 *
 * CWE-778 exception-family fixture for feature 0087. `.kt` is absent from the
 * skill's extension gate today, so nothing here is scanned by the shipped
 * detector. Markers: `EXPECT: finding` / `EXPECT: clean`, trailing on the
 * handler header or on the comment line immediately above it.
 * EXPECTATIONS.md records the line numbers.
 */
class CursorStore(private val root: File) {

    private val logger = LoggerFactory.getLogger(CursorStore::class.java)

    fun readCursor(name: String): String? {
        return try {
            File(root, "$name.cursor").readText(StandardCharsets.UTF_8)
        } catch (e: IOException) { // EXPECT: finding -- id=kt_swallow -- returns null, records nothing
            null
        }
    }

    fun writeCursor(name: String, cursor: String) {
        try {
            File(root, "$name.cursor").writeText(cursor, StandardCharsets.UTF_8)
        } catch (e: IOException) { // EXPECT: clean -- id=kt_logs -- the failure is recorded
            logger.error("cursor $name could not be persisted", e)
        }
    }

    fun parseUpdatedAt(raw: String): Instant? {
        // EXPECT: clean -- id=kt_header_line_log -- defect B1: the one-line
        // handler logs on the header line itself.
        try { return Instant.parse(raw) } catch (e: DateTimeParseException) { logger.warn("unparseable cursor timestamp '$raw'", e) }
        return null
    }

    fun requireCursor(name: String): String {
        try {
            return File(root, "$name.cursor").readText(StandardCharsets.UTF_8)
        } catch (e: IOException) { // EXPECT: clean -- id=kt_rethrow -- wrapped and propagated
            throw IllegalStateException("cursor $name is required but unreadable", e)
        }
    }

    fun countRows(exportFile: File): Long {
        try {
            return exportFile.useLines { it.count().toLong() }
        } catch (e: IOException) { // EXPECT: finding -- id=kt_scope_leak -- defect B2:
            return 0L              // the log call below belongs to recordExportSize()
        }
    }

    fun recordExportSize(exportFile: File, rows: Long) {
        logger.info("export {} contains {} rows", exportFile.name, rows)
    }

    fun decodeTags(raw: String): Map<String, String> {
        // EXPECT: finding -- id=kt_run_catching -- runCatching + getOrNull discards
        // the Throwable entirely.
        return runCatching { Json.decodeFromString<Map<String, String>>(raw) }.getOrNull()
            ?: emptyMap()
    }

    fun purge(name: String) {
        try {
            File(root, "$name.cursor").delete()
        } catch (e: SecurityException) { // EXPECT: finding -- id=kt_swallow_empty -- empty handler body
        }
    }
}
