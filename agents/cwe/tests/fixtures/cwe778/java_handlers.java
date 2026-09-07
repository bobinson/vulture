package com.example.reporting;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Batch export of report rows.
 *
 * CWE-778 exception-family fixture for feature 0087. Markers:
 * {@code EXPECT: finding} / {@code EXPECT: clean}, either trailing on the
 * handler header or on the comment line immediately above it.
 * EXPECTATIONS.md records the line numbers.
 */
public final class ReportExporter {

    private static final Logger LOG = LoggerFactory.getLogger(ReportExporter.class);
    private static final String SELECT_PENDING =
            "SELECT id, payload, updated_at FROM report_rows WHERE state = 'pending'";

    private final DataSource dataSource;

    public ReportExporter(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    public Optional<Instant> parseUpdatedAt(String raw) {
        try {
            return Optional.of(Instant.parse(raw));
        } catch (DateTimeParseException | NullPointerException e) { // EXPECT: finding -- id=java_multi_catch -- multi-catch returns empty, records nothing
            return Optional.empty();
        }
    }

    public List<String> loadPending() {
        List<String> rows = new ArrayList<>();
        try (Connection conn = dataSource.getConnection();
                PreparedStatement ps = conn.prepareStatement(SELECT_PENDING);
                ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                rows.add(rs.getString("payload"));
            }
        } catch (SQLException e) { // EXPECT: clean -- id=java_try_with_resources_logs -- try-with-resources handler records the failure
            LOG.error("pending export query failed", e);
        }
        return rows;
    }

    public String readTemplate(Path path) {
        // EXPECT: clean -- id=java_header_line_log -- defect B1: the whole
        // handler, log call included, is on the header line.
        try { return Files.readString(path, StandardCharsets.UTF_8); } catch (IOException e) { LOG.warn("template {} unreadable, using the built-in default", path, e); }
        return "{{body}}";
    }

    public void writeTemplate(Path path, String body) {
        try {
            Files.writeString(path, body, StandardCharsets.UTF_8);
        } catch (IOException e) { // EXPECT: clean -- id=java_rethrow -- wrapped and propagated to the caller
            throw new UncheckedIOException("could not persist template " + path, e);
        }
    }

    public long countRows(Path exportFile) {
        try {
            return Files.lines(exportFile).count();
        } catch (IOException e) { // EXPECT: finding -- id=java_scope_leak -- defect
            return 0L;            // B2: the log call below belongs to recordExportSize()
        }
    }

    public void recordExportSize(Path exportFile, long rowCount) {
        LOG.info("export {} contains {} rows", exportFile, rowCount);
    }

    public byte[] readArchive(Path path) {
        try {
            return Files.readAllBytes(path);
        }
        // EXPECT: finding -- id=java_allman -- Allman brace style: the opening
        // brace is on the line after the catch header, and the body swallows.
        catch (IOException e)
        {
            return new byte[0];
        }
    }
}
