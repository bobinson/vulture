using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Example.Reporting;

/// <summary>
/// Export repository for the reporting service.
///
/// CWE-778 exception-family fixture for feature 0087. Markers:
/// <c>EXPECT: finding</c> / <c>EXPECT: clean</c>, trailing on the handler
/// header or on the comment line immediately above it. EXPECTATIONS.md
/// records the line numbers.
/// </summary>
public sealed class ExportRepository
{
    private const string SelectPending =
        "SELECT Id, Payload FROM ReportRows WHERE State = 'pending'";

    private readonly IDbConnection _connection;
    private readonly ILogger<ExportRepository> _logger;

    public ExportRepository(IDbConnection connection, ILogger<ExportRepository> logger)
    {
        _connection = connection;
        _logger = logger;
    }

    public IReadOnlyList<string> LoadPending()
    {
        var rows = new List<string>();
        try
        {
            using var command = _connection.CreateCommand();
            command.CommandText = SelectPending;
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                rows.Add(reader.GetString(1));
            }
        }
        catch (SqlException ex) when (ex.Number == 1205) // EXPECT: finding -- id=cs_when_filter -- exception filter, deadlock victim retried silently
        {
            rows.Clear();
        }

        return rows;
    }

    public async Task<string> ReadCursorAsync(string path, CancellationToken token)
    {
        try
        {
            return await File.ReadAllTextAsync(path, token).ConfigureAwait(false);
        }
        catch (IOException ex) // EXPECT: clean -- id=cs_logs -- the failure is recorded
        {
            _logger.LogError(ex, "cursor file {Path} could not be read", path);
            return string.Empty;
        }
    }

    public Dictionary<string, string> ParseCursorTags(string raw)
    {
        // EXPECT: clean -- id=cs_header_line_log -- defect B1: the whole handler,
        // log call included, sits on the header line.
        try { return JsonSerializer.Deserialize<Dictionary<string, string>>(raw) ?? new(); } catch (JsonException ex) { _logger.LogWarning(ex, "cursor tags unparseable"); }
        return new Dictionary<string, string>();
    }

    public void WriteCursor(string path, string cursor)
    {
        try
        {
            File.WriteAllText(path, cursor);
        }
        catch (IOException ex) // EXPECT: clean -- id=cs_rethrow -- wrapped and propagated
        {
            throw new InvalidOperationException($"cursor {path} is not writable", ex);
        }
    }

    public long CountRows(string exportFile)
    {
        try
        {
            return File.ReadLines(exportFile).LongCount();
        }
        catch (IOException) // EXPECT: finding -- id=cs_scope_leak -- defect B2: the
        {
            return 0L;      // log call below belongs to RecordExportSize()
        }
    }

    public void RecordExportSize(string exportFile, long rowCount)
    {
        _logger.LogInformation("export {File} contains {Rows} rows", exportFile, rowCount);
    }

    public void TouchMarker(string path)
    {
        try { File.SetLastWriteTimeUtc(path, DateTime.UtcNow); } catch (InvalidOperationException) { } // EXPECT: finding -- id=cs_empty_no_variable -- variable-less catch with a completely empty body
    }
}
