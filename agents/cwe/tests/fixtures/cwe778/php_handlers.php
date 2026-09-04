<?php

declare(strict_types=1);

namespace App\Reporting;

use Illuminate\Support\Facades\Log;
use JsonException;
use RuntimeException;

/**
 * Export cursor storage for the reporting service.
 *
 * CWE-778 exception-family fixture for feature 0087. Markers:
 * `EXPECT: finding` / `EXPECT: clean`, trailing on the handler header or on
 * the comment line immediately above it. EXPECTATIONS.md records the line
 * numbers.
 */
final class CursorStore
{
    private const CURSOR_SUFFIX = '.cursor';

    public function __construct(private readonly string $root)
    {
    }

    /**
     * Decode a stored cursor document.
     *
     * @param string $raw encoded cursor payload -- EXPECT: clean -- id=php_docblock_at_param -- the `@` of a docblock tag is not an error-suppression site
     *
     * @return array<string, string> decoded cursor, empty when unusable
     */
    public function decodeCursor(string $raw): array
    {
        try {
            return json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException | \ValueError $e) { // EXPECT: finding -- id=php_union_catch -- union catch returns an empty cursor with no record
            return [];
        }
    }

    public function writeCursor(string $name, string $cursor): void
    {
        try {
            file_put_contents($this->path($name), $cursor);
        } catch (RuntimeException $e) { // EXPECT: clean -- id=php_laravel_log -- Laravel Log::error records the failure
            Log::error('cursor could not be persisted', ['name' => $name, 'error' => $e]);
        }
    }

    public function touchMarker(string $name): bool
    {
        // EXPECT: clean -- id=php_header_line_log -- defect B1: the whole
        // handler, syslog call included, is on the header line.
        try { touch($this->path($name)); } catch (RuntimeException $e) { syslog(LOG_ERR, 'marker not writable: ' . $e->getMessage()); return false; }
        return true;
    }

    public function requireCursor(string $name): string
    {
        try {
            return $this->readOrFail($this->path($name));
        } catch (RuntimeException $e) { // EXPECT: clean -- id=php_rethrow -- wrapped and propagated
            throw new RuntimeException("cursor {$name} is required but unreadable", 0, $e);
        }
    }

    public function reportCursor(string $name): array
    {
        try {
            return $this->decodeCursor($this->readOrFail($this->path($name)));
        } catch (RuntimeException $e) { // EXPECT: clean -- id=php_report_delegate -- report() hands the throwable to the framework handler
            report($e);
            return [];
        }
    }

    public function countRows(string $exportFile): int
    {
        try {
            return count(file($exportFile, FILE_IGNORE_NEW_LINES));
        } catch (RuntimeException $e) { // EXPECT: finding -- id=php_scope_leak -- defect
            return 0;                   // B2: the log call below is recordExportSize()'s
        }
    }

    public function recordExportSize(string $exportFile, int $rows): void
    {
        Log::info('export size recorded', ['file' => $exportFile, 'rows' => $rows]);
    }

    public function cachedManifest(string $url): string
    {
        // EXPECT: finding -- id=php_at_suppression -- the `@` operator discards
        // the warning and the caller cannot tell a fetch failure from an empty
        // manifest.
        $body = @file_get_contents($url);

        return $body === false ? '' : $body;
    }

    private function readOrFail(string $path): string
    {
        $body = file_get_contents($path);
        if ($body === false) {
            throw new RuntimeException("unreadable: {$path}");
        }

        return $body;
    }

    private function path(string $name): string
    {
        return rtrim($this->root, '/') . '/' . $name . self::CURSOR_SUFFIX;
    }
}
