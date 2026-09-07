# frozen_string_literal: true

# Export cursor storage for the reporting service.
#
# CWE-778 exception-family fixture for feature 0087. Markers:
# `EXPECT: finding` / `EXPECT: clean` on the comment line immediately ABOVE
# the handler header, or trailing on a single-line (modifier) handler.
# EXPECTATIONS.md records the line numbers.

require "fileutils"
require "json"
require "net/http"
require "uri"

module Reporting
  # Reads and writes per-report export cursors.
  class CursorStore
    CURSOR_SUFFIX = ".cursor"

    def initialize(root)
      @root = root
    end

    def decode_cursor(raw)
      JSON.parse(raw)
    # EXPECT: finding -- id=rb_rescue_swallow -- `rescue => e` returns an empty
    # cursor and records nothing about the parse failure.
    rescue JSON::ParserError, TypeError => e
      {}
    end

    def write_cursor(name, cursor)
      File.write(path_for(name), JSON.dump(cursor))
    # EXPECT: clean -- id=rb_logs -- the failure is recorded before we give up.
    rescue Errno::EACCES, Errno::ENOSPC => e
      Rails.logger.error("cursor #{name} could not be persisted: #{e.message}")
      nil
    end

    def touch_marker(name)
      # EXPECT: clean -- id=rb_modifier_logs -- defect B1 analogue: the modifier
      # form keeps its whole body on the header line, and that body logs.
      FileUtils.touch(path_for(name)) rescue Rails.logger.warn("marker #{name} not writable")
    end

    def require_cursor(name)
      File.read(path_for(name))
    # EXPECT: clean -- id=rb_reraise -- wrapped and re-raised for the caller.
    rescue Errno::ENOENT => e
      raise CursorMissing, "cursor #{name} is required but absent: #{e.message}"
    end

    def count_rows(export_file)
      File.foreach(export_file).count
    # EXPECT: finding -- id=rb_scope_leak -- defect B2: swallowed here; the log
    # call below belongs to record_export_size, not to this handler.
    rescue Errno::ENOENT
      0
    end

    def record_export_size(export_file, rows)
      Rails.logger.info("export #{export_file} contains #{rows} rows")
    end

    def cached_manifest(url)
      # EXPECT: finding -- id=rb_modifier_nil -- modifier rescue collapses every
      # StandardError to nil, so a fetch failure is indistinguishable from an
      # empty manifest.
      body = Net::HTTP.get(URI(url)) rescue nil
      body.to_s
    end

    def purge(name)
      # rescue: retries are the caller's job -- EXPECT: clean -- id=rb_comment_rescue -- the keyword on this line is inside a comment, not a handler site
      FileUtils.rm_f(path_for(name))
    # EXPECT: clean -- id=rb_ensure -- `ensure` is a cleanup clause, not an
    # error handler, so it is not a handler site at all.
    ensure
      @root = @root.to_s
    end

    private

    def path_for(name)
      File.join(@root, "#{name}#{CURSOR_SUFFIX}")
    end
  end

  class CursorMissing < StandardError; end
end
