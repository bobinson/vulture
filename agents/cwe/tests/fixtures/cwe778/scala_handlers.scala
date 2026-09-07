package com.example.reporting

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path}
import java.time.Instant
import java.time.format.DateTimeParseException

import scala.io.Source
import scala.util.Try
import scala.util.control.NonFatal

import com.fasterxml.jackson.core.JsonParseException
import org.slf4j.LoggerFactory

/** Export cursor storage for the reporting service.
  *
  * CWE-778 exception-family fixture for feature 0087. `.scala` is absent from
  * the skill's extension gate today and `_CATCH_LINE` cannot match Scala's
  * `case` arms, so nothing here is scanned by the shipped detector. Markers:
  * `EXPECT: finding` / `EXPECT: clean`, trailing on the `case` arm or on the
  * comment line immediately above it. Scala emits ONE SITE PER CASE ARM, not
  * one per `catch`. EXPECTATIONS.md records the line numbers.
  */
final class CursorStore(root: Path) {

  private val logger = LoggerFactory.getLogger(classOf[CursorStore])

  def decodeCursor(raw: String): Map[String, String] =
    try Cursors.parse(raw)
    catch {
      // EXPECT: finding -- id=scala_arm_parse -- this arm returns an empty map
      // and records nothing; the sibling arm below logs and must not excuse it.
      case _: JsonParseException => Map.empty
      // EXPECT: clean -- id=scala_arm_io -- this arm records the failure.
      case e: IllegalArgumentException =>
        logger.error(s"cursor payload rejected: ${e.getMessage}")
        Map.empty
    }

  def writeCursor(name: String, cursor: String): Unit =
    try Files.write(cursorPath(name), cursor.getBytes(StandardCharsets.UTF_8))
    catch {
      // EXPECT: clean -- id=scala_nonfatal_logs -- defect B1 analogue: the whole
      // arm body, log call included, sits on the `case` line.
      case NonFatal(e) => logger.error(s"cursor $name could not be persisted", e)
    }

  def requireCursor(name: String): String =
    try Source.fromFile(cursorPath(name).toFile).mkString
    catch {
      // EXPECT: clean -- id=scala_rethrow -- wrapped and propagated.
      case NonFatal(e) =>
        throw new IllegalStateException(s"cursor $name is required but unreadable", e)
    }

  def countRows(exportFile: Path): Long =
    try Files.lines(exportFile).count()
    catch {
      // EXPECT: finding -- id=scala_scope_leak -- defect B2: swallowed here; the
      // only nearby log call belongs to recordExportSize below.
      case NonFatal(e) => 0L
    }

  def recordExportSize(exportFile: Path, rows: Long): Unit =
    logger.info(s"export $exportFile contains $rows rows")

  def parseUpdatedAt(raw: String): Option[Instant] =
    // EXPECT: finding -- id=scala_try_tooption -- `Try(...).toOption` discards
    // the Throwable entirely.
    Try(Instant.parse(raw)).toOption

  def parseUpdatedAtStrict(raw: String): Option[Instant] =
    try Some(Instant.parse(raw))
    catch {
      // EXPECT: finding -- id=scala_arm_typed_swallow -- typed `case e: X` arm
      // returns None with no record.
      case e: DateTimeParseException => None
    }

  private def cursorPath(name: String): Path = root.resolve(s"$name.cursor")
}

private object Cursors {
  def parse(raw: String): Map[String, String] =
    raw
      .split(';')
      .filter(_.contains('='))
      .map { pair =>
        val Array(key, value) = pair.split('=')
        key -> value
      }
      .toMap
}
