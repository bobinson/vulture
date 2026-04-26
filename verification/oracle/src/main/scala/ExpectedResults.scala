import com.google.gson._
import java.io.FileReader
import scala.jdk.CollectionConverters._

/**
 * Reads a manifest and produces a complete expected-results document.
 * No I/O to the target. Pure manifest -> expected output transformation.
 *
 * Combines:
 *   1. PROVEN state transitions (from Isabelle-extracted advance function)
 *   2. DETERMINISTIC finding expectations (from manifest ground truth)
 */
object ExpectedResults {
  private val gson: Gson = new GsonBuilder().setPrettyPrinting().create()

  case class VulnExpectation(id: String, titlePattern: String, severityMin: String, category: String)
  case class FalsePositiveGuard(id: String, titlePattern: String)

  case class StageExpected(
    stage: String,
    statusBefore: String,
    statusAfter: String,
    mustFindVulns: List[VulnExpectation],
    mustNotFindVulns: List[FalsePositiveGuard],
    minEndpoints: Int,
    minFindings: Int
  )

  case class FullExpectation(
    targetUrl: String,
    stages: List[StageExpected],
    expectedEndpoints: List[String],
    expectedTechnologies: List[String],
    totalMustFind: Int,
    totalMustNotFind: Int
  )

  def generate(manifestPath: String): FullExpectation = {
    val root = gson.fromJson(new FileReader(manifestPath), classOf[JsonObject])
    val vulns = root.getAsJsonObject("vulnerabilities")
    val endpoints = root.getAsJsonObject("endpoints")
    val tech = root.getAsJsonObject("technologies")
    val exp = root.getAsJsonObject("pipeline_expectations")

    val mustFind = parseVulns(vulns.getAsJsonArray("must_find"))
    val mustNotFind = parseFP(vulns.getAsJsonArray("must_not_find"))
    val expectedEPs = strList(endpoints.getAsJsonArray("expected_discovered"))
    val expectedTech = strList(tech.getAsJsonArray("expected_patterns"))

    val scanExp = exp.getAsJsonObject("scan_to_discover")
    val discoverExp = exp.getAsJsonObject("discover_to_prove")
    val proveExp = exp.getAsJsonObject("prove_completion")

    // PROVEN state machine for transitions
    val pStages = List(Pipeline_Verified.Scan(), Pipeline_Verified.Discover(), Pipeline_Verified.Prove())
    var p: Pipeline_Verified.pipeline_ext[Unit] = Pipeline_Verified.pipeline_exta[Unit](
      Pipeline_Verified.ScanRunning(), pStages, Pipeline_Verified.zero_nat(), ()
    )

    val stages = List(
      {
        val before = OracleCLI.statusToString(Pipeline_Verified.p_status(p))
        p = Pipeline_Verified.advance(p, Pipeline_Verified.AuditCompleted())
        StageExpected("scan", before, OracleCLI.statusToString(Pipeline_Verified.p_status(p)),
          mustFind, mustNotFind, 0,
          if (scanExp.get("scan_must_produce_findings").getAsBoolean) 1 else 0)
      },
      {
        val before = OracleCLI.statusToString(Pipeline_Verified.p_status(p))
        p = Pipeline_Verified.advance(p, Pipeline_Verified.AuditCompleted())
        StageExpected("discover", before, OracleCLI.statusToString(Pipeline_Verified.p_status(p)),
          List(), List(), discoverExp.get("discover_must_find_endpoints_min").getAsInt, 0)
      },
      {
        val before = OracleCLI.statusToString(Pipeline_Verified.p_status(p))
        p = Pipeline_Verified.advance(p, Pipeline_Verified.AuditCompleted())
        StageExpected("prove", before, OracleCLI.statusToString(Pipeline_Verified.p_status(p)),
          List(), List(), 0, proveExp.get("prove_must_verify_min").getAsInt)
      }
    )

    FullExpectation(root.get("target_url").getAsString, stages, expectedEPs, expectedTech,
      mustFind.size, mustNotFind.size)
  }

  def toJson(e: FullExpectation): String = {
    // Convert to Java-friendly structure for Gson (Scala Lists serialize as head/next)
    val obj = new JsonObject()
    obj.addProperty("targetUrl", e.targetUrl)
    obj.addProperty("totalMustFind", e.totalMustFind)
    obj.addProperty("totalMustNotFind", e.totalMustNotFind)
    obj.add("expectedEndpoints", toJsonArray(e.expectedEndpoints))
    obj.add("expectedTechnologies", toJsonArray(e.expectedTechnologies))

    val stagesArr = new JsonArray()
    for (s <- e.stages) {
      val so = new JsonObject()
      so.addProperty("stage", s.stage)
      so.addProperty("statusBefore", s.statusBefore)
      so.addProperty("statusAfter", s.statusAfter)
      so.addProperty("minEndpoints", s.minEndpoints)
      so.addProperty("minFindings", s.minFindings)

      val mfArr = new JsonArray()
      for (v <- s.mustFindVulns) {
        val vo = new JsonObject()
        vo.addProperty("id", v.id)
        vo.addProperty("titlePattern", v.titlePattern)
        vo.addProperty("severityMin", v.severityMin)
        vo.addProperty("category", v.category)
        mfArr.add(vo)
      }
      so.add("mustFindVulns", mfArr)

      val mnfArr = new JsonArray()
      for (f <- s.mustNotFindVulns) {
        val fo = new JsonObject()
        fo.addProperty("id", f.id)
        fo.addProperty("titlePattern", f.titlePattern)
        mnfArr.add(fo)
      }
      so.add("mustNotFindVulns", mnfArr)
      stagesArr.add(so)
    }
    obj.add("stages", stagesArr)
    gson.toJson(obj)
  }

  private def toJsonArray(xs: List[String]): JsonArray = {
    val arr = new JsonArray()
    xs.foreach(arr.add)
    arr
  }

  private def parseVulns(arr: JsonArray): List[VulnExpectation] =
    arr.asScala.map { e =>
      val o = e.getAsJsonObject
      VulnExpectation(o.get("id").getAsString, o.get("title_pattern").getAsString,
        o.get("severity_min").getAsString,
        if (o.has("category")) o.get("category").getAsString else "")
    }.toList

  private def parseFP(arr: JsonArray): List[FalsePositiveGuard] =
    arr.asScala.map { e =>
      val o = e.getAsJsonObject
      FalsePositiveGuard(o.get("id").getAsString, o.get("title_pattern").getAsString)
    }.toList

  private def strList(arr: JsonArray): List[String] =
    arr.asScala.map(_.getAsString).toList
}
