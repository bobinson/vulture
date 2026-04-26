import com.google.gson.{Gson, GsonBuilder, JsonArray, JsonObject}
import scala.jdk.CollectionConverters._

/** CLI wrapper around Isabelle-extracted verified functions.
  *
  * Usage:
  *   pipeline-oracle advance '{"status":"scan_running","stages":["scan","discover","prove"],"index":0}' completed
  *   pipeline-oracle expand  '{"stages":["prove"],"has_source":true}'
  */
object OracleCLI {
  private val gson: Gson = new GsonBuilder().setPrettyPrinting().create()

  def main(args: Array[String]): Unit = {
    if (args.length < 2) {
      System.err.println("Usage: pipeline-oracle <advance|expand|expect> <json|path> [outcome]")
      System.exit(1)
    }
    try {
      args(0) match {
        case "advance" => cmdAdvance(args)
        case "expand"  => cmdExpand(args)
        case "expect"  => println(ExpectedResults.toJson(ExpectedResults.generate(args(1))))
        case other     => System.err.println(s"Unknown command: $other"); System.exit(1)
      }
    } catch {
      case e: Exception => System.err.println(s"Error: ${e.getMessage}"); System.exit(1)
    }
  }

  private def cmdAdvance(args: Array[String]): Unit = {
    val json = gson.fromJson(args(1), classOf[JsonObject])
    val status = parseStatus(json.get("status").getAsString)
    val stages = parseStageList(json.getAsJsonArray("stages"))
    val index = intToNat(json.get("index").getAsInt)
    val outcome = parseOutcome(args(2))

    val pipeline = Pipeline_Verified.pipeline_exta[Unit](status, stages, index, ())
    val result = Pipeline_Verified.advance(pipeline, outcome)

    val out = new JsonObject()
    out.addProperty("status", statusToString(Pipeline_Verified.p_status(result)))
    out.addProperty("index", natToInt(Pipeline_Verified.p_index(result)))
    println(gson.toJson(out))
  }

  private def cmdExpand(args: Array[String]): Unit = {
    val json = gson.fromJson(args(1), classOf[JsonObject])
    val stages = parseExpStageList(json.getAsJsonArray("stages"))
    val hasSource = json.get("has_source").getAsBoolean

    val result = Stage_Expansion_Verified.expand_stages(stages, hasSource)

    val out = new JsonObject()
    val arr = new JsonArray()
    result.foreach(s => arr.add(expStageToString(s)))
    out.add("stages", arr)
    println(gson.toJson(out))
  }

  // ---- Status mapping (Pipeline_Verified types) ----

  private def parseStatus(s: String): Pipeline_Verified.pipeline_status = s match {
    case "pending"           => Pipeline_Verified.Pending()
    case "scan_running"      => Pipeline_Verified.ScanRunning()
    case "discover_running"  => Pipeline_Verified.DiscoverRunning()
    case "prove_running"     => Pipeline_Verified.ProveRunning()
    case "completed"         => Pipeline_Verified.Completed()
    case "failed"            => Pipeline_Verified.Failed()
    case other => throw new IllegalArgumentException(s"Unknown status: $other")
  }

  def statusToString(s: Pipeline_Verified.pipeline_status): String = s match {
    case Pipeline_Verified.Pending()          => "pending"
    case Pipeline_Verified.ScanRunning()      => "scan_running"
    case Pipeline_Verified.DiscoverRunning()  => "discover_running"
    case Pipeline_Verified.ProveRunning()     => "prove_running"
    case Pipeline_Verified.Completed()        => "completed"
    case Pipeline_Verified.Failed()           => "failed"
  }

  // ---- Stage mapping (Pipeline_Verified.stage for advance) ----

  private def parsePipelineStage(s: String): Pipeline_Verified.stage = s match {
    case "scan"     => Pipeline_Verified.Scan()
    case "discover" => Pipeline_Verified.Discover()
    case "prove"    => Pipeline_Verified.Prove()
    case other => throw new IllegalArgumentException(s"Unknown stage: $other")
  }

  private def parseStageList(arr: JsonArray): List[Pipeline_Verified.stage] =
    arr.asScala.map(e => parsePipelineStage(e.getAsString)).toList

  // ---- Stage mapping (Stage_Expansion_Verified.stage for expand) ----

  private def parseExpStage(s: String): Stage_Expansion_Verified.stage = s match {
    case "scan"     => Stage_Expansion_Verified.Scan()
    case "discover" => Stage_Expansion_Verified.Discover()
    case "prove"    => Stage_Expansion_Verified.Prove()
    case other => throw new IllegalArgumentException(s"Unknown stage: $other")
  }

  private def expStageToString(s: Stage_Expansion_Verified.stage): String = s match {
    case Stage_Expansion_Verified.Scan()     => "scan"
    case Stage_Expansion_Verified.Discover() => "discover"
    case Stage_Expansion_Verified.Prove()    => "prove"
  }

  private def parseExpStageList(arr: JsonArray): List[Stage_Expansion_Verified.stage] =
    arr.asScala.map(e => parseExpStage(e.getAsString)).toList

  // ---- Outcome mapping ----

  private def parseOutcome(s: String): Pipeline_Verified.audit_outcome = s match {
    case "completed" => Pipeline_Verified.AuditCompleted()
    case "failed"    => Pipeline_Verified.AuditFailed()
    case other => throw new IllegalArgumentException(s"Unknown outcome: $other")
  }

  // ---- Nat <-> Int conversion ----

  private def intToNat(n: Int): Pipeline_Verified.nat = {
    if (n <= 0) Pipeline_Verified.zero_nat()
    else Pipeline_Verified.Suc(intToNat(n - 1))
  }

  private def natToInt(n: Pipeline_Verified.nat): Int = n match {
    case Pipeline_Verified.zero_nat() => 0
    case Pipeline_Verified.Suc(m) => 1 + natToInt(m)
  }
}
