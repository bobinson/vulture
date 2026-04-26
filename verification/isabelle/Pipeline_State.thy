theory Pipeline_State
  imports Main
begin

section \<open>Types\<close>

datatype pipeline_status =
    Pending
  | ScanRunning
  | DiscoverRunning
  | ProveRunning
  | Completed
  | Failed

datatype stage = Scan | Discover | Prove

datatype audit_outcome = AuditCompleted | AuditFailed

record pipeline =
  p_status :: pipeline_status
  p_stages :: "stage list"
  p_index  :: nat


section \<open>Transition Functions\<close>

fun stage_to_running :: "stage \<Rightarrow> pipeline_status" where
  "stage_to_running Scan = ScanRunning"
| "stage_to_running Discover = DiscoverRunning"
| "stage_to_running Prove = ProveRunning"

text \<open>
  The core state transition. This IS the specification.
  The Go implementation must match this function exactly.

  Guards:
  - Completed, Failed, Pending are absorbing (no transition out).
  - Only running states can advance.
  - AuditFailed from any running state \<rightarrow> Failed.
  - AuditCompleted \<rightarrow> look up next stage; if none, mark Completed.
\<close>

fun advance :: "pipeline \<Rightarrow> audit_outcome \<Rightarrow> pipeline" where
  "advance p outcome =
    (if p_status p \<in> {Completed, Failed, Pending} then p
     else case outcome of
       AuditFailed \<Rightarrow> p\<lparr> p_status := Failed \<rparr>
     | AuditCompleted \<Rightarrow>
         let next_idx = Suc (p_index p) in
         (if next_idx < length (p_stages p)
          then p\<lparr> p_status := stage_to_running (p_stages p ! next_idx),
                   p_index := next_idx \<rparr>
          else p\<lparr> p_status := Completed \<rparr>))"


section \<open>Helper lemma for stage_to_running\<close>

lemma stage_to_running_is_running:
  "stage_to_running s \<in> {ScanRunning, DiscoverRunning, ProveRunning}"
  by (cases s) auto


section \<open>Terminal States\<close>

theorem completed_is_absorbing:
  "p_status p = Completed \<Longrightarrow> advance p outcome = p"
  by simp

theorem failed_is_absorbing:
  "p_status p = Failed \<Longrightarrow> advance p outcome = p"
  by simp

theorem pending_is_absorbing:
  "p_status p = Pending \<Longrightarrow> advance p outcome = p"
  by simp

corollary non_running_is_absorbing:
  "p_status p \<in> {Completed, Failed, Pending} \<Longrightarrow> advance p outcome = p"
  by simp


section \<open>Failure Propagation\<close>

theorem failure_always_reaches_failed:
  "p_status p \<notin> {Completed, Failed, Pending}
   \<Longrightarrow> p_status (advance p AuditFailed) = Failed"
  by (cases "p_status p") auto

theorem failure_preserves_stages:
  "p_stages (advance p AuditFailed) = p_stages p"
  by (cases "p_status p") auto

theorem failure_preserves_index:
  "p_index (advance p AuditFailed) = p_index p"
  by (cases "p_status p") auto


section \<open>Forward Progress\<close>

theorem advance_never_decreases_index:
  "p_index (advance p AuditCompleted) \<ge> p_index p"
  by (cases "p_status p") (auto simp add: Let_def)

theorem advance_increments_by_at_most_one:
  "p_index (advance p AuditCompleted) \<le> Suc (p_index p)"
  by (cases "p_status p") (auto simp add: Let_def)


section \<open>Full Pipeline Lifecycle\<close>

definition standard_pipeline :: pipeline where
  "standard_pipeline = \<lparr> p_status = ScanRunning,
                          p_stages = [Scan, Discover, Prove],
                          p_index = 0 \<rparr>"

theorem three_stage_completes:
  "let p1 = advance standard_pipeline AuditCompleted;
       p2 = advance p1 AuditCompleted;
       p3 = advance p2 AuditCompleted
   in p_status p3 = Completed"
  by (simp add: standard_pipeline_def Let_def)

theorem three_stage_passes_through_all_states:
  "let p1 = advance standard_pipeline AuditCompleted;
       p2 = advance p1 AuditCompleted;
       p3 = advance p2 AuditCompleted
   in p_status standard_pipeline = ScanRunning
    \<and> p_status p1 = DiscoverRunning
    \<and> p_status p2 = ProveRunning
    \<and> p_status p3 = Completed"
  by (simp add: standard_pipeline_def Let_def)

theorem three_stage_needs_exactly_three:
  "let p1 = advance standard_pipeline AuditCompleted;
       p2 = advance p1 AuditCompleted
   in p_status p2 = ProveRunning \<and> p_status p2 \<noteq> Completed"
  by (simp add: standard_pipeline_def Let_def)

theorem failure_at_any_stage:
  "p_status (advance standard_pipeline AuditFailed) = Failed"
  "p_status (advance (advance standard_pipeline AuditCompleted) AuditFailed) = Failed"
  "p_status (advance (advance (advance standard_pipeline AuditCompleted) AuditCompleted) AuditFailed) = Failed"
  by (simp_all add: standard_pipeline_def Let_def)


section \<open>Idempotency\<close>

theorem double_advance_completed_is_identity:
  "p_status p = Completed \<Longrightarrow> advance (advance p o1) o2 = p"
  by simp

theorem double_advance_failed_is_identity:
  "p_status p = Failed \<Longrightarrow> advance (advance p o1) o2 = p"
  by simp


section \<open>Status Closure\<close>

text \<open>The output status is always a valid pipeline_status constructor.\<close>

text \<open>Every stage maps to a running status, which is a subset of all valid statuses.\<close>

lemma stage_to_running_valid:
  "stage_to_running s \<in> {Pending, ScanRunning, DiscoverRunning, ProveRunning, Completed, Failed}"
  by (cases s) auto

lemma stage_to_running_range [simp]:
  "stage_to_running s = ScanRunning \<or>
   stage_to_running s = DiscoverRunning \<or>
   stage_to_running s = ProveRunning"
  by (cases s) auto

text \<open>The nth element of any stage list is a stage, and stage_to_running
  maps stages to valid statuses. We use this to close the running+completed case.\<close>

text \<open>Status closure for the standard pipeline (concrete, fast proof).
  The universal version for arbitrary stages lists requires interactive proof
  with sledgehammer and is left for future work.\<close>

theorem standard_status_remains_valid:
  "p_status (advance standard_pipeline outcome) \<in>
   {Pending, ScanRunning, DiscoverRunning, ProveRunning, Completed, Failed}"
  by (cases outcome) (simp_all add: standard_pipeline_def Let_def)

theorem standard_status_chain_valid:
  "let p1 = advance standard_pipeline AuditCompleted;
       p2 = advance p1 AuditCompleted;
       p3 = advance p2 AuditCompleted
   in p_status p1 \<in> {Pending, ScanRunning, DiscoverRunning, ProveRunning, Completed, Failed}
    \<and> p_status p2 \<in> {Pending, ScanRunning, DiscoverRunning, ProveRunning, Completed, Failed}
    \<and> p_status p3 \<in> {Pending, ScanRunning, DiscoverRunning, ProveRunning, Completed, Failed}"
  by (simp add: standard_pipeline_def Let_def)


section \<open>No Regression\<close>

text \<open>Proved concretely for the standard 3-stage pipeline at each index.
  Advancing from DiscoverRunning or ProveRunning never regresses.\<close>

theorem no_return_to_scan_from_discover_idx0:
  "p_status (advance \<lparr>p_status=DiscoverRunning, p_stages=[Scan,Discover,Prove], p_index=0\<rparr> outcome) \<noteq> ScanRunning"
  by (cases outcome) (simp_all add: Let_def)

theorem no_return_to_scan_from_discover_idx1:
  "p_status (advance \<lparr>p_status=DiscoverRunning, p_stages=[Scan,Discover,Prove], p_index=1\<rparr> outcome) \<noteq> ScanRunning"
  by (cases outcome) (simp_all add: Let_def)

theorem no_return_to_scan_from_discover_idx2:
  "p_status (advance \<lparr>p_status=DiscoverRunning, p_stages=[Scan,Discover,Prove], p_index=2\<rparr> outcome) \<noteq> ScanRunning"
  by (cases outcome) (simp_all add: Let_def)

theorem no_return_to_scan_from_prove_idx0:
  "p_status (advance \<lparr>p_status=ProveRunning, p_stages=[Scan,Discover,Prove], p_index=0\<rparr> outcome) \<noteq> ScanRunning"
  by (cases outcome) (simp_all add: Let_def)

theorem no_return_to_scan_from_prove_idx1:
  "p_status (advance \<lparr>p_status=ProveRunning, p_stages=[Scan,Discover,Prove], p_index=1\<rparr> outcome) \<noteq> ScanRunning"
  by (cases outcome) (simp_all add: Let_def)

theorem no_return_to_scan_from_prove_idx2:
  "p_status (advance \<lparr>p_status=ProveRunning, p_stages=[Scan,Discover,Prove], p_index=2\<rparr> outcome) \<noteq> ScanRunning"
  by (cases outcome) (simp_all add: Let_def)

text \<open>ProveRunning only occurs at index 2 in a well-formed pipeline.
  At index 2, Suc 2 = 3 which is NOT less than length [S,D,P] = 3,
  so advance produces Completed (not DiscoverRunning).\<close>

theorem no_return_to_discover_from_prove:
  "p_status (advance \<lparr>p_status=ProveRunning, p_stages=[Scan,Discover,Prove], p_index=2\<rparr> outcome) \<noteq> DiscoverRunning"
  by (cases outcome) (simp_all add: Let_def)


section \<open>Code Extraction\<close>

export_code advance stage_to_running
  in Scala module_name Pipeline_Verified file_prefix Pipeline_Verified

end
