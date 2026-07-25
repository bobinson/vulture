# 0027 Requirements Traceability Matrix

Verification levels:
- **PROVEN** — Isabelle/HOL theorem (mathematical guarantee for all inputs)
- **ORACLE** — Go conformance test against Isabelle-extracted oracle
- **DAL-C** — Requirements-based test + decision coverage

## Formally Verified (Isabelle/HOL)

| REQ ID | Requirement | Proof | Oracle Test |
|--------|-------------|-------|-------------|
| REQ_027_F01 | Terminal states are absorbing | `Pipeline_State.thy:completed_is_absorbing` | `TestAdvance_Exhaustive` |
| REQ_027_F02 | Failure from any running state reaches Failed | `Pipeline_State.thy:failure_always_reaches_failed` | `TestAdvance_Exhaustive` |
| REQ_027_F03 | Stage index never decreases | `Pipeline_State.thy:advance_never_decreases_index` | `TestAdvance_Exhaustive` |
| REQ_027_F04 | 3-stage pipeline passes through all states | `Pipeline_State.thy:three_stage_passes_through_all_states` | `TestAdvance_Lifecycle` |
| REQ_027_F05 | Double-advance on terminal state is identity | `Pipeline_State.thy:double_advance_completed_is_identity` | `TestAdvance_Exhaustive` |
| REQ_027_F06 | No regression from discover/prove to scan | `Pipeline_State.thy:no_return_to_scan_from_*` | `TestAdvance_Exhaustive` |
| REQ_027_F07 | Expansion: prove→[scan,discover,prove] | `Stage_Expansion.thy:prove_expands_with_source` | `TestExpand_KnownResults` |
| REQ_027_F08 | Expansion: discover without source→[discover] | `Stage_Expansion.thy:discover_without_source` | `TestExpand_KnownResults` |
| REQ_027_F09 | Expansion: no duplicates, sorted | `Stage_Expansion.thy:expansion_sorted/expansion_distinct` | `TestExpand_Exhaustive` |

## Go Pipeline Orchestration (DAL-C + Oracle)

| REQ ID | Requirement | Code | Test |
|--------|-------------|------|------|
| REQ_027_001 | Stage completion creates next audit | `pipeline_service.go:createAndLaunchStage` | `TestAdvanceStage_CreatesNextAudit` |
| REQ_027_002 | AdvanceStage is idempotent | `pipeline_service.go:advanceToNextStage` (status guard) | `TestAdvanceStage_IdempotencyGuard` |
| REQ_027_003 | Audit completion notifies pipeline | `stream_handler.go:persistResults` | `TestPersistResults_CallsAdvanceStage` |
| REQ_027_004 | Pipeline audits auto-execute | `stream_handler.go:RunPipelineStage` | `TestRunPipelineStage_ExecutesAndPersists` |
| REQ_027_005 | CreatePipeline launches first stage | `pipeline_service.go:launchFirstStage` | `TestCreatePipeline_StartsFirstStage` |
| REQ_027_006 | Prove config receives discover SiteMap | `pipeline_service.go:injectDiscoverResult` | `TestAdvanceStage_InjectsDiscoverIntoProve` |
| REQ_027_007 | Discover config receives scan findings | `pipeline_service.go:injectScanFindings` | `TestGetStageAuditConfig_DiscoverWithScanFindings` |
| REQ_027_012 | Failure at any stage fails pipeline | `pipeline_service.go:failPipeline` | `TestPipelineService_AdvanceStage_FailsPipeline` |
| REQ_027_013 | Full lifecycle: scan→discover→prove→completed | `pipeline_service.go` | `TestPipelineFullLifecycle` |

## Discover Agent (DAL-C)

| REQ ID | Requirement | Code | Test |
|--------|-------------|------|------|
| REQ_027_008 | Discover fetches scan results by default | `discover/agent.py:_fetch_scan_findings` | `test_fetch_scan_findings_from_backend` |
| REQ_027_009 | ignore_scan_results=true skips fetch | `discover/agent.py:run_discover` | 10 scan enrichment tests |
| REQ_027_010 | Discover operates without scan results | `discover/agent.py:run_discover` | `test_fetch_scan_findings_no_source_path` |

## Prove Agent (DAL-C)

| REQ ID | Requirement | Code | Test |
|--------|-------------|------|------|
| REQ_027_011 | Prove continues with probing when no findings | `prove/agent.py:_run_probe_only` | `test_run_prove_continues_without_findings` |

## Negative / Abnormal Conditions

| REQ ID | Requirement | Code | Test |
|--------|-------------|------|------|
| REQ_027_N01 | AdvanceStage survives audit create error | `pipeline_service.go:createAndLaunchStage` | `TestAdvanceStage_AuditCreateError` |
| REQ_027_N02 | CreatePipeline handles empty stages | `pipeline_service.go:launchFirstStage` | `TestCreatePipeline_EmptyStages` |
| REQ_027_N03 | persistResults logs AdvanceStage error | `stream_handler.go:persistResults` | `TestPersistResults_AdvanceStageErrorNonFatal` |
| REQ_027_N04 | consumeEventsNoSSE handles empty channel | `stream_handler.go:consumeEventsNoSSE` | `TestConsumeEventsNoSSE` |
| REQ_027_N05 | _fetch_scan_findings handles backend error | `discover/agent.py` | `test_fetch_scan_findings_backend_error` |
| REQ_027_N06 | _fetch_scan_findings handles HTTP 500 | `discover/agent.py` | `test_fetch_scan_findings_http_error_status` |
| REQ_027_N07 | _fetch_scan_findings handles malformed JSON | `discover/agent.py` | `test_fetch_scan_findings_malformed_json` |
| REQ_027_N08 | _fetch_scan_findings handles dict response | `discover/agent.py` | `test_fetch_scan_findings_dict_response` |

## Simulated Target Verification

| REQ ID | Requirement | Test |
|--------|-------------|------|
| REQ_027_S01 | Oracle trace state transitions correct | `TestSim_OracleTraceTransitions` |
| REQ_027_S02 | Manifest regex patterns compile | `TestSim_ManifestPatternsCompile` |
| REQ_027_S03 | Target endpoints reachable | `TestSim_TargetEndpointsReachable` |
| REQ_027_S04 | Planted vulns present on target | `TestSim_PlantedVulnsPresent` |
