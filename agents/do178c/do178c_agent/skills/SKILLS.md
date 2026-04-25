# DO-178C Compliance Auditor - Skills

Static analysis for RTCA DO-178C / EUROCAE ED-12C airborne software assurance.
All skills configurable by Design Assurance Level (DAL A through E).

## dead_code_check
- **Function**: `check_dead_code(source_path: str) -> dict`
- **Purpose**: Detects unreachable code after return/raise/panic and constant-true/false conditionals
- **DO-178C Ref**: Table A-5 Obj 5 (dead code elimination)
- **Severity**: DAL A/B=critical, C=high, D=medium, E=skip

## mcdc_coverage
- **Function**: `check_mcdc_coverage(source_path: str) -> dict`
- **Purpose**: Flags compound boolean conditions without MC/DC coverage markers
- **DO-178C Ref**: Table A-7 Obj 5-7 (structural coverage)
- **Severity**: DAL A=critical, B=high, C-E=skip

## recursion_check
- **Function**: `check_recursion(source_path: str) -> dict`
- **Purpose**: Detects direct recursion and unbounded loops
- **DO-178C Ref**: 6.3.4.f (stack usage analysis)
- **Severity**: DAL A/B=critical, C=high, D-E=skip

## malloc_check
- **Function**: `check_malloc(source_path: str) -> dict`
- **Purpose**: Flags dynamic allocation (malloc, new, make, append, container types)
- **DO-178C Ref**: 6.3.4.f, Table A-5 Obj 6 (resource usage)
- **Severity**: DAL A/B=critical, C=high, D=medium, E=skip

## traceability_check
- **Function**: `check_traceability(source_path: str) -> dict`
- **Purpose**: Verifies functions have requirement tags (@requirement, REQ-NNN, HLR-NNN, LLR-NNN)
- **DO-178C Ref**: Table A-3 Obj 1-4 (requirements traceability)
- **Severity**: DAL A=critical, B/C=high, D=medium, E=skip

## timing_check
- **Function**: `check_timing(source_path: str) -> dict`
- **Purpose**: Detects non-deterministic timing: sleep, wall-clock reads, unbounded network I/O
- **DO-178C Ref**: 6.3.4.f, Table A-6 Obj 6 (deterministic execution)
- **Severity**: DAL A=critical, B=high, C=medium, D-E=skip
