.PHONY: check-proofs build-oracle conformance simulate agent-verify build-target clean all

ISABELLE := /opt/Isabelle2024/bin/isabelle
ORACLE_JAR := oracle/build/libs/pipeline-oracle.jar
TARGET_BIN := bin/simulated-target
GRADLE := $(HOME)/.sdkman/candidates/gradle/current/bin/gradle

all: check-proofs build-oracle conformance simulate agent-verify

check-proofs:
	cd isabelle && $(ISABELLE) build -d . Pipeline_Verification
	@echo "=== All proofs verified ==="

extract: check-proofs
	cd isabelle && $(ISABELLE) export -d . -x "*:code**" Pipeline_Verification
	cp isabelle/export/Pipeline_Verification.Pipeline_State/code/Pipeline_Verified.scala oracle/src/main/scala/
	cp isabelle/export/Pipeline_Verification.Stage_Expansion/code/Stage_Expansion_Verified.scala oracle/src/main/scala/

build-oracle: extract
	cd oracle && $(GRADLE) jar
	@echo "=== Oracle: $(ORACLE_JAR) ==="

build-target:
	mkdir -p bin
	cd simulated-target && go build -o ../$(TARGET_BIN) .

# Pure oracle validation (no network)
conformance:
	@test -f $(ORACLE_JAR) || (echo "ERROR: run 'make build-oracle' first" && exit 1)
	cd conformance && go test -v -count=1 -run "TestAdvance|TestExpand"

# Simulation: oracle + target (no agents)
simulate: build-target
	@test -f $(ORACLE_JAR) || (echo "ERROR: run 'make build-oracle' first" && exit 1)
	$(TARGET_BIN) & echo $$! > .target.pid; sleep 1
	cd conformance && go test -v -count=1 -run TestSim || (kill `cat ../.target.pid` 2>/dev/null; rm -f ../.target.pid; exit 1)
	kill `cat .target.pid` 2>/dev/null; rm -f .target.pid
	@echo "=== Simulation PASSED ==="

# Agent-vs-Oracle: real agents against live target
agent-verify: build-target
	@test -f $(ORACLE_JAR) || (echo "ERROR: run 'make build-oracle' first" && exit 1)
	$(TARGET_BIN) & echo $$! > .target.pid; sleep 1
	cd conformance && go test -v -count=1 -timeout=120s -run TestAgent || \
		(kill `cat ../.target.pid` 2>/dev/null; rm -f ../.target.pid; exit 1)
	kill `cat .target.pid` 2>/dev/null; rm -f .target.pid
	@echo "=== Agent-vs-Oracle PASSED ==="

clean:
	rm -rf oracle/build bin .target.pid isabelle/export
	cd conformance && go clean -testcache
