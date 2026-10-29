.PHONY: lean-build lean-verify lean-catalog bridge-build bridge-verify bridge-verify-all difftest drift-check clean

lean-build:
	lake build

lean-verify: lean-build
	@echo "Build succeeded — all proofs verified (Lean checks proofs at compile time)."
	@grep -rn '\bsorry\b' --include='*.lean' Stave/ | grep -v '.lake/' | grep -v '^.*/-!.*sorry' | grep -v '^.*--.*sorry' && \
		echo "WARNING: sorry found — incomplete proofs" && exit 1 || \
		echo "No sorry found — all proofs complete."

lean-catalog:
	@echo "Modules:"
	@find Stave/ -name '*.lean' | sort | sed 's|/|.|g; s|\.lean$$||'

bridge-build: lean-build
	lake build bridge-cli

bridge-verify: bridge-build
	.lake/build/bin/bridge-cli verify all fixtures/

bridge-verify-all: bridge-verify
	@echo "All bridge fixtures verified."

# Run all 16 differential tests (Lean side only — checks evaluator against fixtures).
# For cross-engine comparison, run `go test ./formal/difftest/` from the stave repo.
DIFFTEST_BIN := .lake/build/bin/difftest
DIFFTEST_CASES := \
	cloudtrail-org:CTL.CLOUDTRAIL.ORG.001 \
	org-region-scp:CTL.ORG.REGION.SCP.001 \
	iam-root-mfa:CTL.IAM.ROOT.MFA.001 \
	iam-root-accesskey:CTL.IAM.ROOT.ACCESSKEY.001 \
	cloudtrail-logval:CTL.CLOUDTRAIL.LOG.VALIDATION.001 \
	iam-console-mfa:CTL.IAM.CONSOLE.MFA.001 \
	vpc-sg-unrestricted:CTL.VPC.SG.UNRESTRICTED.001 \
	cloudtrail-regional:CTL.CLOUDTRAIL.REGIONAL.COVERAGE.001

difftest: lean-build
	@lake build difftest
	@pass=0; fail=0; \
	for pair in $(DIFFTEST_CASES); do \
		prefix=$${pair%%:*}; ctl=$${pair##*:}; \
		for scenario in fires passes; do \
			dir="fixtures/difftest/$${prefix}-$${scenario}"; \
			fixture="$${dir}/2026-10-01T120000Z.json"; \
			out=$$($(DIFFTEST_BIN) "$$fixture" "$$ctl" 2>&1) || { \
				echo "FAIL $$ctl/$$scenario (exec error)"; fail=$$((fail+1)); continue; }; \
			fires=$$(echo "$$out" | grep -o '"fires":[a-z]*' | head -1 | cut -d: -f2); \
			if [ "$$scenario" = "fires" ] && [ "$$fires" = "true" ]; then \
				pass=$$((pass+1)); \
			elif [ "$$scenario" = "passes" ] && [ "$$fires" = "false" ]; then \
				pass=$$((pass+1)); \
			else \
				echo "FAIL $$ctl/$$scenario: expected $$scenario, got fires=$$fires"; \
				fail=$$((fail+1)); \
			fi; \
		done; \
	done; \
	echo "difftest: $$pass passed, $$fail failed"; \
	[ $$fail -eq 0 ]

# Full drift check: proofs + sorry scan + difftest
drift-check: lean-verify difftest
	@echo "Drift check passed."

clean:
	lake clean
