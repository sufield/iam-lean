.PHONY: lean-build lean-verify lean-catalog bridge-build bridge-verify bridge-verify-all clean

lean-build:
	lake build

lean-verify: lean-build
	@echo "Build succeeded — all proofs verified (Lean checks proofs at compile time)."
	@grep -rn 'sorry' --include='*.lean' Stave/ | grep -v '.lake/' && \
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

clean:
	lake clean
