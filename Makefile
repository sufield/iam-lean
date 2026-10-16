.PHONY: lean-build lean-verify lean-catalog clean

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

clean:
	lake clean
