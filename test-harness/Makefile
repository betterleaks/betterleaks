.PHONY: compat perf compat-ci quick check-deps

# Run the full harness: clone, scan, compare, benchmark
compat:
	bash harness.sh

# Run compatibility checks only, skip performance benchmarks
quick:
	SKIP_PERF=1 bash harness.sh

# Run only performance benchmarks (assumes repos already cloned and scanned)
perf:
	SKIP_CLONE=1 SKIP_PERF=0 RUNS=10 bash harness.sh

# CI mode: fewer benchmark runs to save time
compat-ci:
	RUNS=3 bash harness.sh

# Check that all dependencies are available
check-deps:
	@echo "Checking dependencies..."
	@command -v gitleaks >/dev/null   || (echo "MISSING: gitleaks"   && exit 1)
	@command -v jq >/dev/null         || (echo "MISSING: jq"         && exit 1)
	@command -v git >/dev/null        || (echo "MISSING: git"        && exit 1)
	@command -v python3 >/dev/null    || (echo "MISSING: python3"    && exit 1)
	@command -v hyperfine >/dev/null  || echo "OPTIONAL: hyperfine not found (perf benchmarks will be skipped)"
	@test -x ../betterleaks           || (echo "MISSING: ../betterleaks binary — run 'make betterleaks' from project root" && exit 1)
	@echo "All required dependencies available."
