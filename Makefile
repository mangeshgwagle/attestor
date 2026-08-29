# Convenience wrapper around run_all.sh and per-language builds.
#
#   make            -> build + run every demo (C and C++ executed; Haskell if GHC)
#   make c          -> only the C demos
#   make cpp        -> only the C++ demos
#   make haskell    -> only the Haskell demos (needs runghc)
#   make warnings   -> compile C/C++ with every warning on, don't run
#   make verify42   -> run the complete 4.2 gate plus language/control checks
#   make verify415  -> run inherited integration and release-hardening checks
#   make verify414  -> run all inherited gates plus the 4.1.4 analysis-protocol smoke
#   make verify413  -> run the inherited 4.1.3 smoke
#   make verify412  -> compatibility alias for the current 4.1-family gate
#   make verify41   -> compatibility alias for the current 4.1-family gate
#   make verify40   -> run the inherited unit, corpus, catalog, and 4.0 smoke gates
#   make verify35   -> run the full unit suite plus inherited compatibility self-tests
#   make clean      -> remove built binaries and Python bytecode caches

CC      ?= gcc
CXX     ?= g++
PYTHON  ?= python3
CFLAGS  ?= -std=c11 -Wall -Wextra
CXXFLAGS?= -std=c++20 -Wall -Wextra

C_SRCS   := $(wildcard c/*.c)
CPP_SRCS := $(wildcard cpp/*.cpp)
HS_SRCS  := $(wildcard haskell/*.hs)
C_BINS   := $(C_SRCS:.c=.out)
CPP_BINS := $(CPP_SRCS:.cpp=.out)

.PHONY: all c cpp haskell warnings verify42 verify415 verify414 verify413 verify412 verify41 verify40 verify35 clean
all:
	@./run_all.sh

c: $(C_BINS)
	@for b in $(C_BINS); do echo "=== $$b ==="; ./$$b; done

cpp: $(CPP_BINS)
	@for b in $(CPP_BINS); do echo "=== $$b ==="; ./$$b; done

haskell:
	@for s in $(HS_SRCS); do echo "=== $$s ==="; runghc $$s || true; done

# Strict-aliasing demo only misbehaves under optimization; build it at -O2.
c/02_strict_aliasing.out: c/02_strict_aliasing.c
	$(CC) -O2 -std=c11 $< -o $@

%.out: %.c
	$(CC) $(CFLAGS) $< -o $@

%.out: %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

warnings:
	@echo "## C warnings ##"
	@for s in $(C_SRCS); do echo "-- $$s --"; $(CC) $(CFLAGS) -fsyntax-only $$s; done
	@echo "## C++ warnings ##"
	@for s in $(CPP_SRCS); do echo "-- $$s --"; $(CXX) $(CXXFLAGS) -fsyntax-only $$s; done

verify35:
	$(PYTHON) -B -m unittest discover -s detector -p "test_*.py"
	$(PYTHON) -B detector/attestor.py --self-test --seed 0
	$(PYTHON) -B detector/advanced_rules.py --self-test
	$(PYTHON) -B detector/precision_catalog.py --self-test

verify40: verify35
	$(PYTHON) -B -c "import sys; sys.path.insert(0, 'detector'); import attestor40; r=attestor40.maximum('realworld/app.js', improve=False, use_cache=False, components=('engineering','security-fabric')); assert r['schema']=='attestor-maximum/4.0'; assert attestor40.truth_guard40.verify_guarded(r)['ok']; print('Attestor 4.0 smoke:', r['status'])"

verify41: verify414

verify412: verify414

verify413: verify40
	$(PYTHON) -B -c "import sys; sys.path.insert(0, 'detector'); import attack_surface413,attestor41,security_posture413,security_validation413,truth_guard41; r=attestor41.maximum('realworld', improve=False, use_cache=False, legacy_components=('engineering','security-fabric')); assert r['schema']=='attestor-maximum/4.1'; assert truth_guard41.verify_guarded(r, root='realworld')['ok']; assert attack_surface413.verify_report(r['attack_surface_413'])[0]; assert security_posture413.verify_report(r['security_posture_413']); assert security_validation413.verify_report(r['security_command_center_413'], schema=security_validation413.COMMAND_CENTER_SCHEMA)[0]; print('Attestor 4.1.3 smoke:', r['status'])"

verify414: verify413
	$(PYTHON) -B -c "import sys; sys.path.insert(0, 'detector'); import attestor414,variant414; reports=[attestor414.maximum('realworld', variant=p, improve=False, use_cache=False) for p in variant414.COMPILED_PROFILES]; assert all(attestor414.verify_report(r, root='realworld')[0] for r in reports); assert [r['variant_414']['selected_profile']['slug'] for r in reports]==list(variant414.PROFILE_SLUGS); print('Attestor 4.1.4 profile smoke:', ', '.join(r['status'] for r in reports))"
	$(PYTHON) -B detector/release_hardening.py .

verify415: verify414
	$(PYTHON) -B detector/restage_bundle.py --check
	$(PYTHON) -B -m unittest discover -s integrations/attestor_chat -p "test_*.py"
	$(PYTHON) -B -m unittest discover -s integrations/attestor_reason -p "test_*.py"
	$(PYTHON) -B -m unittest discover -s integrations/attestor4kids -p "test_*.py"
	$(PYTHON) -B detector/release_hardening.py .

verify42: verify415
	$(PYTHON) -B -m unittest discover -s experiments/enterprise_security42/tests -p "test_*.py"
	$(PYTHON) -B -m unittest discover -s detector -p "test_assurance42.py"
	$(PYTHON) -B -m unittest discover -s detector -p "test_unified_cli42.py"
	$(PYTHON) -B -m unittest discover -s integrations/mc_asm -p "test_*.py"
	$(PYTHON) -B -m unittest discover -s integrations/attestorlang/tests -p "test_*.py"
	$(PYTHON) -B -m unittest discover -s integrations/attestor_models -p "test_*.py"
	$(PYTHON) -B -m unittest discover -s integrations/attestor_desk -p "test_*.py"
	$(PYTHON) -B -m unittest discover -s integrations/attestor_icse -p "test_*.py"
	$(PYTHON) -B -m unittest discover -s integrations/attestor_machine -p "test_*.py"
	$(PYTHON) -B -m unittest discover -s integrations/attestor_write -p "test_*.py"
	$(PYTHON) -B -m unittest discover -s integrations/attestor_endure -p "test_*.py"
	$(PYTHON) -B -m unittest discover -s integrations/attestor_chem -p "test_*.py"
	$(PYTHON) -B -m unittest discover -s integrations/attestor_pro -p "test_*.py"
	$(PYTHON) -B -m unittest discover -s integrations/attestor_review -p "test_*.py"
	$(PYTHON) -B -m unittest discover -s integrations/gate_trainer -p "test_*.py"
	$(PYTHON) -B -m unittest discover -s detector -p "test_*control*42.py"
	$(PYTHON) -B -m unittest discover -s detector -p "test_version42.py"
	$(PYTHON) -B -m unittest discover -s detector -p "test_launchers42.py"
	$(PYTHON) -B detector/release_hardening.py .

# Every gate above runs `python -B` so the audited tree stays free of bytecode:
# release_hardening.py treats __pycache__ as a forbidden release artifact, so a
# single plain `python -m unittest` (or an IDE/pytest run) is enough to make
# `make verify414` fail on an otherwise healthy tree.  `make clean` is the
# documented recovery, so it has to remove those caches too.
clean:
	@rm -f c/*.out cpp/*.out haskell/*.hi haskell/*.o a.out
	@find . -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name '*.pyc' -delete 2>/dev/null || true
	@echo cleaned
