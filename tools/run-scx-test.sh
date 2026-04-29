#!/usr/bin/env bash
#
# tools/run-scx-test.sh - Boot a Rex sched_ext sample under QEMU and check
# its dmesg + ftrace trace against samples/<sample>/expected.txt.
#
# Usage:
#   tools/run-scx-test.sh <sample-name>
#
# Prerequisites: meson configure has been run, the kernel and the sample
# have been built, e.g.
#   meson setup build
#   meson compile -C build kernel-build scx-simple-build scx-simple-loader
#
# Environment overrides (sensible defaults are derived from $REPO_ROOT):
#   BUILD_DIR    Meson build dir          (default: <repo>/build)
#   SAMPLE_PATH  Per-sample build dir     (default: $BUILD_DIR/samples/<sample>)
#   Q_SCRIPT     Path to the q-script     (default: <repo>/scripts/q-script/sanity-test-q)
#   KERNEL_PATH  Kernel build dir         (default: $BUILD_DIR/linux)
#
# Exit code: 0 on success, non-zero on any failure.
#
# This is a thin wrapper around scripts/sanity_tests/run_tests.py so that
# callers (developers, scripts/ci/scx-test.sh) only need to pass a sample
# name. Build orchestration is intentionally out of scope; if SAMPLE_PATH or
# the kernel build dir are missing the script bails out so the failure mode
# is "you forgot to build" rather than a silent partial run.

set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: tools/run-scx-test.sh <sample-name>

Boots the in-tree kernel under QEMU via scripts/q-script/sanity-test-q and
runs samples/<sample-name>/tests/runtest.py inside the guest.

Required: the meson build dir must exist and the sample's loader, scheduler
binary, and runtest.py must already have been built/copied into it (the
meson `test('<sample>_test', ...)` target depends on those automatically).

Required env (override if your layout differs):
  BUILD_DIR    (default: ./build)
  Q_SCRIPT     (default: scripts/q-script/sanity-test-q)
  KERNEL_PATH  (default: $BUILD_DIR/linux)
EOF
}

if [[ $# -lt 1 || "$1" == "-h" || "$1" == "--help" ]]; then
    usage
    exit 2
fi

SAMPLE="$1"
shift

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR=${BUILD_DIR:-"$REPO_ROOT/build"}
SAMPLE_PATH=${SAMPLE_PATH:-"$BUILD_DIR/samples/$SAMPLE"}
Q_SCRIPT=${Q_SCRIPT:-"$REPO_ROOT/scripts/q-script/sanity-test-q"}
KERNEL_PATH=${KERNEL_PATH:-"$BUILD_DIR/linux"}
RUNNER="$REPO_ROOT/scripts/sanity_tests/run_tests.py"

die() {
    printf 'run-scx-test: %s\n' "$*" >&2
    exit 1
}

[[ -d "$BUILD_DIR" ]]    || die "BUILD_DIR=$BUILD_DIR does not exist (did you run meson setup?)"
[[ -d "$SAMPLE_PATH" ]]  || die "SAMPLE_PATH=$SAMPLE_PATH does not exist (sample not built?)"
[[ -x "$Q_SCRIPT" ]]     || die "Q_SCRIPT=$Q_SCRIPT is not executable"
[[ -d "$KERNEL_PATH" ]]  || die "KERNEL_PATH=$KERNEL_PATH does not exist"
[[ -x "$RUNNER" ]]       || die "$RUNNER is not executable"
[[ -f "$SAMPLE_PATH/runtest.py" ]] \
    || die "$SAMPLE_PATH/runtest.py missing (sample's meson test target not built)"
[[ -f "$REPO_ROOT/samples/$SAMPLE/expected.txt" ]] \
    || die "samples/$SAMPLE/expected.txt missing (golden trace not authored)"

printf 'run-scx-test: SAMPLE=%s\n' "$SAMPLE" >&2
printf 'run-scx-test: SAMPLE_PATH=%s\n' "$SAMPLE_PATH" >&2
printf 'run-scx-test: KERNEL_PATH=%s\n' "$KERNEL_PATH" >&2

# Clean any stale grade file so a crashed prior run can't masquerade as
# success.
rm -f "$KERNEL_PATH/auto_grade.txt"

env SAMPLE_PATH="$SAMPLE_PATH" \
    Q_SCRIPT="$Q_SCRIPT" \
    KERNEL_PATH="$KERNEL_PATH" \
    "$RUNNER" "$@"
rc=$?

# run_tests.py exits 1 on failure and only writes "success" into auto_grade
# on green. Double-check both signals before declaring victory.
grade_file="$KERNEL_PATH/auto_grade.txt"
if [[ $rc -ne 0 ]]; then
    printf 'run-scx-test: FAIL (rc=%d)\n' "$rc" >&2
    exit "$rc"
fi
if [[ ! -f "$grade_file" ]] || ! grep -q '^success' "$grade_file"; then
    printf 'run-scx-test: FAIL (auto_grade.txt missing or != "success")\n' >&2
    exit 1
fi

printf 'run-scx-test: PASS (%s)\n' "$SAMPLE" >&2
