#!/usr/bin/env python3
"""In-VM driver for the scx_vtime sched_ext smoke test.

Runs inside the QEMU guest spun up by ``scripts/q-script/sanity-test-q``.

Sequence:

1. Snapshot the loaded BPF program count.
2. Clear ftrace + kernel ring buffer so the captured window is unambiguous.
3. Launch ``./loader`` and wait for ``/sys/kernel/sched_ext/state == enabled``.
4. Drive a small CPU-bound workload so every callback fires at least once.
5. Send SIGINT, wait for the loader to detach, and confirm the scheduler is
   no longer enabled.
6. Snapshot the BPF program count again (asserts no watchdog-disable leak).
7. Concatenate ``dmesg`` + ftrace ``trace`` and check every pattern in
   ``expected.txt``:

       * lines beginning with ``+`` (or bare regex) MUST match at least once,
       * lines beginning with ``!`` MUST NOT match,
       * lines beginning with ``#`` and blank lines are ignored.

Result is written to ``auto_grade.txt`` (``success``/``fail``); on failure
``capture.log`` is written next to it for postmortem.
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

LOADER_BIN = "./scx-vtime-loader"
EXPECTED_PATH = Path("expected.txt")
GRADE_PATH = Path("auto_grade.txt")

# capture.log lands inside the guest's tmpfs overlay and disappears at
# poweroff. If the q-script exported DIR_KERNEL (the host's kernel build
# dir, 9p-mounted in the guest), drop the capture there so it survives
# back to the host. The q-script always sets DIR_KERNEL.
_dir_kernel = os.environ.get("DIR_KERNEL")
CAPTURE_PATH = (
    Path(_dir_kernel) / "capture.log" if _dir_kernel else Path("capture.log")
)

SCHED_EXT_STATE = Path("/sys/kernel/sched_ext/state")
TRACE_FILE = Path("/sys/kernel/debug/tracing/trace")
TRACE_CTL = Path("/sys/kernel/debug/tracing/tracing_on")
TRACE_CLEAR = Path("/sys/kernel/debug/tracing/trace")
TRACE_BUFSIZE_KB = Path("/sys/kernel/debug/tracing/buffer_size_kb")

# 16 MiB per CPU. The default (~1.4 MiB) is far too small: the kfunc-smoke
# init alone logs ~25 lines, and the saturated workload generates hundreds
# of thousands of enqueue / select_cpu trace events that would otherwise
# evict the init lines (and the once-only dispatch / enqueue smoke lines)
# before the post-detach read.
TRACE_BUFFER_KB = 16 * 1024

WORKLOAD_IDLE_SECONDS = 2
WORKLOAD_BUSY_SECONDS = 3
ATTACH_TIMEOUT = 15.0
DETACH_TIMEOUT = 15.0

# Mid-workload trace snapshots, populated by workload(). Single-element
# lists so the function can mutate them without `global` boilerplate.
mid_trace_idle: list[str] = [""]
mid_trace_busy: list[str] = [""]


def log(msg: str) -> None:
    print(f"[scx_vtime_test] {msg}", flush=True)


def run(cmd: str, **kw) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, shell=True, text=True, capture_output=True, **kw)


def count_bpf_programs() -> int:
    r = run("bpftool prog show")
    if not r.stdout:
        return 0
    return sum(1 for line in r.stdout.splitlines() if " name " in line)


def read_state() -> str | None:
    try:
        return SCHED_EXT_STATE.read_text().strip()
    except FileNotFoundError:
        return None
    except OSError:
        return None


def wait_for_state(target: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if read_state() == target:
            return True
        time.sleep(0.2)
    return False


def reset_capture_buffers() -> None:
    run("dmesg -C")
    try:
        if TRACE_BUFSIZE_KB.exists():
            TRACE_BUFSIZE_KB.write_text(f"{TRACE_BUFFER_KB}\n")
            actual = TRACE_BUFSIZE_KB.read_text().strip()
            log(f"trace buffer_size_kb (per cpu) = {actual} (requested {TRACE_BUFFER_KB})")
        if TRACE_CTL.exists():
            TRACE_CTL.write_text("1\n")
        if TRACE_CLEAR.exists():
            TRACE_CLEAR.write_text("")
    except OSError as exc:
        log(f"WARN: could not reset trace buffer: {exc}")


def read_trace() -> str:
    if not TRACE_FILE.exists():
        return ""
    try:
        return TRACE_FILE.read_text()
    except OSError as exc:
        return f"<read error: {exc}>\n"


def capture_buffers(*extra_traces: str) -> str:
    """Capture dmesg + ftrace, optionally unioned with prior snapshots.

    The ftrace ring buffer is finite, so callers may supply earlier
    snapshots taken at points in the test where short-lived events (e.g.
    init) would otherwise be evicted before the final read.
    """
    parts: list[str] = []
    dmesg = run("dmesg")
    if dmesg.stdout:
        parts.append("===== dmesg =====")
        parts.append(dmesg.stdout)
    for i, snap in enumerate(extra_traces):
        if snap:
            parts.append(f"===== trace snapshot {i} =====")
            parts.append(snap)
    parts.append("===== trace (final) =====")
    parts.append(read_trace())
    return "\n".join(parts)


def load_expected() -> tuple[list[re.Pattern[str]], list[re.Pattern[str]]]:
    if not EXPECTED_PATH.exists():
        log(f"FAIL: {EXPECTED_PATH} missing")
        return [], []
    required: list[re.Pattern[str]] = []
    forbidden: list[re.Pattern[str]] = []
    for raw in EXPECTED_PATH.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!"):
            forbidden.append(re.compile(line[1:].strip()))
        elif line.startswith("+"):
            required.append(re.compile(line[1:].strip()))
        else:
            required.append(re.compile(line))
    return required, forbidden


def _spawn_yes_workers(n: int) -> list[subprocess.Popen[bytes]]:
    return [
        subprocess.Popen(
            "yes > /dev/null",
            shell=True,
            preexec_fn=os.setsid,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(n)
    ]


def _kill_workers(procs: list[subprocess.Popen[bytes]]) -> None:
    for p in procs:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
    for p in procs:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()


def workload() -> None:
    """Drive scx_simple through both dispatch regimes.

    scx_simple's ``select_cpu`` directly inserts into the *local* DSQ when
    an idle CPU is found, which means the enqueue/dispatch path is only
    exercised when *every* CPU is busy. To make every callback fire at
    least once we run two phases:

    * **Idle phase** - one ``yes`` worker, leaving CPUs idle so ``select_cpu``
      takes its is-idle branch and direct-dispatches.
    * **Saturated phase** - ``nproc`` workers (one per CPU), forcing tasks
      through ``enqueue`` -> shared DSQ -> ``dispatch``.
    """
    try:
        nproc = max(1, int(run("nproc").stdout.strip() or "1"))
    except ValueError:
        nproc = 1

    log(f"workload: idle phase ({WORKLOAD_IDLE_SECONDS}s, 1 worker)")
    idle_workers = _spawn_yes_workers(1)
    time.sleep(WORKLOAD_IDLE_SECONDS)
    _kill_workers(idle_workers)
    mid_trace_idle[0] = read_trace()

    log(f"workload: saturated phase ({WORKLOAD_BUSY_SECONDS}s, {nproc} workers)")
    busy_workers = _spawn_yes_workers(nproc)
    time.sleep(WORKLOAD_BUSY_SECONDS)
    _kill_workers(busy_workers)
    mid_trace_busy[0] = read_trace()


def fail(reason: str, capture: str | None = None) -> int:
    log(f"FAIL: {reason}")
    if capture is not None:
        CAPTURE_PATH.write_text(capture)
        log(f"capture saved to {CAPTURE_PATH}")
    GRADE_PATH.write_text("fail")
    return 1


def main() -> int:
    if not Path(LOADER_BIN).exists():
        return fail(f"{LOADER_BIN} not found in {Path.cwd()}")

    base_progs = count_bpf_programs()
    log(f"baseline bpftool prog count: {base_progs}")

    reset_capture_buffers()

    log("starting loader")
    loader = subprocess.Popen(
        [LOADER_BIN],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        if not wait_for_state("enabled", ATTACH_TIMEOUT):
            loader.kill()
            loader.wait(timeout=5)
            return fail(
                f"scheduler did not reach 'enabled' (state={read_state()!r})",
                capture_buffers(),
            )
        log("scheduler is enabled, snapshotting trace (init lines)")

        # Snapshot ftrace immediately so the `init` lines survive even if
        # the buffer wraps during the workload.
        init_trace = read_trace()

        workload()

        log("sending SIGINT to loader")
        loader.send_signal(signal.SIGINT)
        try:
            loader.wait(timeout=DETACH_TIMEOUT)
        except subprocess.TimeoutExpired:
            loader.kill()
            loader.wait(timeout=5)
            return fail("loader did not exit after SIGINT",
                        capture_buffers(init_trace, mid_trace_idle[0],
                                        mid_trace_busy[0]))

        # After detach the state file should report disabled (or be absent
        # entirely on some kernels). Anything else is a leak.
        wait_for_state("disabled", 5.0)
        post_state = read_state()
        if post_state not in (None, "disabled"):
            return fail(
                f"detach did not reset state (state={post_state!r})",
                capture_buffers(init_trace, mid_trace_idle[0],
                                mid_trace_busy[0]),
            )

        time.sleep(0.5)  # let the kernel finish releasing the prog
        after_progs = count_bpf_programs()
        log(f"post-detach bpftool prog count: {after_progs}")
        if after_progs > base_progs:
            return fail(
                f"bpftool prog leak ({base_progs} -> {after_progs})",
                capture_buffers(init_trace, mid_trace_idle[0],
                                mid_trace_busy[0]),
            )

        captured = capture_buffers(init_trace, mid_trace_idle[0],
                                   mid_trace_busy[0])
        required, forbidden = load_expected()
        if not required and not forbidden:
            return fail("expected.txt produced no patterns", captured)

        missing = [p.pattern for p in required if not p.search(captured)]
        leaked = [p.pattern for p in forbidden if p.search(captured)]
        if missing or leaked:
            for m in missing:
                log(f"  missing pattern: {m}")
            for l in leaked:
                log(f"  forbidden pattern present: {l}")
            return fail("expected.txt assertion failed", captured)
        log(f"all {len(required)} required pattern(s) matched, "
            f"{len(forbidden)} forbidden pattern(s) absent")

        log("success")
        GRADE_PATH.write_text("success")
        return 0
    finally:
        if loader.poll() is None:
            loader.kill()
            loader.wait(timeout=5)


if __name__ == "__main__":
    sys.exit(main())
