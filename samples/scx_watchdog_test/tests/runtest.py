#!/usr/bin/env python

"""
Watchdog termination test.

Verifies that the Rex runtime's hrtimer-based watchdog correctly interrupts a
non-terminating sched_ext extension and triggers a safe exit.

Success criteria (checked via dmesg):
  1. The scheduler loaded and the dispatch callback entered its infinite loop.
  2. The watchdog detected the runaway callback and terminated it safely
     (either via rex_termination_state / "Timeout in Rex program", or via
     the kernel stall watchdog / "failed to run").
"""

import re
import subprocess
from time import sleep

process = 0

WATCHDOG_WAIT_SECS = 45


def run_loader():
    global process
    process = subprocess.Popen(
        ["./scx-watchdog-test-loader"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def check_dmesg_for_watchdog() -> bool:
    """Return True if dmesg shows that the watchdog fired."""
    try:
        result = subprocess.run(
            "dmesg", capture_output=True, shell=True, text=True
        )
        output = result.stdout

        entered_loop = bool(
            re.search(r"entering non-terminating loop", output)
        )
        timeout_fired = bool(
            re.search(r"Timeout in Rex program", output)
        )
        stall_detected = bool(
            re.search(r"failed to run for", output)
        )
        watchdog_stall = bool(
            re.search(r"watchdog failed to check in", output)
        )

        if entered_loop and (timeout_fired or stall_detected or watchdog_stall):
            return True
        return False
    except Exception as e:
        print(f"dmesg check error: {e}")
        return False


def capture_output() -> bool:
    global process

    try:
        for _ in range(WATCHDOG_WAIT_SECS):
            sleep(1)
            if check_dmesg_for_watchdog():
                print("Success: watchdog terminated the extension")
                process.kill()
                process.communicate(timeout=5)
                return True

        print("Failed: watchdog did not fire within timeout")
        process.kill()
        process.communicate(timeout=5)
        return False

    except subprocess.TimeoutExpired:
        process.kill()
        return False
    except Exception as e:
        print(f"Error: {e}")
        try:
            process.kill()
        except Exception:
            pass
        return False


def main():
    run_loader()
    sleep(2)

    grade_file = open("auto_grade.txt", "w")
    if capture_output():
        grade_file.write("success")
    else:
        grade_file.write("fail")
    grade_file.close()


if __name__ == "__main__":
    main()
