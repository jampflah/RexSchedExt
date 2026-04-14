#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <librex.h>

#define EXE "./target/x86_64-unknown-none/release/scx_watchdog_test"

/*
 * Watchdog termination test loader.
 *
 * Loads and attaches the scx_watchdog_test scheduler whose dispatch callback
 * deliberately enters a non-terminating loop.  The Rex runtime's hrtimer-based
 * watchdog should detect that the extension exceeds its runtime threshold,
 * set rex_termination_state = 2, and the next termination_check! will trigger
 * __rex_handle_timeout() -> panic -> rex_landingpad() for a safe exit.
 *
 * The loader simply waits; the companion test script (tests/runtest.py)
 * inspects dmesg for the expected watchdog output.
 */

static volatile int running = 1;

static void sighandler(int sig)
{
	(void)sig;
	running = 0;
}

int main(void)
{
	struct rex_obj *robj;

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);

	fprintf(stdout,
		"[loader] Loading Rex object from %s ...\n", EXE);

	robj = rex_obj_load(EXE);
	if (!robj) {
		fprintf(stderr, "[loader] FAILED to load Rex object\n");
		return 1;
	}
	fprintf(stdout, "[loader] Rex object loaded successfully.\n");

	fprintf(stdout, "[loader] Attaching watchdog_test scheduler ...\n");
	if (rex_obj_attach(robj)) {
		fprintf(stderr,
			"[loader] FAILED to attach watchdog_test scheduler\n");
		return 1;
	}

	fprintf(stdout,
		"[loader] watchdog_test scheduler attached.\n"
		"[loader] The dispatch callback is now looping.\n"
		"[loader] Waiting for the watchdog to terminate the extension ...\n");

	while (running)
		sleep(1);

	fprintf(stdout,
		"\n[loader] Detaching watchdog_test scheduler ...\n");
	rex_obj_detach(robj);
	fprintf(stdout,
		"[loader] watchdog_test scheduler detached.\n");

	return 0;
}
