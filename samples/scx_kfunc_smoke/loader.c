#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <librex.h>

#define EXE "./target/x86_64-unknown-none/release/scx_kfunc_smoke"

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

	fprintf(stdout, "[loader] Loading Rex object from %s ...\n", EXE);

	robj = rex_obj_load(EXE);
	if (!robj) {
		fprintf(stderr, "[loader] FAILED to load Rex object\n");
		return 1;
	}
	fprintf(stdout, "[loader] Rex object loaded successfully.\n");

	fprintf(stdout, "[loader] Attaching sched_ext scheduler ...\n");
	if (rex_obj_attach(robj)) {
		fprintf(stderr, "[loader] FAILED to attach sched_ext scheduler\n");
		return 1;
	}

	fprintf(stdout, "[loader] scx_kfunc_smoke scheduler attached and ACTIVE.\n");
	fprintf(stdout, "[loader] Check 'dmesg' or 'trace_pipe' for kernel/BPF logs.\n");
	fprintf(stdout, "[loader] Press Ctrl-C to exit.\n");

	while (running)
		sleep(1);

	fprintf(stdout, "\n[loader] Detaching scx_kfunc_smoke scheduler ...\n");
	rex_obj_detach(robj);
	fprintf(stdout, "[loader] scx_kfunc_smoke scheduler detached.\n");

	return 0;
}
