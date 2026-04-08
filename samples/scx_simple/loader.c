#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <librex.h>

#define EXE "./target/x86_64-unknown-none/release/scx_simple"

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

	robj = rex_obj_load(EXE);
	if (!robj) {
		fprintf(stderr, "Failed to load Rex object\n");
		return 1;
	}

	if (rex_obj_attach(robj)) {
		fprintf(stderr, "Failed to attach sched_ext scheduler\n");
		return 1;
	}

	fprintf(stdout, "scx_simple scheduler attached.\n");
	fprintf(stdout, "Press Ctrl-C to exit.\n");

	while (running)
		sleep(1);

	rex_obj_detach(robj);
	fprintf(stdout, "scx_simple scheduler detached.\n");

	return 0;
}
