#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <librex.h>
#include <bpf/libbpf.h>

#define EXE "./target/x86_64-unknown-none/release/scx_simple"

static volatile int running = 1;

static void sighandler(int sig)
{
	running = 0;
}

int main(void)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link = NULL;

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);

	obj = rex_obj_get_bpf(rex_obj_load(EXE));
	if (!obj) {
		fprintf(stderr, "Failed to load Rex object\n");
		return 1;
	}

	/*
	 * TODO: Once Rex kernel supports struct_ops, use
	 * bpf_map__attach_struct_ops() to attach the scheduler.
	 *
	 * For now, find and attach individual callbacks by name.
	 * This will need to be replaced with proper struct_ops
	 * attachment once the kernel integration (Phase 2) is done.
	 */

	prog = bpf_object__find_program_by_name(obj, "simple_init");
	if (!prog) {
		fprintf(stderr, "simple_init not found\n");
		return 1;
	}

	fprintf(stdout, "scx_simple loaded successfully.\n");
	fprintf(stdout, "Press Ctrl-C to exit.\n");

	while (running)
		sleep(1);

	fprintf(stdout, "Exiting scx_simple.\n");

	if (link)
		bpf_link__destroy(link);

	return 0;
}
