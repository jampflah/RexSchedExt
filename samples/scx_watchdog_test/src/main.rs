#![no_std]
#![no_main]

extern crate rex;

use rex::sched_ext::*;
use rex::task_struct::TaskStruct;
use rex::{rex_printk, rex_sched_ext, rex_sched_ext_ops};

const SHARED_DSQ: u64 = 0;

#[rex_sched_ext(callback = "select_cpu")]
fn wdt_select_cpu(
    obj: &sched_ext,
    p: &TaskStruct,
    prev_cpu: i32,
    wake_flags: u64,
) -> i32 {
    let (cpu, is_idle) = obj.scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags);
    if is_idle {
        obj.scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
    }
    cpu
}

#[rex_sched_ext(callback = "enqueue")]
fn wdt_enqueue(obj: &sched_ext, p: &TaskStruct, enq_flags: u64) {
    obj.scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

/// Non-terminating dispatch callback to exercise the watchdog.
///
/// The tight loop calls `bpf_ktime_get_ns()` on every iteration so that the
/// Rex `termination_check!` macro has a chance to inspect the per-CPU
/// `rex_termination_state` flag between helper calls.  Once the kernel-side
/// hrtimer fires and sets the flag to 2, the next `termination_check!` will
/// invoke `__rex_handle_timeout() -> panic -> rex_landingpad()`, triggering a
/// safe exit of the extension.
#[rex_sched_ext(callback = "dispatch")]
fn wdt_dispatch(obj: &sched_ext, cpu: i32, _prev: Option<&TaskStruct>) {
    rex_printk!(
        "[watchdog_test] dispatch: entering non-terminating loop on cpu={}\n",
        cpu
    )
    .ok();

    loop {
        obj.bpf_ktime_get_ns();
    }
}

#[rex_sched_ext(callback = "init")]
fn wdt_init(obj: &sched_ext) -> i32 {
    rex_printk!("[watchdog_test] init: creating shared DSQ (id={})\n", SHARED_DSQ).ok();
    match obj.scx_bpf_create_dsq(SHARED_DSQ, -1) {
        Ok(_) => {
            rex_printk!("[watchdog_test] init: shared DSQ created successfully\n").ok();
            0
        }
        Err(e) => {
            rex_printk!("[watchdog_test] init: FAILED to create shared DSQ, err={}\n", e).ok();
            e
        }
    }
}

#[rex_sched_ext(callback = "exit")]
fn wdt_exit(_obj: &sched_ext, info: &ScxExitInfo) {
    rex_printk!(
        "[watchdog_test] exit: scheduler unloaded (kind={})\n",
        info.kind
    )
    .ok();
}

/// Set timeout_ms = 5000 so the kernel watchdog fires after ~5 s of stall.
#[rex_sched_ext_ops]
static wdt_ops: SchedExtOps = {
    let mut ops = SchedExtOps::with_name(b"watchdog_test");
    ops.timeout_ms = 5000;
    ops
};
