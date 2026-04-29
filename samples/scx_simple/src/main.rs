#![no_std]
#![no_main]

extern crate rex;

use rex::sched_ext::*;
use rex::task_struct::TaskStruct;
use rex::{rex_printk, rex_sched_ext, rex_sched_ext_ops};

const SHARED_DSQ: u64 = 0;

// ---------------------------------------------------------------------------
// Watchdog stall test
//
// Set STALL_MODE below to deliberately break the scheduler and observe
// sched_ext's safety net kick in. With the default 30000 ms watchdog timeout,
// the kernel should log:
//
//   sched_ext: watchdog tick (checking all CPUs)
//   sched_ext: watchdog detected timeout on CPU N!
//   sched_ext: BPF scheduler "simple" errored, disabling
//   sched_ext: runnable task stall (<comm>[pid] failed to run for ...)
//
// and every task is switched back to CFS. After that you can Ctrl-C the
// loader and the "detach" log lines are basically a no-op because the
// scheduler already self-unregistered.
//
// STALL_MODE selects *how* to break:
//   0 = no stall (normal scheduler, the default)
//   1 = soft stall: dispatch() stops pulling from SHARED_DSQ, so enqueued
//       tasks sit forever. This is the branch that triggers
//       SCX_EXIT_ERROR_STALL cleanly via check_rq_for_timeouts().
//   2 = hard stall: infinite spin *inside* dispatch(). Hangs the CPU
//       running dispatch; on a small VM the kernel's soft-lockup or
//       RCU-stall detector will usually fire before scx's watchdog has
//       a chance to react.
const STALL_MODE: u32 = 1;
// ---------------------------------------------------------------------------

/// Pick a CPU for a waking task. If the default selection finds an idle
/// CPU, dispatch directly to the local DSQ to skip the enqueue path.
#[rex_sched_ext(callback = "select_cpu")]
fn simple_select_cpu(
    obj: &sched_ext,
    p: &TaskStruct,
    prev_cpu: i32,
    wake_flags: u64,
) -> i32 {
    let (cpu, is_idle) = obj.scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags);
    if is_idle {
        rex_printk!("[scx_simple] select_cpu: pid={} prev_cpu={} -> cpu={} (idle, direct dispatch)\n",
                    p.get_pid(), prev_cpu, cpu).ok();
        obj.scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
    }
    cpu
}

/// Enqueue a runnable task into the shared FIFO dispatch queue.
#[rex_sched_ext(callback = "enqueue")]
fn simple_enqueue(obj: &sched_ext, p: &TaskStruct, enq_flags: u64) {
    rex_printk!("[scx_simple] enqueue: pid={} flags={}\n", p.get_pid(), enq_flags).ok();
    obj.scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

/// Called when the local DSQ is empty. Pull a task from the shared DSQ.
#[rex_sched_ext(callback = "dispatch")]
fn simple_dispatch(
    obj: &sched_ext,
    _cpu: i32,
    _prev: Option<&TaskStruct>,
) {
    match STALL_MODE {
        // Normal operation.
        0 => {
            rex_printk!("[scx_simple] dispatch: cpu={} pulling from shared DSQ\n", _cpu).ok();
            obj.scx_bpf_dsq_move_to_local(SHARED_DSQ);
        }
        // Soft stall: never pull from SHARED_DSQ, so everything piles up.
        // This is the code path that trips SCX_EXIT_ERROR_STALL in
        // linux/kernel/sched/ext.c:check_rq_for_timeouts().
        1 => {
            rex_printk!("[scx_simple] dispatch: cpu={} STALL_MODE=1 (not dispatching)\n", _cpu).ok();
        }
        // Hard stall: spin forever inside the callback.
        // Note: this hangs the CPU that runs dispatch() and usually
        // tickles the soft-lockup detector before scx's watchdog.
        _ => {
            rex_printk!("[scx_simple] dispatch: cpu={} STALL_MODE=2 (spinning forever)\n", _cpu).ok();
            loop {
                core::hint::spin_loop();
            }
        }
    }
}

/// Called once when the scheduler is loaded. Creates the shared DSQ.
#[rex_sched_ext(callback = "init")]
fn simple_init(obj: &sched_ext) -> i32 {
    rex_printk!("[scx_simple] init: creating shared DSQ (id={})\n", SHARED_DSQ).ok();
    match obj.scx_bpf_create_dsq(SHARED_DSQ, -1) {
        Ok(_) => {
            rex_printk!("[scx_simple] init: shared DSQ created successfully!\n").ok();
            0
        }
        Err(e) => {
            rex_printk!("[scx_simple] init: FAILED to create shared DSQ, err={}\n", e).ok();
            e
        }
    }
}

/// Called when the scheduler is being unloaded.
#[rex_sched_ext(callback = "exit")]
fn simple_exit(_obj: &sched_ext, _info: &ScxExitInfo) {
    rex_printk!("[scx_simple] exit: scheduler is being unloaded\n").ok();
}

/// Scheduler ops metadata placed in .struct_ops section.
#[rex_sched_ext_ops]
static simple_ops: SchedExtOps = SchedExtOps::with_name(b"simple");
