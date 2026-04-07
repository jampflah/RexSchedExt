#![no_std]
#![no_main]

extern crate rex;

use rex::sched_ext::*;
use rex::task_struct::TaskStruct;
use rex::{rex_printk, rex_sched_ext, rex_sched_ext_ops};

const SHARED_DSQ: u64 = 0;

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
        obj.scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
    }
    cpu
}

/// Enqueue a runnable task into the shared FIFO dispatch queue.
#[rex_sched_ext(callback = "enqueue")]
fn simple_enqueue(obj: &sched_ext, p: &TaskStruct, enq_flags: u64) {
    obj.scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

/// Called when the local DSQ is empty. Pull a task from the shared DSQ.
#[rex_sched_ext(callback = "dispatch")]
fn simple_dispatch(
    obj: &sched_ext,
    _cpu: i32,
    _prev: Option<&TaskStruct>,
) {
    obj.scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

/// Called once when the scheduler is loaded. Creates the shared DSQ.
#[rex_sched_ext(callback = "init")]
fn simple_init(obj: &sched_ext) -> i32 {
    match obj.scx_bpf_create_dsq(SHARED_DSQ, -1) {
        Ok(_) => 0,
        Err(e) => e,
    }
}

/// Called when the scheduler is being unloaded.
#[rex_sched_ext(callback = "exit")]
fn simple_exit(_obj: &sched_ext, _info: &ScxExitInfo) {}

/// Scheduler ops metadata placed in .struct_ops section.
#[rex_sched_ext_ops]
static simple_ops: SchedExtOps = SchedExtOps::with_name(b"simple");
