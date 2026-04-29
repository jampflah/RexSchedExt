#![no_std]
#![no_main]

//! `scx_vtime` - Stage-3 §2.1 vtime-DSQ scheduler.
//!
//! Exercises the three vtime-related kfunc wrappers in
//! `rex/src/sched_ext/sched_ext_impl.rs`:
//!
//!   * `scx_bpf_dsq_insert_vtime` - the legacy scalar-argument ABI.
//!   * `scx_bpf_dsq_insert_vtime_args` -> `__scx_bpf_dsq_insert_vtime` -
//!     the args-struct ABI used by the upstream BPF skeletons. Returns
//!     `true` on success; logged once on the first enqueue.
//!   * `scx_bpf_task_set_dsq_vtime` - associates a virtual time with the
//!     task before it goes into a vtime-ordered DSQ.
//!
//! Scheduler shape: every wakeup goes through `enqueue` (no idle
//! direct-dispatch path) so we exercise the vtime insert path on every
//! task. `dispatch` simply drains the vtime DSQ via
//! `scx_bpf_dsq_move_to_local`. Vtimes are monotonically increasing
//! across all tasks so the kernel's vtime ordering is well-defined
//! (later-enqueued tasks have larger vtime and run after earlier ones).

extern crate rex;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use rex::sched_ext::*;
use rex::task_struct::TaskStruct;
use rex::{rex_printk, rex_sched_ext, rex_sched_ext_ops};

const VTIME_DSQ: u64 = 0;

/// Monotonic counter handing out virtual times to enqueued tasks.
/// Starts at 1 so a vtime of 0 is a sentinel ("never enqueued").
static NEXT_VTIME: AtomicU64 = AtomicU64::new(1);

/// One-shot guards for the per-callback smoke logs.
static FIRST_ENQUEUE: AtomicBool = AtomicBool::new(true);
static FIRST_DISPATCH: AtomicBool = AtomicBool::new(true);

#[rex_sched_ext(callback = "init")]
fn vtime_init(obj: &sched_ext) -> i32 {
    rex_printk!("[scx_vtime] init: BEGIN\n").ok();
    if let Err(e) = obj.scx_bpf_create_dsq(VTIME_DSQ, -1) {
        rex_printk!(
            "[scx_vtime] init: FATAL: create VTIME_DSQ failed err={}\n",
            e
        ).ok();
        return e;
    }
    rex_printk!("[scx_vtime] init: created VTIME_DSQ id={}\n", VTIME_DSQ).ok();
    rex_printk!("[scx_vtime] init: END\n").ok();
    0
}

/// Skip the idle direct-dispatch path: every wakeup must go through
/// `enqueue` so we actually exercise the vtime insert kfuncs. We still
/// call `scx_bpf_select_cpu_dfl` to get a sane CPU placement.
#[rex_sched_ext(callback = "select_cpu")]
fn vtime_select_cpu(
    obj: &sched_ext,
    p: &TaskStruct,
    prev_cpu: i32,
    wake_flags: u64,
) -> i32 {
    let (cpu, _is_idle) = obj.scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags);
    cpu
}

#[rex_sched_ext(callback = "enqueue")]
fn vtime_enqueue(obj: &sched_ext, p: &TaskStruct, enq_flags: u64) {
    let vtime = NEXT_VTIME.fetch_add(1, Ordering::Relaxed);

    // §2.7: associate the vtime with the task itself so any later
    // dispatch path that reads it (or move_vtime helpers) see the same
    // value as the DSQ insert below.
    let set_ok = obj.scx_bpf_task_set_dsq_vtime(p, vtime);

    if FIRST_ENQUEUE.swap(false, Ordering::Relaxed) {
        // §2.1: route the very first enqueue through the args-struct
        // ABI so we exercise both code paths in one attach. The args
        // ABI is `__scx_bpf_dsq_insert_vtime` and returns `true` on
        // success; the v1 `scx_bpf_dsq_insert_vtime` is a void.
        let ok = obj.scx_bpf_dsq_insert_vtime_args(
            p,
            VTIME_DSQ,
            SCX_SLICE_DFL,
            vtime,
            enq_flags,
        );
        rex_printk!(
            "[scx_vtime] enqueue: first-call vtime={} task_set_dsq_vtime={} insert_vtime_args={}\n",
            vtime,
            set_ok,
            ok,
        ).ok();
        return;
    }

    obj.scx_bpf_dsq_insert_vtime(
        p,
        VTIME_DSQ,
        SCX_SLICE_DFL,
        vtime,
        enq_flags,
    );
}

#[rex_sched_ext(callback = "dispatch")]
fn vtime_dispatch(
    obj: &sched_ext,
    cpu: i32,
    _prev: Option<&TaskStruct>,
) {
    if FIRST_DISPATCH.swap(false, Ordering::Relaxed) {
        let queued = obj.scx_bpf_dsq_nr_queued(VTIME_DSQ);
        rex_printk!(
            "[scx_vtime] dispatch: first-call cpu={} VTIME_DSQ.nr_queued={}\n",
            cpu,
            queued
        ).ok();
    }
    obj.scx_bpf_dsq_move_to_local(VTIME_DSQ);
}

#[rex_sched_ext(callback = "exit")]
fn vtime_exit(_obj: &sched_ext, _info: &ScxExitInfo) {
    let last = NEXT_VTIME.load(Ordering::Relaxed);
    rex_printk!(
        "[scx_vtime] exit: NEXT_VTIME={} (vtimes assigned across this attach)\n",
        last
    ).ok();
    rex_printk!("[scx_vtime] exit: scheduler is being unloaded\n").ok();
}

#[rex_sched_ext_ops]
static vtime_ops: SchedExtOps = SchedExtOps::with_name(b"vtime");
