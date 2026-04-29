#![no_std]
#![no_main]

//! `scx_kfunc_smoke` - Stage-2 read-only kfunc smoke test scheduler.
//!
//! See [docs/sched-ext-test-plan.md](../../docs/sched-ext-test-plan.md):
//! exercises the read-only kfunc wrappers in `rex/src/sched_ext/` so that:
//!
//!   * §2.3: `scx_bpf_create_dsq` + `scx_bpf_destroy_dsq` round-trip
//!     (and `scx_bpf_dsq_nr_queued` on a destroyed id returns negative).
//!   * §2.5: every cpumask / topology getter returns non-null (and
//!     `_put_*` doesn't crash even after a 100x get/put loop).
//!   * §2.6 (cpu_* helpers): `scx_bpf_cpu_node`, `scx_bpf_cpu_rq`,
//!     `scx_bpf_locked_rq`, `scx_bpf_cpu_curr`, `scx_bpf_task_cpu`.
//!   * §2.8: `scx_bpf_dispatch_nr_slots` returns >0 inside dispatch and
//!     `scx_bpf_dispatch_cancel` doesn't crash; the next dispatch still
//!     fires.
//!   * §2.11: `scx_bpf_now` is monotonic between init and exit.
//!     (`scx_bpf_events` requires unsafe pointer setup; skipped here
//!     until the wrapper exposes a safe constructor.)
//!
//! The scheduler itself is `scx_simple`-shaped: select_cpu direct-dispatches
//! to LOCAL when an idle CPU is found, otherwise enqueue puts the task on a
//! shared FIFO and dispatch drains it. That keeps the host system viable so
//! the runtest can drive a workload long enough for every callback to fire.

extern crate rex;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use rex::sched_ext::*;
use rex::task_struct::TaskStruct;
use rex::{rex_printk, rex_sched_ext, rex_sched_ext_ops};

/// Shared FIFO DSQ used by the viable scheduler path.
const SHARED_DSQ: u64 = 0;

/// Throwaway DSQ created in init only to verify the create/destroy round-trip.
const SCRATCH_DSQ: u64 = 0xDEAD_BEEF;

/// Number of get/put cycles for the cpumask leak smoke. The kernel's
/// reference count must come back to baseline at the end; if it didn't,
/// kmemleak / repeated runs would surface it.
const NR_GET_PUT_CYCLES: u32 = 100;

/// One-shot guards so the inside-callback smoke checks log exactly once
/// per scheduler attach. Without this the logs would flood the trace
/// buffer and the assertions still hold trivially.
static FIRST_ENQUEUE: AtomicBool = AtomicBool::new(true);
static FIRST_DISPATCH: AtomicBool = AtomicBool::new(true);

/// `scx_bpf_now()` taken in init; cross-checked against the value taken
/// in exit to assert §2.11's monotonicity property.
static INIT_NOW: AtomicU64 = AtomicU64::new(0);

#[rex_sched_ext(callback = "init")]
fn smoke_init(obj: &sched_ext) -> i32 {
    rex_printk!("[scx_kfunc_smoke] init: BEGIN\n").ok();

    if let Err(e) = obj.scx_bpf_create_dsq(SHARED_DSQ, -1) {
        rex_printk!(
            "[scx_kfunc_smoke] init: FATAL: create SHARED_DSQ failed err={}\n",
            e
        ).ok();
        return e;
    }

    if let Err(e) = obj.scx_bpf_create_dsq(SCRATCH_DSQ, -1) {
        rex_printk!(
            "[scx_kfunc_smoke] init: create SCRATCH_DSQ failed err={}\n",
            e
        ).ok();
        return e;
    }
    obj.scx_bpf_destroy_dsq(SCRATCH_DSQ);
    let nr = obj.scx_bpf_dsq_nr_queued(SCRATCH_DSQ);
    rex_printk!(
        "[scx_kfunc_smoke] dsq_nr_queued(destroyed)={} (expect <0)\n",
        nr
    ).ok();

    let t0 = obj.scx_bpf_now();
    INIT_NOW.store(t0, Ordering::Relaxed);
    rex_printk!("[scx_kfunc_smoke] now(t0)={}\n", t0).ok();

    let nr_cpus = obj.scx_bpf_nr_cpu_ids();
    let nr_nodes = obj.scx_bpf_nr_node_ids();
    rex_printk!(
        "[scx_kfunc_smoke] nr_cpu_ids={} nr_node_ids={}\n",
        nr_cpus,
        nr_nodes
    ).ok();

    let mut cycles_done: u32 = 0;
    while cycles_done < NR_GET_PUT_CYCLES {
        if let Some(m) = obj.scx_bpf_get_possible_cpumask() {
            obj.scx_bpf_put_cpumask(m);
            cycles_done += 1;
        } else {
            rex_printk!(
                "[scx_kfunc_smoke] get_possible_cpumask returned None at cycle {}\n",
                cycles_done
            ).ok();
            break;
        }
    }
    rex_printk!(
        "[scx_kfunc_smoke] get_possible_cpumask: {} cycles complete\n",
        cycles_done
    ).ok();

    if let Some(m) = obj.scx_bpf_get_online_cpumask() {
        rex_printk!("[scx_kfunc_smoke] get_online_cpumask: ok\n").ok();
        obj.scx_bpf_put_cpumask(m);
    } else {
        rex_printk!("[scx_kfunc_smoke] get_online_cpumask: None\n").ok();
    }

    if let Some(m) = obj.scx_bpf_get_idle_cpumask() {
        rex_printk!("[scx_kfunc_smoke] get_idle_cpumask: ok\n").ok();
        obj.scx_bpf_put_idle_cpumask(m);
    } else {
        rex_printk!("[scx_kfunc_smoke] get_idle_cpumask: None\n").ok();
    }

    if let Some(m) = obj.scx_bpf_get_idle_smtmask() {
        rex_printk!("[scx_kfunc_smoke] get_idle_smtmask: ok\n").ok();
        obj.scx_bpf_put_idle_cpumask(m);
    } else {
        rex_printk!("[scx_kfunc_smoke] get_idle_smtmask: None\n").ok();
    }

    // Per-node idle getters (`scx_bpf_get_idle_cpumask_node`,
    // `scx_bpf_get_idle_smtmask_node`) are intentionally NOT exercised here
    // -- they require ops.flags & SCX_OPS_BUILTIN_IDLE_PER_NODE, which in
    // turn makes the flat getters above hard-error
    // ("SCX_OPS_BUILTIN_IDLE_PER_NODE enabled"). Per-node coverage belongs
    // in a dedicated `scx_kfunc_smoke_per_node` sample with the flag set.
    // See linux/kernel/sched/ext_idle.c:validate_node and the no-flag
    // branches at the same file's line ~1106 / ~1165.

    // Per-CPU sweep of cpu_node + cpu_curr.
    let mut cpu: i32 = 0;
    while (cpu as u32) < nr_cpus {
        let node = obj.scx_bpf_cpu_node(cpu);
        let curr_present = obj.scx_bpf_cpu_curr(cpu).is_some();
        rex_printk!(
            "[scx_kfunc_smoke] cpu={} node={} cpu_curr.is_some={}\n",
            cpu,
            node,
            curr_present
        ).ok();
        cpu += 1;
    }

    // Single call to the now-deprecated `scx_bpf_cpu_rq`. The kernel
    // emits exactly one WARN_ONCE per boot for it; one call is enough
    // for GOT-relocation coverage without flooding dmesg. Future code
    // should use `scx_bpf_locked_rq()` (inside callbacks) or
    // `scx_bpf_cpu_curr()` (for remote CPUs) -- exercised above.
    let cpu0_rq_present = obj.scx_bpf_cpu_rq(0).is_some();
    rex_printk!(
        "[scx_kfunc_smoke] cpu_rq(0).is_some={} (kfunc is deprecated; one-shot)\n",
        cpu0_rq_present
    ).ok();

    rex_printk!("[scx_kfunc_smoke] init: END\n").ok();
    0
}

#[rex_sched_ext(callback = "select_cpu")]
fn smoke_select_cpu(
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
fn smoke_enqueue(obj: &sched_ext, p: &TaskStruct, enq_flags: u64) {
    if FIRST_ENQUEUE.swap(false, Ordering::Relaxed) {
        let locked = obj.scx_bpf_locked_rq().is_some();
        let task_cpu = obj.scx_bpf_task_cpu(p);
        rex_printk!(
            "[scx_kfunc_smoke] enqueue: first-call locked_rq.is_some={} task_cpu={}\n",
            locked,
            task_cpu
        ).ok();
    }
    obj.scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

#[rex_sched_ext(callback = "dispatch")]
fn smoke_dispatch(
    obj: &sched_ext,
    _cpu: i32,
    prev: Option<&TaskStruct>,
) {
    // §2.8: both dispatch context kfuncs require ops.dispatch() context
    // (mask SCX_KF_DISPATCH = 0x2). dispatch_cancel additionally needs a
    // pending entry in the dispatch buffer (cursor > 0) -- otherwise the
    // kernel scx_errors with "dispatch buffer underflow". The cleanest
    // way to satisfy that is to insert `prev` (the just-stopped task on
    // this CPU; not currently in any DSQ) into LOCAL, immediately cancel
    // the pending insert, then proceed to drain SHARED via the normal
    // move_to_local path. We only burn the FIRST_DISPATCH one-shot when
    // prev is non-None so an idle-CPU dispatch doesn't waste it.
    if FIRST_DISPATCH.load(Ordering::Relaxed) {
        if let Some(prev_task) = prev {
            let slots = obj.scx_bpf_dispatch_nr_slots();
            obj.scx_bpf_dsq_insert(
                prev_task,
                SCX_DSQ_LOCAL,
                SCX_SLICE_DFL,
                0,
            );
            obj.scx_bpf_dispatch_cancel();
            FIRST_DISPATCH.store(false, Ordering::Relaxed);
            rex_printk!(
                "[scx_kfunc_smoke] dispatch: first-call nr_slots={} dispatch_cancel ok\n",
                slots
            ).ok();
        }
    }
    obj.scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

#[rex_sched_ext(callback = "exit")]
fn smoke_exit(obj: &sched_ext, _info: &ScxExitInfo) {
    let t1 = obj.scx_bpf_now();
    let t0 = INIT_NOW.load(Ordering::Relaxed);
    let monotonic = t1 >= t0;
    let delta = t1.wrapping_sub(t0);
    rex_printk!(
        "[scx_kfunc_smoke] exit: now(t1)={} delta={} monotonic={}\n",
        t1,
        delta,
        monotonic
    ).ok();

    // §2.11: snapshot scheduler-wide event counters into our buffer and
    // log a fingerprint. The kfunc fills `scx_event_stats`'s s64 fields
    // (SCX_EV_*); we sum the populated counters to keep the log line
    // size-stable across kernel struct extensions. The buffer is
    // zero-initialised by ScxEventStats::zeroed(), so trailing untouched
    // entries don't perturb the sum and the slice accessor is safe.
    let mut events = ScxEventStats::zeroed();
    obj.scx_bpf_events(&mut events);
    let counters = events.as_i64_slice();
    let mut nonzero: u32 = 0;
    let mut sum: i64 = 0;
    for c in counters {
        if *c != 0 {
            nonzero += 1;
            sum = sum.wrapping_add(*c);
        }
    }
    rex_printk!(
        "[scx_kfunc_smoke] exit: events: nonzero_counters={} sum={}\n",
        nonzero,
        sum
    ).ok();

    rex_printk!("[scx_kfunc_smoke] exit: scheduler is being unloaded\n").ok();
}

#[rex_sched_ext_ops]
static smoke_ops: SchedExtOps = SchedExtOps::with_name(b"kfsmoke");
