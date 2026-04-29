#![no_std]
#![no_main]

//! `scx_dsq_move` - Stage-3 §2.2 DSQ-iterator + cross-DSQ move smoke.
//!
//! Exercises the iterator + move kfunc family from
//! `rex/src/sched_ext/sched_ext_impl.rs`:
//!
//!   * [`BpfIterScxDsq::new`] -> `bpf_iter_scx_dsq_new`
//!   * [`Iterator::next`]    -> `bpf_iter_scx_dsq_next`
//!   * [`Drop`] of the iter  -> `bpf_iter_scx_dsq_destroy`
//!   * `scx_bpf_dsq_peek`    -> head-task lookup
//!   * `scx_bpf_dsq_move`            -> FIFO move via iterator
//!   * `scx_bpf_dsq_move_vtime`      -> vtime-prio move via iterator
//!   * `scx_bpf_dsq_move_set_slice`  -> slice override before next move
//!   * `scx_bpf_dsq_move_set_vtime`  -> vtime override before next move
//!
//! Scheduler shape: every wakeup goes through `enqueue` and lands on a
//! FIFO-ordered SOURCE_DSQ. The first dispatch that finds SOURCE_DSQ
//! non-empty walks it with a [`BpfIterScxDsq`] and moves every other
//! task to SINK_DSQ via the four move helpers (alternating `move` and
//! `move_vtime` so both code paths fire). Each dispatch then drains
//! SINK first and falls through to SOURCE so no task is starved. The
//! one-shot smoke logs the expected invariants:
//!
//!   * `peek_pid == iter_first_pid`
//!   * `nr_queued(SOURCE)` strictly decreases by `moved`
//!   * `nr_queued(SINK)` strictly increases by `moved`
//!
//! When the iterator goes out of scope at the end of the smoke block,
//! its `Drop` impl calls `bpf_iter_scx_dsq_destroy`. The runtest's
//! bpftool-prog leak guard catches any per-attach iterator leak across
//! cycles.

extern crate rex;

use core::sync::atomic::{AtomicBool, Ordering};

use rex::sched_ext::*;
use rex::task_struct::TaskStruct;
use rex::{rex_printk, rex_sched_ext, rex_sched_ext_ops};

const SOURCE_DSQ: u64 = 0xCAFE_0001;
const SINK_DSQ: u64 = 0xCAFE_0002;

/// Slice handed to `scx_bpf_dsq_move_set_slice` before every-other
/// task's move. Picked so it's distinguishable from `SCX_SLICE_DFL`
/// (20ms) in any later trace inspection.
const MOVE_SLICE_NS: u64 = 5_000_000; // 5 ms

/// Monotonic vtime fed into `scx_bpf_dsq_move_set_vtime`. Re-used
/// modulo arithmetic isn't important here; the kernel only needs the
/// value to be set so the kfunc has something to apply.
const MOVE_VTIME_BASE: u64 = 1;

static FIRST_DISPATCH_SMOKE: AtomicBool = AtomicBool::new(true);

#[rex_sched_ext(callback = "init")]
fn dsq_move_init(obj: &sched_ext) -> i32 {
    rex_printk!("[scx_dsq_move] init: BEGIN\n").ok();
    if let Err(e) = obj.scx_bpf_create_dsq(SOURCE_DSQ, -1) {
        rex_printk!(
            "[scx_dsq_move] init: FATAL: create SOURCE_DSQ failed err={}\n",
            e
        ).ok();
        return e;
    }
    if let Err(e) = obj.scx_bpf_create_dsq(SINK_DSQ, -1) {
        rex_printk!(
            "[scx_dsq_move] init: FATAL: create SINK_DSQ failed err={}\n",
            e
        ).ok();
        return e;
    }
    rex_printk!(
        "[scx_dsq_move] init: created SOURCE=0x{:x} SINK=0x{:x}\n",
        SOURCE_DSQ,
        SINK_DSQ
    ).ok();
    rex_printk!("[scx_dsq_move] init: END\n").ok();
    0
}

#[rex_sched_ext(callback = "select_cpu")]
fn dsq_move_select_cpu(
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
fn dsq_move_enqueue(obj: &sched_ext, p: &TaskStruct, enq_flags: u64) {
    obj.scx_bpf_dsq_insert(p, SOURCE_DSQ, SCX_SLICE_DFL, enq_flags);
}

#[rex_sched_ext(callback = "dispatch")]
fn dsq_move_dispatch(
    obj: &sched_ext,
    _cpu: i32,
    _prev: Option<&TaskStruct>,
) {
    // §2.2 full smoke. Bounded to two `next()` calls so we exercise
    // every kfunc in the section -- peek, iter new/next/destroy, the
    // FIFO and vtime move variants, and both _set_slice/_set_vtime
    // setters -- without holding the source-DSQ lock for an unbounded
    // walk. Concurrency is handled with `compare_exchange` so only one
    // CPU's dispatch enters the smoke.
    //
    // The iterator is pinned in this function's stack frame (via
    // BpfIterScxDsq::uninit() + open(&mut self, ...) on a stable
    // address). See wrappers.rs for why that pin matters --
    // `bpf_iter_scx_dsq_new` writes self-pointers into the iterator
    // bytes that are invalid after a struct move.
    if FIRST_DISPATCH_SMOKE
        .compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed)
        .is_ok()
    {
        let n_src_pre = obj.scx_bpf_dsq_nr_queued(SOURCE_DSQ);
        if n_src_pre <= 0 {
            FIRST_DISPATCH_SMOKE.store(true, Ordering::Release);
        } else {
            let peek_pid: i32 = obj
                .scx_bpf_dsq_peek(SOURCE_DSQ)
                .map(|t| t.get_pid())
                .unwrap_or(0);

            let mut iter_first_pid: i32 = 0;
            let mut moved: u32 = 0;
            let mut iter_count: u32 = 0;
            let mut peek_match: bool = false;

            let mut it = BpfIterScxDsq::uninit();
            if it.open(SOURCE_DSQ, 0).is_ok() {
                // First task: peek-match check + FIFO move via
                // scx_bpf_dsq_move (preceded by move_set_slice).
                if let Some(task) = it.next() {
                    iter_first_pid = task.get_pid();
                    peek_match = iter_first_pid == peek_pid;
                    iter_count += 1;
                    obj.scx_bpf_dsq_move_set_slice(&mut it, MOVE_SLICE_NS);
                    if obj.scx_bpf_dsq_move(&mut it, &task, SINK_DSQ, 0)
                    {
                        moved += 1;
                    }
                }
                // Second task: vtime move via scx_bpf_dsq_move_vtime
                // (preceded by move_set_vtime).
                if let Some(task) = it.next() {
                    iter_count += 1;
                    obj.scx_bpf_dsq_move_set_vtime(
                        &mut it,
                        MOVE_VTIME_BASE,
                    );
                    if obj.scx_bpf_dsq_move_vtime(
                        &mut it,
                        &task,
                        SINK_DSQ,
                        0,
                    ) {
                        moved += 1;
                    }
                }
                // it drops here -> bpf_iter_scx_dsq_destroy
            }

            let n_src_post = obj.scx_bpf_dsq_nr_queued(SOURCE_DSQ);
            let n_sink_post = obj.scx_bpf_dsq_nr_queued(SINK_DSQ);

            rex_printk!(
                "[scx_dsq_move] dispatch: peek_pid={} iter_first_pid={} peek_match={} iter_count={} moved={} src_pre={} src_post={} sink_post={}\n",
                peek_pid,
                iter_first_pid,
                peek_match,
                iter_count,
                moved,
                n_src_pre,
                n_src_post,
                n_sink_post,
            ).ok();
        }
    }

    // Drain SINK first so moved tasks don't starve, then fall through
    // to SOURCE.
    if !obj.scx_bpf_dsq_move_to_local(SINK_DSQ) {
        obj.scx_bpf_dsq_move_to_local(SOURCE_DSQ);
    }
}

#[rex_sched_ext(callback = "exit")]
fn dsq_move_exit(_obj: &sched_ext, _info: &ScxExitInfo) {
    rex_printk!(
        "[scx_dsq_move] exit: scheduler is being unloaded\n"
    ).ok();
}

#[rex_sched_ext_ops]
static dsq_move_ops: SchedExtOps = SchedExtOps::with_name(b"dsqmov");
