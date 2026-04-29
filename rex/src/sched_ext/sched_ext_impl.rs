use core::marker::PhantomData;

use crate::base_helper::termination_check;
use crate::bindings::linux::kernel::task_struct;
use crate::bindings::uapi::linux::bpf::bpf_map_type;
use crate::ffi;
#[cfg(CONFIG_CGROUP_SCHED = "y")]
use crate::sched_ext::binding::cgroup;
use crate::sched_ext::binding::{
    cpumask, scx_cpu_acquire_args, scx_cpu_release_args, scx_dump_ctx,
    ScxBpfDsqInsertVtimeArgs, ScxBpfSelectCpuAndArgs,
};
#[cfg(CONFIG_CGROUP_SCHED = "y")]
use crate::sched_ext::wrappers::Cgroup;
use crate::sched_ext::wrappers::{
    Cpumask, Rq, ScxCpuAcquireArgs, ScxCpuReleaseArgs, ScxDumpCtx,
    ScxEventStats,
};
use crate::task_struct::TaskStruct;
use crate::utils::{to_result, NoRef, Result};

#[repr(C)]
pub struct sched_ext {
    _placeholder: PhantomData<()>,
}

impl sched_ext {
    crate::base_helper::base_helper_defs!();

    pub const unsafe fn new() -> sched_ext {
        Self {
            _placeholder: PhantomData,
        }
    }

    /// Convert a raw task_struct pointer from a kernel callback argument
    /// into a safe TaskStruct reference.
    ///
    /// # Safety
    /// The caller must ensure `task` is a valid, non-null `task_struct` pointer
    /// that remains valid for the duration of the callback (guaranteed by the
    /// kernel's RCU protections in sched_ext).
    #[inline(always)]
    pub unsafe fn convert_task(task: *mut task_struct) -> TaskStruct {
        TaskStruct::from_raw(task)
    }

    /// Convert a raw `cgroup *` from a kernel callback into a safe wrapper.
    ///
    /// # Safety
    /// `p` must be a valid, non-null `cgroup *` that remains valid for the
    /// duration of the callback (RCU-protected by sched_ext).
    #[cfg(CONFIG_CGROUP_SCHED = "y")]
    #[inline(always)]
    pub unsafe fn convert_cgroup(p: *mut cgroup) -> Cgroup {
        unsafe { Cgroup::from_raw(p) }
    }

    /// Convert a raw `const cpumask *` from a kernel callback.
    ///
    /// # Safety
    /// `p` must be a valid, non-null `const cpumask *` that remains valid
    /// for the duration of the callback.
    #[inline(always)]
    pub unsafe fn convert_cpumask(p: *const cpumask) -> Cpumask {
        unsafe { Cpumask::from_raw(p) }
    }

    /// Convert a raw `const scx_dump_ctx *` from a kernel callback.
    ///
    /// # Safety
    /// `p` must be a valid, non-null `const scx_dump_ctx *` that remains
    /// valid for the duration of the callback.
    #[inline(always)]
    pub unsafe fn convert_dump_ctx(p: *const scx_dump_ctx) -> ScxDumpCtx {
        unsafe { ScxDumpCtx::from_raw(p) }
    }

    /// Convert a raw `const scx_cpu_acquire_args *` from a kernel callback.
    ///
    /// # Safety
    /// `p` must be a valid, non-null pointer that remains valid for the
    /// duration of the callback.
    #[inline(always)]
    pub unsafe fn convert_cpu_acquire_args(
        p: *const scx_cpu_acquire_args,
    ) -> ScxCpuAcquireArgs {
        unsafe { ScxCpuAcquireArgs::from_raw(p) }
    }

    /// Convert a raw `const scx_cpu_release_args *` from a kernel callback.
    ///
    /// # Safety
    /// `p` must be a valid, non-null pointer that remains valid for the
    /// duration of the callback.
    #[inline(always)]
    pub unsafe fn convert_cpu_release_args(
        p: *const scx_cpu_release_args,
    ) -> ScxCpuReleaseArgs {
        unsafe { ScxCpuReleaseArgs::from_raw(p) }
    }

    pub fn bpf_get_current_task(&self) -> Option<TaskStruct> {
        TaskStruct::get_current_task()
    }

    // ---------------------------------------------------------------
    //  scx_bpf_* kfunc helpers
    //  These wrap the kernel kfuncs exposed by sched_ext (ext.c).
    //  They are resolved at load time via Rex's dynamic symbol
    //  resolution (.rela.dyn GOT patching).
    // ---------------------------------------------------------------

    /// Insert task `p` into dispatch queue `dsq_id` with time slice `slice`.
    /// `enq_flags` are `SCX_ENQ_*` flags.
    #[inline(always)]
    pub fn scx_bpf_dsq_insert(
        &self,
        p: &TaskStruct,
        dsq_id: u64,
        slice: u64,
        enq_flags: u64,
    ) {
        termination_check!(unsafe {
            ffi::scx_bpf_dsq_insert(p.as_ptr(), dsq_id, slice, enq_flags)
        })
    }

    /// Use the default CPU selection logic. Returns `(cpu, is_idle)`.
    /// If `is_idle` is true, the caller can directly dispatch the task
    /// to `SCX_DSQ_LOCAL` to skip the enqueue path.
    #[inline(always)]
    pub fn scx_bpf_select_cpu_dfl(
        &self,
        p: &TaskStruct,
        prev_cpu: i32,
        wake_flags: u64,
    ) -> (i32, bool) {
        let mut is_idle: bool = false;
        let cpu = termination_check!(unsafe {
            ffi::scx_bpf_select_cpu_dfl(
                p.as_ptr(),
                prev_cpu,
                wake_flags,
                &mut is_idle as *mut bool,
            )
        });
        (cpu, is_idle)
    }

    /// Move a task from the specified DSQ to the local CPU's DSQ.
    /// Returns true if a task was consumed.
    /// (Replaces the old `scx_bpf_consume` which no longer exists.)
    #[inline(always)]
    pub fn scx_bpf_dsq_move_to_local(&self, dsq_id: u64) -> bool {
        termination_check!(unsafe { ffi::scx_bpf_dsq_move_to_local(dsq_id) })
    }

    /// Backward-compatible alias for `scx_bpf_dsq_move_to_local`.
    #[inline(always)]
    pub fn scx_bpf_consume(&self, dsq_id: u64) -> bool {
        self.scx_bpf_dsq_move_to_local(dsq_id)
    }

    /// Kick the specified CPU to trigger rescheduling.
    /// `flags` are `SCX_KICK_*` flags.
    #[inline(always)]
    pub fn scx_bpf_kick_cpu(&self, cpu: i32, flags: u64) {
        termination_check!(unsafe { ffi::scx_bpf_kick_cpu(cpu, flags) })
    }

    /// Create a custom dispatch queue with the given ID and NUMA node.
    #[inline(always)]
    pub fn scx_bpf_create_dsq(&self, dsq_id: u64, node: i32) -> Result {
        termination_check!(unsafe {
            to_result!(ffi::scx_bpf_create_dsq(dsq_id, node) as i32)
        })
    }

    /// Destroy a previously created custom dispatch queue.
    #[inline(always)]
    pub fn scx_bpf_destroy_dsq(&self, dsq_id: u64) {
        termination_check!(unsafe { ffi::scx_bpf_destroy_dsq(dsq_id) })
    }

    /// Return the CPU that task `p` is currently or was most recently on.
    #[inline(always)]
    pub fn scx_bpf_task_cpu(&self, p: &TaskStruct) -> i32 {
        termination_check!(unsafe { ffi::scx_bpf_task_cpu(p.as_ptr()) })
    }

    /// Report a fatal scheduler error. The scheduler will be unloaded
    /// and the system will fall back to the default scheduler.
    /// Uses `scx_bpf_error_bstr(fmt, data, data__sz)` under the hood.
    #[inline(always)]
    pub fn scx_bpf_error_str(&self, msg: &str) {
        termination_check!(unsafe {
            ffi::scx_bpf_error_bstr(
                msg.as_ptr(),
                core::ptr::null(),
                0,
            )
        })
    }

    /// Insert task `p` into a VTIME-ordered dispatch queue.
    #[inline(always)]
    pub fn scx_bpf_dsq_insert_vtime(
        &self,
        p: &TaskStruct,
        dsq_id: u64,
        slice: u64,
        vtime: u64,
        enq_flags: u64,
    ) {
        termination_check!(unsafe {
            ffi::scx_bpf_dsq_insert_vtime(p.as_ptr(), dsq_id, slice, vtime, enq_flags)
        })
    }

    /// Return the number of remaining dispatch slots in the current
    /// dispatch context.
    #[inline(always)]
    pub fn scx_bpf_dispatch_nr_slots(&self) -> u32 {
        termination_check!(unsafe { ffi::scx_bpf_dispatch_nr_slots() })
    }

    /// Cancel the last dispatch operation.
    #[inline(always)]
    pub fn scx_bpf_dispatch_cancel(&self) {
        termination_check!(unsafe { ffi::scx_bpf_dispatch_cancel() })
    }

    /// Return the number of tasks queued in the specified DSQ.
    #[inline(always)]
    pub fn scx_bpf_dsq_nr_queued(&self, dsq_id: u64) -> i32 {
        termination_check!(unsafe { ffi::scx_bpf_dsq_nr_queued(dsq_id) })
    }

    /// Set the time slice for the given task.
    #[inline(always)]
    pub fn scx_bpf_task_set_slice(&self, p: &TaskStruct, slice: u64) -> bool {
        termination_check!(unsafe { ffi::scx_bpf_task_set_slice(p.as_ptr(), slice) })
    }

    /// Set the virtual time of a task for VTIME-ordered DSQs.
    #[inline(always)]
    pub fn scx_bpf_task_set_dsq_vtime(&self, p: &TaskStruct, vtime: u64) -> bool {
        termination_check!(unsafe { ffi::scx_bpf_task_set_dsq_vtime(p.as_ptr(), vtime) })
    }

    /// Re-enqueue tasks from the local DSQ after a CPU goes offline.
    #[inline(always)]
    pub fn scx_bpf_reenqueue_local(&self) -> u32 {
        termination_check!(unsafe { ffi::scx_bpf_reenqueue_local() })
    }

    /// Return the number of possible CPUs.
    #[inline(always)]
    pub fn scx_bpf_nr_cpu_ids(&self) -> u32 {
        termination_check!(unsafe { ffi::scx_bpf_nr_cpu_ids() })
    }

    // ---------------------------------------------------------------
    //  v2 entry points
    // ---------------------------------------------------------------

    /// `scx_bpf_dsq_insert___v2` — bool-returning dispatch insert.
    /// Returns `true` on success (e.g. `false` if scx_root has detached).
    #[inline(always)]
    pub fn scx_bpf_dsq_insert_v2(
        &self,
        p: &TaskStruct,
        dsq_id: u64,
        slice: u64,
        enq_flags: u64,
    ) -> bool {
        termination_check!(unsafe {
            ffi::scx_bpf_dsq_insert___v2(p.as_ptr(), dsq_id, slice, enq_flags)
        })
    }

    /// `scx_bpf_reenqueue_local___v2` — defer-style re-enqueue helper.
    #[inline(always)]
    pub fn scx_bpf_reenqueue_local_v2(&self) {
        termination_check!(unsafe { ffi::scx_bpf_reenqueue_local___v2() })
    }

    // ---------------------------------------------------------------
    //  Arg-wrapped underscored kfuncs.
    //  The args struct lives in the published BPF ABI (see
    //  linux/tools/sched_ext/include/scx/compat.bpf.h). We assemble
    //  it on the BPF stack from scalar arguments here.
    // ---------------------------------------------------------------

    /// `__scx_bpf_dsq_insert_vtime` — vtime insert via the args-struct ABI.
    /// Returns `true` on success.
    #[inline(always)]
    pub fn scx_bpf_dsq_insert_vtime_args(
        &self,
        p: &TaskStruct,
        dsq_id: u64,
        slice: u64,
        vtime: u64,
        enq_flags: u64,
    ) -> bool {
        let mut args = ScxBpfDsqInsertVtimeArgs {
            dsq_id,
            slice,
            vtime,
            enq_flags,
        };
        termination_check!(unsafe {
            ffi::__scx_bpf_dsq_insert_vtime(
                p.as_ptr(),
                &mut args as *mut _,
            )
        })
    }

    /// `__scx_bpf_select_cpu_and` — CPU selection via the args-struct ABI.
    /// Returns the chosen CPU, or a negative errno on failure.
    #[inline(always)]
    pub fn scx_bpf_select_cpu_and_args(
        &self,
        p: &TaskStruct,
        cpus_allowed: &Cpumask,
        prev_cpu: i32,
        wake_flags: u64,
        flags: u64,
    ) -> i32 {
        let mut args = ScxBpfSelectCpuAndArgs {
            prev_cpu,
            wake_flags,
            flags,
        };
        termination_check!(unsafe {
            ffi::__scx_bpf_select_cpu_and(
                p.as_ptr(),
                cpus_allowed.as_ptr(),
                &mut args as *mut _,
            )
        })
    }

    // ---------------------------------------------------------------
    //  DSQ iterator move helpers.
    //  These all take a `&mut BpfIterScxDsq` whose owning iterator
    //  the caller is currently iterating with.
    // ---------------------------------------------------------------

    /// Set the time slice for the next move from this iterator.
    #[inline(always)]
    pub fn scx_bpf_dsq_move_set_slice(
        &self,
        it: &mut crate::sched_ext::wrappers::BpfIterScxDsq,
        slice: u64,
    ) {
        termination_check!(unsafe {
            ffi::scx_bpf_dsq_move_set_slice(it.as_mut_ptr(), slice)
        })
    }

    /// Set the vtime for the next move from this iterator.
    #[inline(always)]
    pub fn scx_bpf_dsq_move_set_vtime(
        &self,
        it: &mut crate::sched_ext::wrappers::BpfIterScxDsq,
        vtime: u64,
    ) {
        termination_check!(unsafe {
            ffi::scx_bpf_dsq_move_set_vtime(it.as_mut_ptr(), vtime)
        })
    }

    /// Move task `p` from the iterator's source DSQ to `dsq_id`.
    /// Returns `true` if the task was moved.
    #[inline(always)]
    pub fn scx_bpf_dsq_move(
        &self,
        it: &mut crate::sched_ext::wrappers::BpfIterScxDsq,
        p: &TaskStruct,
        dsq_id: u64,
        enq_flags: u64,
    ) -> bool {
        termination_check!(unsafe {
            ffi::scx_bpf_dsq_move(
                it.as_mut_ptr(),
                p.as_ptr(),
                dsq_id,
                enq_flags,
            )
        })
    }

    /// Move `p` to a vtime-ordered DSQ.
    #[inline(always)]
    pub fn scx_bpf_dsq_move_vtime(
        &self,
        it: &mut crate::sched_ext::wrappers::BpfIterScxDsq,
        p: &TaskStruct,
        dsq_id: u64,
        enq_flags: u64,
    ) -> bool {
        termination_check!(unsafe {
            ffi::scx_bpf_dsq_move_vtime(
                it.as_mut_ptr(),
                p.as_ptr(),
                dsq_id,
                enq_flags,
            )
        })
    }

    /// Peek at the head task of `dsq_id` without dequeuing it.
    /// Returns `None` if the DSQ is empty or invalid.
    #[inline(always)]
    pub fn scx_bpf_dsq_peek(&self, dsq_id: u64) -> Option<TaskStruct> {
        let p = termination_check!(unsafe { ffi::scx_bpf_dsq_peek(dsq_id) });
        if p.is_null() {
            None
        } else {
            Some(unsafe { TaskStruct::from_raw(p) })
        }
    }

    // ---------------------------------------------------------------
    //  bstr-style logging
    // ---------------------------------------------------------------

    /// Trigger a fatal scheduler exit with the given exit code and message.
    /// Convenience wrapper around `scx_bpf_exit_bstr` with no arg data.
    #[inline(always)]
    pub fn scx_bpf_exit_str(&self, exit_code: i64, msg: &str) {
        termination_check!(unsafe {
            ffi::scx_bpf_exit_bstr(
                exit_code,
                msg.as_ptr(),
                core::ptr::null(),
                0,
            )
        })
    }

    /// Append a literal message to the scheduler's debug dump.
    /// Convenience wrapper around `scx_bpf_dump_bstr` with no arg data.
    #[inline(always)]
    pub fn scx_bpf_dump_str(&self, msg: &str) {
        termination_check!(unsafe {
            ffi::scx_bpf_dump_bstr(msg.as_ptr(), core::ptr::null(), 0)
        })
    }

    // ---------------------------------------------------------------
    //  CPU performance control
    // ---------------------------------------------------------------

    /// Maximum performance level (perf scale) for `cpu`.
    #[inline(always)]
    pub fn scx_bpf_cpuperf_cap(&self, cpu: i32) -> u32 {
        termination_check!(unsafe { ffi::scx_bpf_cpuperf_cap(cpu) })
    }

    /// Currently requested performance level for `cpu`.
    #[inline(always)]
    pub fn scx_bpf_cpuperf_cur(&self, cpu: i32) -> u32 {
        termination_check!(unsafe { ffi::scx_bpf_cpuperf_cur(cpu) })
    }

    /// Request `perf` (0..=cap) on `cpu`.
    #[inline(always)]
    pub fn scx_bpf_cpuperf_set(&self, cpu: i32, perf: u32) {
        termination_check!(unsafe { ffi::scx_bpf_cpuperf_set(cpu, perf) })
    }

    // ---------------------------------------------------------------
    //  Topology / cpumask getters
    // ---------------------------------------------------------------

    /// Number of NUMA node IDs the kernel knows about.
    #[inline(always)]
    pub fn scx_bpf_nr_node_ids(&self) -> u32 {
        termination_check!(unsafe { ffi::scx_bpf_nr_node_ids() })
    }

    /// Refcounted snapshot of the possible-CPU mask. Caller must release
    /// it with `scx_bpf_put_cpumask`.
    #[inline(always)]
    pub fn scx_bpf_get_possible_cpumask(&self) -> Option<Cpumask> {
        let p =
            termination_check!(unsafe { ffi::scx_bpf_get_possible_cpumask() });
        if p.is_null() {
            None
        } else {
            Some(unsafe { Cpumask::from_raw(p) })
        }
    }

    /// Refcounted snapshot of the online-CPU mask.
    #[inline(always)]
    pub fn scx_bpf_get_online_cpumask(&self) -> Option<Cpumask> {
        let p =
            termination_check!(unsafe { ffi::scx_bpf_get_online_cpumask() });
        if p.is_null() {
            None
        } else {
            Some(unsafe { Cpumask::from_raw(p) })
        }
    }

    /// Drop the reference held by a cpumask returned from
    /// `scx_bpf_get_possible_cpumask` / `scx_bpf_get_online_cpumask`.
    #[inline(always)]
    pub fn scx_bpf_put_cpumask(&self, mask: Cpumask) {
        termination_check!(unsafe { ffi::scx_bpf_put_cpumask(mask.as_ptr()) })
    }

    // ---------------------------------------------------------------
    //  Task / runqueue queries
    // ---------------------------------------------------------------

    /// Whether `p` is currently running on some CPU.
    #[inline(always)]
    pub fn scx_bpf_task_running(&self, p: &TaskStruct) -> bool {
        termination_check!(unsafe {
            ffi::scx_bpf_task_running(p.as_ptr() as *const _)
        })
    }

    /// Get a typed handle to `cpu`'s runqueue, or `None` if unavailable.
    #[inline(always)]
    pub fn scx_bpf_cpu_rq(&self, cpu: i32) -> Option<Rq> {
        let p = termination_check!(unsafe { ffi::scx_bpf_cpu_rq(cpu) });
        if p.is_null() {
            None
        } else {
            Some(unsafe { Rq::from_raw(p) })
        }
    }

    /// Get the runqueue currently locked by the caller (callbacks only).
    #[inline(always)]
    pub fn scx_bpf_locked_rq(&self) -> Option<Rq> {
        let p = termination_check!(unsafe { ffi::scx_bpf_locked_rq() });
        if p.is_null() {
            None
        } else {
            Some(unsafe { Rq::from_raw(p) })
        }
    }

    /// Currently-running task on `cpu`, or `None` if idle.
    #[inline(always)]
    pub fn scx_bpf_cpu_curr(&self, cpu: i32) -> Option<TaskStruct> {
        let p = termination_check!(unsafe { ffi::scx_bpf_cpu_curr(cpu) });
        if p.is_null() {
            None
        } else {
            Some(unsafe { TaskStruct::from_raw(p) })
        }
    }

    // ---------------------------------------------------------------
    //  cgroup
    // ---------------------------------------------------------------

    /// Owning cgroup of `p` (only available when the kernel was built
    /// with `CONFIG_CGROUP_SCHED`).
    #[cfg(CONFIG_CGROUP_SCHED = "y")]
    #[inline(always)]
    pub fn scx_bpf_task_cgroup(&self, p: &TaskStruct) -> Option<Cgroup> {
        let cg =
            termination_check!(unsafe { ffi::scx_bpf_task_cgroup(p.as_ptr()) });
        if cg.is_null() {
            None
        } else {
            Some(unsafe { Cgroup::from_raw(cg) })
        }
    }

    // ---------------------------------------------------------------
    //  Misc
    // ---------------------------------------------------------------

    /// Monotonic time used by sched_ext for time-slice and vtime accounting.
    #[inline(always)]
    pub fn scx_bpf_now(&self) -> u64 {
        termination_check!(unsafe { ffi::scx_bpf_now() })
    }

    /// Snapshot the scheduler's event counters into `events`.
    /// The buffer must be at least `core::mem::size_of::<scx_event_stats>()`
    /// bytes, but since `scx_event_stats` is opaque to Rex this method is
    /// `unsafe` and takes the byte size from the caller.
    ///
    /// # Safety
    /// `events` must point to a buffer of `events_sz` bytes that the caller
    /// holds a unique reference to for the duration of the call.
    #[inline(always)]
    pub unsafe fn scx_bpf_events(
        &self,
        events: &mut ScxEventStats,
        events_sz: usize,
    ) {
        termination_check!(unsafe {
            ffi::scx_bpf_events(events.as_mut_ptr(), events_sz)
        })
    }

    // ---------------------------------------------------------------
    //  Idle / NUMA helpers
    // ---------------------------------------------------------------

    /// NUMA node of `cpu`.
    #[inline(always)]
    pub fn scx_bpf_cpu_node(&self, cpu: i32) -> i32 {
        termination_check!(unsafe { ffi::scx_bpf_cpu_node(cpu) })
    }

    /// Pick a CPU for `p` constrained to `cpus_allowed`. Returns the chosen
    /// CPU on success, a negative errno on failure.
    #[inline(always)]
    pub fn scx_bpf_select_cpu_and(
        &self,
        p: &TaskStruct,
        prev_cpu: i32,
        wake_flags: u64,
        cpus_allowed: &Cpumask,
        flags: u64,
    ) -> i32 {
        termination_check!(unsafe {
            ffi::scx_bpf_select_cpu_and(
                p.as_ptr(),
                prev_cpu,
                wake_flags,
                cpus_allowed.as_ptr(),
                flags,
            )
        })
    }

    /// Refcounted idle-CPU mask scoped to `node`. Release with
    /// `scx_bpf_put_idle_cpumask`.
    #[inline(always)]
    pub fn scx_bpf_get_idle_cpumask_node(
        &self,
        node: i32,
    ) -> Option<Cpumask> {
        let p = termination_check!(unsafe {
            ffi::scx_bpf_get_idle_cpumask_node(node)
        });
        if p.is_null() {
            None
        } else {
            Some(unsafe { Cpumask::from_raw(p) })
        }
    }

    /// Refcounted system-wide idle-CPU mask.
    #[inline(always)]
    pub fn scx_bpf_get_idle_cpumask(&self) -> Option<Cpumask> {
        let p = termination_check!(unsafe { ffi::scx_bpf_get_idle_cpumask() });
        if p.is_null() {
            None
        } else {
            Some(unsafe { Cpumask::from_raw(p) })
        }
    }

    /// Refcounted idle-SMT-core mask scoped to `node`.
    #[inline(always)]
    pub fn scx_bpf_get_idle_smtmask_node(
        &self,
        node: i32,
    ) -> Option<Cpumask> {
        let p = termination_check!(unsafe {
            ffi::scx_bpf_get_idle_smtmask_node(node)
        });
        if p.is_null() {
            None
        } else {
            Some(unsafe { Cpumask::from_raw(p) })
        }
    }

    /// Refcounted system-wide idle-SMT-core mask.
    #[inline(always)]
    pub fn scx_bpf_get_idle_smtmask(&self) -> Option<Cpumask> {
        let p = termination_check!(unsafe { ffi::scx_bpf_get_idle_smtmask() });
        if p.is_null() {
            None
        } else {
            Some(unsafe { Cpumask::from_raw(p) })
        }
    }

    /// Drop a reference returned by any `scx_bpf_get_idle_*` getter.
    #[inline(always)]
    pub fn scx_bpf_put_idle_cpumask(&self, mask: Cpumask) {
        termination_check!(unsafe {
            ffi::scx_bpf_put_idle_cpumask(mask.as_ptr())
        })
    }

    /// Atomically check-and-clear the idle bit of `cpu`. Returns `true` if
    /// `cpu` was idle (and is now reserved for the caller).
    #[inline(always)]
    pub fn scx_bpf_test_and_clear_cpu_idle(&self, cpu: i32) -> bool {
        termination_check!(unsafe {
            ffi::scx_bpf_test_and_clear_cpu_idle(cpu)
        })
    }

    /// Pick an idle CPU from `cpus_allowed` on NUMA node `node`.
    /// Returns the chosen CPU, or a negative errno.
    #[inline(always)]
    pub fn scx_bpf_pick_idle_cpu_node(
        &self,
        cpus_allowed: &Cpumask,
        node: i32,
        flags: u64,
    ) -> i32 {
        termination_check!(unsafe {
            ffi::scx_bpf_pick_idle_cpu_node(cpus_allowed.as_ptr(), node, flags)
        })
    }

    /// Pick any idle CPU from `cpus_allowed`.
    #[inline(always)]
    pub fn scx_bpf_pick_idle_cpu(
        &self,
        cpus_allowed: &Cpumask,
        flags: u64,
    ) -> i32 {
        termination_check!(unsafe {
            ffi::scx_bpf_pick_idle_cpu(cpus_allowed.as_ptr(), flags)
        })
    }

    /// Pick any CPU (idle preferred, busy as fallback) from `cpus_allowed`
    /// on `node`.
    #[inline(always)]
    pub fn scx_bpf_pick_any_cpu_node(
        &self,
        cpus_allowed: &Cpumask,
        node: i32,
        flags: u64,
    ) -> i32 {
        termination_check!(unsafe {
            ffi::scx_bpf_pick_any_cpu_node(cpus_allowed.as_ptr(), node, flags)
        })
    }

    /// Pick any CPU (idle preferred, busy as fallback) from `cpus_allowed`.
    #[inline(always)]
    pub fn scx_bpf_pick_any_cpu(
        &self,
        cpus_allowed: &Cpumask,
        flags: u64,
    ) -> i32 {
        termination_check!(unsafe {
            ffi::scx_bpf_pick_any_cpu(cpus_allowed.as_ptr(), flags)
        })
    }
}
