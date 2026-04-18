use core::marker::PhantomData;

use crate::base_helper::termination_check;
use crate::bindings::linux::kernel::task_struct;
use crate::bindings::uapi::linux::bpf::bpf_map_type;
use crate::ffi;
use crate::task_struct::TaskStruct;
use crate::utils::{to_result, NoRef, Result};

/// Record the current jiffies as this CPU's Rex op-entry timestamp.
///
/// Called from the generated `extern "C"` entry wrapper for every Rex
/// sched_ext op, before the user callback body runs. The value is later
/// consulted by `termination_check!` on every helper/kfunc call to decide
/// whether the op has exceeded `rex_op_timeout_jiffies`.
///
/// This function must not call any Rex helper (no `termination_check!`)
/// because it runs at op entry where the cooperative watchdog state has
/// not yet been set up.
#[inline(always)]
pub unsafe fn __rex_op_enter() {
    unsafe {
        let entry_ptr: *mut u64 = crate::per_cpu::this_cpu_ptr_mut(
            &raw mut crate::ffi::rex_op_entry_jiffies,
        );
        let now = core::ptr::read_volatile(&raw const crate::ffi::jiffies);
        core::ptr::write_volatile(entry_ptr, now);
    }
}

/// Clear this CPU's Rex op-entry timestamp on normal return from the op.
///
/// The panic path intentionally skips this: `rex_landingpad_asm` abandons
/// the Rust stack frames above it so no `Drop` destructors run. The Rex
/// panic handler in `rex::panic` clears the timestamp instead.
#[inline(always)]
pub unsafe fn __rex_op_exit() {
    unsafe {
        let entry_ptr: *mut u64 = crate::per_cpu::this_cpu_ptr_mut(
            &raw mut crate::ffi::rex_op_entry_jiffies,
        );
        core::ptr::write_volatile(entry_ptr, 0);
    }
}

/// RAII guard used by the `#[rex_sched_ext]` macro to bracket every
/// generated `extern "C"` op entry with `__rex_op_enter` / `__rex_op_exit`.
///
/// On normal return the guard's `Drop` clears the per-CPU op-entry
/// timestamp. On the Rex panic path, `rex_landingpad_asm` longjmps back
/// to `rex_dispatcher_func` and the guard's `Drop` is skipped; the Rex
/// panic handler clears the timestamp in that case.
pub struct RexOpGuard;

impl RexOpGuard {
    #[inline(always)]
    pub unsafe fn enter() -> Self {
        unsafe { __rex_op_enter(); }
        RexOpGuard
    }
}

impl Drop for RexOpGuard {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe { __rex_op_exit(); }
    }
}

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
}
