use core::marker::PhantomData;

use crate::base_helper::termination_check;
use crate::bindings::linux::kernel::task_struct;
use crate::bindings::uapi::linux::bpf::bpf_map_type;
use crate::ffi;
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

    /// Consume a task from the specified DSQ and transfer it to the
    /// local CPU's DSQ. Returns true if a task was consumed.
    #[inline(always)]
    pub fn scx_bpf_consume(&self, dsq_id: u64) -> bool {
        termination_check!(unsafe { ffi::scx_bpf_consume(dsq_id) })
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
    #[inline(always)]
    pub fn scx_bpf_error_str(&self, msg: &str) {
        termination_check!(unsafe {
            ffi::scx_bpf_error(msg.as_ptr(), msg.len() as u32)
        })
    }
}
