//! Safe wrappers around opaque kernel structs forwarded by sched_ext
//! callbacks. Modeled on `TaskStruct` in `rex/src/task_struct.rs`: each
//! wrapper holds a typed reference and a raw pointer for kernel helpers.
//! No field accessors are exposed yet — they are added per-callsite when
//! a sample needs them.

use crate::bindings::linux::kernel::task_struct;
use crate::ffi;
#[cfg(CONFIG_CGROUP_SCHED = "y")]
use crate::sched_ext::binding::cgroup;
use crate::sched_ext::binding::{
    bpf_iter_scx_dsq, cpumask, rq, scx_cpu_acquire_args, scx_cpu_release_args,
    scx_dump_ctx, scx_event_stats,
};
use crate::task_struct::TaskStruct;

#[cfg(CONFIG_CGROUP_SCHED = "y")]
pub struct Cgroup {
    #[allow(dead_code)]
    inner: &'static cgroup,
    kptr: *mut cgroup,
}

#[cfg(CONFIG_CGROUP_SCHED = "y")]
impl Cgroup {
    /// # Safety
    /// `ptr` must be a valid `cgroup *` that outlives the returned wrapper
    /// (true for sched_ext callback arguments — RCU-protected for the
    /// callback's duration).
    #[inline(always)]
    pub(crate) unsafe fn from_raw(ptr: *mut cgroup) -> Self {
        Cgroup {
            inner: unsafe { &*ptr },
            kptr: ptr,
        }
    }

    #[inline(always)]
    pub fn as_ptr(&self) -> *mut cgroup {
        self.kptr
    }
}

pub struct Cpumask {
    #[allow(dead_code)]
    inner: &'static cpumask,
    kptr: *const cpumask,
}

impl Cpumask {
    /// # Safety
    /// `ptr` must be a valid `const cpumask *` that outlives the wrapper.
    #[inline(always)]
    pub(crate) unsafe fn from_raw(ptr: *const cpumask) -> Self {
        Cpumask {
            inner: unsafe { &*ptr },
            kptr: ptr,
        }
    }

    #[inline(always)]
    pub fn as_ptr(&self) -> *const cpumask {
        self.kptr
    }
}

pub struct ScxDumpCtx {
    #[allow(dead_code)]
    inner: &'static scx_dump_ctx,
    kptr: *const scx_dump_ctx,
}

impl ScxDumpCtx {
    /// # Safety
    /// `ptr` must be a valid `const scx_dump_ctx *` that outlives the wrapper.
    #[inline(always)]
    pub(crate) unsafe fn from_raw(ptr: *const scx_dump_ctx) -> Self {
        ScxDumpCtx {
            inner: unsafe { &*ptr },
            kptr: ptr,
        }
    }

    #[inline(always)]
    pub fn as_ptr(&self) -> *const scx_dump_ctx {
        self.kptr
    }
}

pub struct ScxCpuAcquireArgs {
    #[allow(dead_code)]
    inner: &'static scx_cpu_acquire_args,
    kptr: *const scx_cpu_acquire_args,
}

impl ScxCpuAcquireArgs {
    /// # Safety
    /// `ptr` must be a valid `const scx_cpu_acquire_args *` that outlives
    /// the wrapper.
    #[inline(always)]
    pub(crate) unsafe fn from_raw(ptr: *const scx_cpu_acquire_args) -> Self {
        ScxCpuAcquireArgs {
            inner: unsafe { &*ptr },
            kptr: ptr,
        }
    }

    #[inline(always)]
    pub fn as_ptr(&self) -> *const scx_cpu_acquire_args {
        self.kptr
    }
}

pub struct ScxCpuReleaseArgs {
    #[allow(dead_code)]
    inner: &'static scx_cpu_release_args,
    kptr: *const scx_cpu_release_args,
}

impl ScxCpuReleaseArgs {
    /// # Safety
    /// `ptr` must be a valid `const scx_cpu_release_args *` that outlives
    /// the wrapper.
    #[inline(always)]
    pub(crate) unsafe fn from_raw(ptr: *const scx_cpu_release_args) -> Self {
        ScxCpuReleaseArgs {
            inner: unsafe { &*ptr },
            kptr: ptr,
        }
    }

    #[inline(always)]
    pub fn as_ptr(&self) -> *const scx_cpu_release_args {
        self.kptr
    }
}

pub struct Rq {
    #[allow(dead_code)]
    inner: &'static rq,
    kptr: *mut rq,
}

impl Rq {
    /// # Safety
    /// `ptr` must be a valid `rq *` that outlives the wrapper.
    #[inline(always)]
    pub(crate) unsafe fn from_raw(ptr: *mut rq) -> Self {
        Rq {
            inner: unsafe { &*ptr },
            kptr: ptr,
        }
    }

    #[inline(always)]
    pub fn as_ptr(&self) -> *mut rq {
        self.kptr
    }
}

pub struct ScxEventStats {
    #[allow(dead_code)]
    inner: &'static scx_event_stats,
    kptr: *mut scx_event_stats,
}

impl ScxEventStats {
    /// # Safety
    /// `ptr` must be a valid `scx_event_stats *` that outlives the wrapper
    /// and points to a buffer at least `size_of::<scx_event_stats>()` bytes.
    #[inline(always)]
    pub(crate) unsafe fn from_raw(ptr: *mut scx_event_stats) -> Self {
        ScxEventStats {
            inner: unsafe { &*ptr },
            kptr: ptr,
        }
    }

    #[inline(always)]
    pub fn as_mut_ptr(&mut self) -> *mut scx_event_stats {
        self.kptr
    }
}

/// RAII handle around the BPF DSQ iterator.
/// Construct with [`BpfIterScxDsq::new`]; iterate via the [`Iterator`] impl
/// (which calls `bpf_iter_scx_dsq_next`); destruction is automatic on Drop.
pub struct BpfIterScxDsq {
    it: bpf_iter_scx_dsq,
    /// Set once `bpf_iter_scx_dsq_new` has succeeded so Drop knows it must
    /// call `bpf_iter_scx_dsq_destroy`. Avoids destroying an uninitialized
    /// iterator if construction failed mid-way.
    initialized: bool,
}

impl BpfIterScxDsq {
    /// Build a fresh iterator over `dsq_id`. Returns `Err(rc)` (a negative
    /// errno from the kernel) on failure; the iterator is not usable.
    #[inline(always)]
    pub fn new(dsq_id: u64, flags: u64) -> core::result::Result<Self, i32> {
        let mut this = BpfIterScxDsq {
            it: bpf_iter_scx_dsq { __opaque: [0u64; 6] },
            initialized: false,
        };
        let rc = unsafe {
            ffi::bpf_iter_scx_dsq_new(&mut this.it as *mut _, dsq_id, flags)
        };
        if rc == 0 {
            this.initialized = true;
            Ok(this)
        } else {
            Err(rc)
        }
    }

    #[inline(always)]
    pub fn as_mut_ptr(&mut self) -> *mut bpf_iter_scx_dsq {
        &mut self.it as *mut _
    }
}

impl Iterator for BpfIterScxDsq {
    type Item = TaskStruct;

    #[inline(always)]
    fn next(&mut self) -> Option<TaskStruct> {
        if !self.initialized {
            return None;
        }
        let p: *mut task_struct =
            unsafe { ffi::bpf_iter_scx_dsq_next(&mut self.it as *mut _) };
        if p.is_null() {
            None
        } else {
            Some(unsafe { TaskStruct::from_raw(p) })
        }
    }
}

impl Drop for BpfIterScxDsq {
    #[inline(always)]
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                ffi::bpf_iter_scx_dsq_destroy(&mut self.it as *mut _);
            }
        }
    }
}
