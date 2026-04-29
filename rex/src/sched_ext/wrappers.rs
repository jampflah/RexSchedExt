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

/// Backing-buffer size for [`ScxEventStats`], in bytes.
///
/// The kernel-side `struct scx_event_stats` is composed entirely of `s64`
/// counters (see `linux/kernel/sched/ext_internal.h`). We allocate a fixed
/// 256-byte buffer (32 × `i64`) which is roughly 3.5× the current kernel
/// layout's size — enough headroom that adding new counters upstream
/// won't silently truncate our snapshot. `scx_bpf_events` always writes
/// at most `events_sz` bytes, so over-allocation is safe.
pub const SCX_EVENT_STATS_BUF_BYTES: usize = 256;

const _: () = assert!(
    SCX_EVENT_STATS_BUF_BYTES % core::mem::size_of::<i64>() == 0,
    "ScxEventStats buffer must be a whole number of i64 counters",
);

const SCX_EVENT_STATS_BUF_LEN_I64: usize =
    SCX_EVENT_STATS_BUF_BYTES / core::mem::size_of::<i64>();

/// Caller-owned buffer for `scx_bpf_events`. Construct with
/// [`ScxEventStats::zeroed`], hand to the kfunc, then read counters via
/// [`ScxEventStats::as_i64_slice`].
///
/// `scx_event_stats` is intentionally opaque to Rex (the kernel struct is
/// not in our bindgen surface), so the wrapper holds a fixed-size aligned
/// `i64` array rather than a typed reference. Zero-initialising on
/// construction lets `as_i64_slice` be a safe call regardless of whether
/// the kfunc has run yet, at the cost of one 256-byte stack memset.
#[repr(C, align(8))]
pub struct ScxEventStats {
    /// Aligned-to-`i64` array; the kernel writes its `scx_event_stats`
    /// representation into the leading bytes via `scx_bpf_events`.
    /// Initialised to all-zeros so reads before the kfunc runs (or for
    /// counters the kernel doesn't populate) are defined.
    buf: [i64; SCX_EVENT_STATS_BUF_LEN_I64],
}

impl ScxEventStats {
    /// Allocate a zero-initialised counter buffer suitable for passing
    /// to `scx_bpf_events`.
    #[inline(always)]
    pub fn zeroed() -> Self {
        Self {
            buf: [0i64; SCX_EVENT_STATS_BUF_LEN_I64],
        }
    }

    /// Buffer size in bytes (the value passed to `scx_bpf_events` as
    /// `events_sz`). Always equals [`SCX_EVENT_STATS_BUF_BYTES`].
    #[inline(always)]
    pub const fn size_bytes() -> usize {
        SCX_EVENT_STATS_BUF_BYTES
    }

    /// Raw pointer for the `scx_bpf_events` kfunc.
    #[inline(always)]
    pub fn as_mut_ptr(&mut self) -> *mut scx_event_stats {
        self.buf.as_mut_ptr() as *mut scx_event_stats
    }

    /// View the buffer as a slice of `i64` counters. After
    /// `scx_bpf_events` has populated the buffer, the leading entries
    /// match the kernel's `struct scx_event_stats` field order; trailing
    /// entries the kernel didn't touch remain zero.
    #[inline(always)]
    pub fn as_i64_slice(&self) -> &[i64] {
        &self.buf
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
