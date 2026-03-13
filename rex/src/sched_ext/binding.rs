/// Built-in dispatch queues
pub const SCX_DSQ_GLOBAL: u64 = 1u64 << 63;
pub const SCX_DSQ_LOCAL: u64 = SCX_DSQ_GLOBAL | 1;
pub const SCX_DSQ_LOCAL_ON: u64 = SCX_DSQ_GLOBAL | 2;
pub const SCX_DSQ_INVALID: u64 = SCX_DSQ_GLOBAL | 3;

/// Default time slice (20ms in nanoseconds)
pub const SCX_SLICE_DFL: u64 = 20_000_000;
pub const SCX_SLICE_INF: u64 = u64::MAX;

/// Enqueue flags passed to ops.enqueue()
pub const SCX_ENQ_WAKEUP: u64 = 1 << 0;
pub const SCX_ENQ_HEAD: u64 = 1 << 4;
pub const SCX_ENQ_CPU_SELECTED: u64 = 1 << 23;
pub const SCX_ENQ_LAST: u64 = 1 << 41;

/// Dequeue flags passed to ops.dequeue()
pub const SCX_DEQ_SLEEP: u64 = 1 << 0;

/// Kick flags for scx_bpf_kick_cpu()
pub const SCX_KICK_IDLE: u64 = 1 << 0;
pub const SCX_KICK_PREEMPT: u64 = 1 << 1;
pub const SCX_KICK_WAIT: u64 = 1 << 2;

/// Exit kinds reported via scx_exit_info
pub const SCX_EXIT_NONE: u64 = 0;
pub const SCX_EXIT_DONE: u64 = 1;
pub const SCX_EXIT_UNREG: u64 = 64;
pub const SCX_EXIT_UNREG_BPF: u64 = 65;
pub const SCX_EXIT_UNREG_KERN: u64 = 66;
pub const SCX_EXIT_SYS_BUSY: u64 = 128;
pub const SCX_EXIT_ERROR: u64 = 1024;
pub const SCX_EXIT_ERROR_BPF: u64 = 1025;
pub const SCX_EXIT_ERROR_STALL: u64 = 1026;

/// Ops flags for sched_ext_ops.flags
pub const SCX_OPS_KEEP_BUILTIN_IDLE: u64 = 1 << 0;
pub const SCX_OPS_ENQ_LAST: u64 = 1 << 1;
pub const SCX_OPS_ENQ_EXITING: u64 = 1 << 2;
pub const SCX_OPS_SWITCH_PARTIAL: u64 = 1 << 3;
pub const SCX_OPS_HAS_CGROUP_WEIGHT: u64 = 1 << 16;

/// Exit info passed to ops.exit()
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ScxExitInfo {
    pub kind: u64,
    pub exit_code: i64,
    pub reason: u64,
    pub msg: u64,
    pub dump: u64,
}

/// Arguments passed to ops.init_task()
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ScxInitTaskArgs {
    pub fork: bool,
}

/// Arguments passed to ops.exit_task()
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ScxExitTaskArgs {
    pub cancelled: bool,
}

/// Metadata for the scheduler ops definition.
/// Placed in `.struct_ops` ELF section by the #[rex_sched_ext_ops] macro.
#[repr(C)]
pub struct SchedExtOps {
    pub flags: u64,
    pub timeout_ms: u32,
    pub exit_dump_len: u32,
    pub name: [u8; 128],
}

impl SchedExtOps {
    pub const DEFAULT: Self = Self {
        flags: 0,
        timeout_ms: 0,
        exit_dump_len: 0,
        name: [0u8; 128],
    };

    pub const fn with_name(name_str: &[u8]) -> Self {
        let mut ops = Self::DEFAULT;
        let mut i = 0;
        while i < name_str.len() && i < 127 {
            ops.name[i] = name_str[i];
            i += 1;
        }
        ops
    }
}
