// All kernel symbols we need should be declared here

#![allow(dead_code)]

use core::ffi::{c_uchar, VaList};

use crate::bindings::linux::kernel::{
    bpf_perf_event_data_kern, sk_buff, task_struct, xdp_buff, MAX_BPRINTF_BUF,
};
use crate::bindings::uapi::linux::bpf::{bpf_perf_event_value, bpf_spin_lock};
use crate::panic::{CleanupEntry, ENTRIES_SIZE};
#[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
use crate::sched_ext::{
    bpf_iter_scx_dsq, cpumask, rq, scx_event_stats, ScxBpfDsqInsertVtimeArgs,
    ScxBpfSelectCpuAndArgs,
};
#[cfg(all(CONFIG_SCHED_CLASS_EXT = "y", CONFIG_CGROUP_SCHED = "y"))]
use crate::sched_ext::cgroup;

// Functions
unsafe extern "C" {
    /// `void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)`
    ///
    /// `struct bpf_map` is opaque in our case so make it a `*mut ()`
    pub(crate) fn bpf_map_lookup_elem(map: *mut (), key: *const ()) -> *mut ();

    /// `long bpf_map_update_elem(struct bpf_map *map, const void *key, const
    /// void *value, u64 flags)`
    ///
    /// `struct bpf_map` is opaque in our case so make it a `*mut ()`
    pub(crate) fn bpf_map_update_elem(
        map: *mut (),
        key: *const (),
        value: *const (),
        flags: u64,
    ) -> i64;

    /// `long bpf_map_delete_elem(struct bpf_map *map, const void *key)`
    ///
    /// `struct bpf_map` is opaque in our case so make it a `*mut ()`
    pub(crate) fn bpf_map_delete_elem(map: *mut (), key: *const ()) -> i64;

    /// `long bpf_map_push_elem(struct bpf_map *map, const void *value, u64
    /// flags)`
    ///
    /// `struct bpf_map` is opaque in our case so make it a `*mut ()`
    pub(crate) fn bpf_map_push_elem(
        map: *mut (),
        value: *const (),
        flags: u64,
    ) -> i64;

    /// `long bpf_map_pop_elem(struct bpf_map *map, void *value)`
    ///
    /// `struct bpf_map` is opaque in our case so make it a `*mut ()`
    pub(crate) fn bpf_map_pop_elem(map: *mut (), value: *const ()) -> i64;

    /// `long bpf_map_peek_elem(struct bpf_map *map, void *value)`
    ///
    /// `struct bpf_map` is opaque in our case so make it a `*mut ()`
    pub(crate) fn bpf_map_peek_elem(map: *mut (), value: *const ()) -> i64;

    /// `long bpf_probe_read_kernel(void *dst, u32 size, const void
    /// *unsafe_ptr)`
    pub(crate) fn bpf_probe_read_kernel(
        dst: *mut (),
        size: u32,
        unsafe_ptr: *const (),
    ) -> i64;

    /// `u64 notrace ktime_get_mono_fast_ns(void)`
    pub(crate) fn ktime_get_mono_fast_ns() -> u64;

    /// `u64 notrace ktime_get_boot_fast_ns(void)`
    pub(crate) fn ktime_get_boot_fast_ns() -> u64;

    /// `u64 bpf_ktime_get_ns(void)`
    pub(crate) fn bpf_ktime_get_ns() -> u64;

    /// `u64 bpf_ktime_get_boot_ns(void)`
    pub(crate) fn bpf_ktime_get_boot_ns() -> u64;

    /// `u64 bpf_ktime_get_coarse_ns(void)`
    pub(crate) fn bpf_ktime_get_coarse_ns() -> u64;

    /// `u32 get_random_u32(void)`
    pub(crate) fn get_random_u32() -> u32;

    /// `long bpf_snprintf_btf(char *str, u32 str_size, struct btf_ptr *ptr, u32
    /// btf_ptr_size, u64 flags)`
    pub(crate) fn bpf_snprintf(
        str: *mut u8,
        str_size: u32,
        fmt: *const u8,
        data: *const u64,
        data_len: u32,
    ) -> i64;

    /// `asmlinkage int vprintk(const char *fmt, va_list args)`
    pub(crate) fn vprintk(fmt: *const c_uchar, args: VaList) -> i32;

    /// `__nocfi noinline void notrace __noreturn rex_landingpad(char *msg)`
    ///
    /// The in-kernel panic landingpad for panic recovery
    pub(crate) fn rex_landingpad() -> !;

    /// `long bpf_spin_lock(struct bpf_spin_lock *lock)`
    pub(crate) fn bpf_spin_lock(lock: *mut bpf_spin_lock) -> i64;

    /// `long bpf_spin_unlock(struct bpf_spin_lock *lock)`
    pub(crate) fn bpf_spin_unlock(lock: *mut bpf_spin_lock) -> i64;

    /// `asmlinkage void just_return_func(void)`
    pub(crate) fn just_return_func();

    /// `long bpf_get_stackid_pe(struct bpf_perf_event_data_kern *ctx, struct
    /// bpf_map *map, u64 flags)`
    ///
    /// The specialized version of `bpf_get_stackid` for perf event programs
    ///
    /// Also allow improper_ctypes here since the empty lock_class_key is
    /// guaranteed not touched by us
    #[allow(improper_ctypes)]
    pub(crate) fn bpf_get_stackid_pe(
        ctx: *const bpf_perf_event_data_kern,
        map: *mut (),
        flags: u64,
    ) -> i64;

    /// `long bpf_perf_prog_read_value(struct bpf_perf_event_data *ctx, struct
    /// bpf_perf_event_value *buf, u32 buf_size)`
    ///
    /// Also allow improper_ctypes here since the empty lock_class_key is
    /// guaranteed not touched by us
    #[allow(improper_ctypes)]
    pub(crate) fn bpf_perf_prog_read_value(
        ctx: *const bpf_perf_event_data_kern,
        buf: &mut bpf_perf_event_value,
        size: u32,
    ) -> i64;

    /// `long bpf_perf_event_output_tp(void *tp_buff, struct bpf_map *map, u64
    /// flags, void *data, u64 size)`
    pub(crate) fn bpf_perf_event_output_tp(
        tp_buff: *const (),
        map: *mut (),
        flags: u64,
        data: *const (),
        size: u64,
    ) -> i64;

    /// `long bpf_perf_event_read_value(struct bpf_map *map, u64 flags,
    /// struct bpf_perf_event_value *buf, u32 buf_size)`
    /// same reason for use of improper_ctypes as bpf_perf_prog_read_value
    #[allow(improper_ctypes)]
    pub(crate) fn bpf_perf_event_read_value(
        map: *mut (),
        flags: u64,
        buf: &mut bpf_perf_event_value,
        buf_size: u32,
    ) -> i64;

    /// `long bpf_skb_event_output(struct sk_buff *skb, struct bpf_map *map, u64
    /// flags, void *meta, u64 meta_size)`
    /// The compiler complains about some non-FFI safe type, but since the
    /// kernel is using it fine it should be safe for an FFI call using C ABI
    #[allow(improper_ctypes)]
    pub(crate) fn bpf_skb_event_output(
        skb: *const sk_buff,
        map: *mut (),
        flags: u64,
        meta: *const (),
        meta_size: u64,
    ) -> i64;

    /// `long bpf_xdp_event_output(struct xdp_buff *xdp, struct bpf_map *map,
    /// u64 flags, void *meta, u64 meta_size)`
    /// The compiler complains about some non-FFI safe type, but since the
    /// kernel is using it fine it should be safe for an FFI call using C ABI
    #[allow(improper_ctypes)]
    pub(crate) fn bpf_xdp_event_output(
        xdp: *const xdp_buff,
        map: *mut (),
        flags: u64,
        meta: *const (),
        meta_size: u64,
    ) -> i64;

    /// `long bpf_xdp_adjust_head(struct xdp_buff *xdp, int offset)`
    ///
    /// The compiler complains about some non-FFI safe type, but since the
    /// kernel is using it fine it should be safe for an FFI call using C ABI
    #[allow(improper_ctypes)]
    pub(crate) fn bpf_xdp_adjust_head(xdp: *mut xdp_buff, offset: i32) -> i32;

    /// long bpf_xdp_adjust_tail(struct xdp_buff *xdp, int offset)
    ///
    /// The compiler complains about some non-FFI safe type, but since the
    /// kernel is using it fine it should be safe for an FFI call using C ABI
    #[allow(improper_ctypes)]
    pub(crate) fn bpf_xdp_adjust_tail(xdp: *mut xdp_buff, offset: i32) -> i32;

    /// long bpf_clone_redirect(struct sk_buff *skb, u32 ifindex, u64 flags)
    ///
    /// The compiler complains about some non-FFI safe type, but since the
    /// kernel is using it fine it should be safe for an FFI call using C ABI
    #[allow(improper_ctypes)]
    pub(crate) fn bpf_clone_redirect(
        skb: *mut sk_buff,
        ifindex: u32,
        flags: u64,
    ) -> i32;

    /// void *bpf_ringbuf_reserve(void *ringbuf, u64 size, u64 flags)
    pub(crate) fn bpf_ringbuf_reserve(
        ringbuf: *mut (),
        size: u64,
        flags: u64,
    ) -> *mut ();

    /// long bpf_ringbuf_output(void *ringbuf, void *data, u64 size, u64 flags)
    // data is marked `ARG_PTR_TO_MEM | MEM_RDONLY`, which implies the argument
    // is comptiable with readonly memory and does not modifiy the memory
    // pointed by the pointer, therefore, we use a *const () type.
    pub(crate) fn bpf_ringbuf_output(
        ringbuf: *mut (),
        data: *const (),
        size: u64,
        flags: u64,
    ) -> i64;

    /// void bpf_ringbuf_submit(void *data, u64 flags)
    pub(crate) fn bpf_ringbuf_submit(data: *mut (), flags: u64);

    /// void bpf_ringbuf_discard(void *data, u64 flags)
    pub(crate) fn bpf_ringbuf_discard(data: *mut (), flags: u64);

    /// u64 bpf_ringbuf_query(void *ringbuf, u64 flags)
    pub(crate) fn bpf_ringbuf_query(ringbuf: *mut (), flags: u64) -> u64;

    /// void rex_trace_printk(void)
    pub(crate) fn rex_trace_printk();

    /// __bpf_kfunc struct task_struct *bpf_task_from_pid(s32 pid)
    pub(crate) fn bpf_task_from_pid(pid: i32) -> *mut task_struct;

    /// __bpf_kfunc void bpf_task_release(struct task_struct *p)
    pub(crate) fn bpf_task_release(task: *mut task_struct);

    // ---------------------------------------------------------------
    //  sched_ext kfuncs (kernel/sched/ext.c)
    //  Resolved at load time via dynamic symbol resolution.
    // ---------------------------------------------------------------

    /// void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq_id,
    ///                          u64 slice, u64 enq_flags)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_dsq_insert(
        p: *mut task_struct,
        dsq_id: u64,
        slice: u64,
        enq_flags: u64,
    );

    /// s32 scx_bpf_select_cpu_dfl(struct task_struct *p, s32 prev_cpu,
    ///                             u64 wake_flags, bool *is_idle)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_select_cpu_dfl(
        p: *mut task_struct,
        prev_cpu: i32,
        wake_flags: u64,
        is_idle: *mut bool,
    ) -> i32;

    /// bool scx_bpf_dsq_move_to_local(u64 dsq_id)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_dsq_move_to_local(dsq_id: u64) -> bool;

    /// void scx_bpf_kick_cpu(s32 cpu, u64 flags)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_kick_cpu(cpu: i32, flags: u64);

    /// s32 scx_bpf_create_dsq(u64 dsq_id, s32 node)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_create_dsq(dsq_id: u64, node: i32) -> i64;

    /// void scx_bpf_destroy_dsq(u64 dsq_id)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_destroy_dsq(dsq_id: u64);

    /// s32 scx_bpf_task_cpu(struct task_struct *p)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_task_cpu(p: *mut task_struct) -> i32;

    /// void scx_bpf_error_bstr(char *fmt, unsigned long long *data, u32 data__sz)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_error_bstr(fmt: *const u8, data: *const u64, data_sz: u32);

    /// void scx_bpf_dsq_insert_vtime(struct task_struct *p, u64 dsq_id,
    ///                               u64 slice, u64 vtime, u64 enq_flags)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_dsq_insert_vtime(
        p: *mut task_struct,
        dsq_id: u64,
        slice: u64,
        vtime: u64,
        enq_flags: u64,
    );

    /// u32 scx_bpf_dispatch_nr_slots(void)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_dispatch_nr_slots() -> u32;

    /// void scx_bpf_dispatch_cancel(void)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_dispatch_cancel();

    /// s32 scx_bpf_dsq_nr_queued(u64 dsq_id)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_dsq_nr_queued(dsq_id: u64) -> i32;

    /// bool scx_bpf_task_set_slice(struct task_struct *p, u64 slice)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_task_set_slice(p: *mut task_struct, slice: u64) -> bool;

    /// bool scx_bpf_task_set_dsq_vtime(struct task_struct *p, u64 vtime)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_task_set_dsq_vtime(p: *mut task_struct, vtime: u64) -> bool;

    /// u32 scx_bpf_reenqueue_local(void)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_reenqueue_local() -> u32;

    /// u32 scx_bpf_nr_cpu_ids(void)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_nr_cpu_ids() -> u32;

    // ----- BPF DSQ iterator (ext.c:6780/6822/6868) -----

    /// int bpf_iter_scx_dsq_new(struct bpf_iter_scx_dsq *it, u64 dsq_id, u64 flags)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn bpf_iter_scx_dsq_new(
        it: *mut bpf_iter_scx_dsq,
        dsq_id: u64,
        flags: u64,
    ) -> i32;

    /// struct task_struct *bpf_iter_scx_dsq_next(struct bpf_iter_scx_dsq *it)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn bpf_iter_scx_dsq_next(
        it: *mut bpf_iter_scx_dsq,
    ) -> *mut task_struct;

    /// void bpf_iter_scx_dsq_destroy(struct bpf_iter_scx_dsq *it)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn bpf_iter_scx_dsq_destroy(it: *mut bpf_iter_scx_dsq);

    // ----- Underscored arg-wrapped variants (ext.c:6115, ext_idle.c:1030) -----

    /// bool __scx_bpf_dsq_insert_vtime(struct task_struct *p,
    ///                                 struct scx_bpf_dsq_insert_vtime_args *args)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn __scx_bpf_dsq_insert_vtime(
        p: *mut task_struct,
        args: *mut ScxBpfDsqInsertVtimeArgs,
    ) -> bool;

    /// s32 __scx_bpf_select_cpu_and(struct task_struct *p,
    ///                              const struct cpumask *cpus_allowed,
    ///                              struct scx_bpf_select_cpu_and_args *args)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn __scx_bpf_select_cpu_and(
        p: *mut task_struct,
        cpus_allowed: *const cpumask,
        args: *mut ScxBpfSelectCpuAndArgs,
    ) -> i32;

    // ----- v2 entry points -----

    /// bool scx_bpf_dsq_insert___v2(struct task_struct *p, u64 dsq_id,
    ///                              u64 slice, u64 enq_flags) (ext.c:6026)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_dsq_insert___v2(
        p: *mut task_struct,
        dsq_id: u64,
        slice: u64,
        enq_flags: u64,
    ) -> bool;

    /// void scx_bpf_reenqueue_local___v2(void) (ext.c:7079)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_reenqueue_local___v2();

    // ----- DSQ move helpers (ext.c:6357/6376/6410/6435) -----

    /// void scx_bpf_dsq_move_set_slice(struct bpf_iter_scx_dsq *it__iter, u64 slice)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_dsq_move_set_slice(
        it: *mut bpf_iter_scx_dsq,
        slice: u64,
    );

    /// void scx_bpf_dsq_move_set_vtime(struct bpf_iter_scx_dsq *it__iter, u64 vtime)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_dsq_move_set_vtime(
        it: *mut bpf_iter_scx_dsq,
        vtime: u64,
    );

    /// bool scx_bpf_dsq_move(struct bpf_iter_scx_dsq *it__iter,
    ///                       struct task_struct *p, u64 dsq_id, u64 enq_flags)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_dsq_move(
        it: *mut bpf_iter_scx_dsq,
        p: *mut task_struct,
        dsq_id: u64,
        enq_flags: u64,
    ) -> bool;

    /// bool scx_bpf_dsq_move_vtime(struct bpf_iter_scx_dsq *it__iter,
    ///                             struct task_struct *p, u64 dsq_id, u64 enq_flags)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_dsq_move_vtime(
        it: *mut bpf_iter_scx_dsq,
        p: *mut task_struct,
        dsq_id: u64,
        enq_flags: u64,
    ) -> bool;

    /// struct task_struct *scx_bpf_dsq_peek(u64 dsq_id) (ext.c:6896)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_dsq_peek(dsq_id: u64) -> *mut task_struct;

    // ----- bstr helpers (ext.c:6977/7026) -----

    /// void scx_bpf_exit_bstr(s64 exit_code, char *fmt,
    ///                        unsigned long long *data, u32 data__sz)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_exit_bstr(
        exit_code: i64,
        fmt: *const u8,
        data: *const u64,
        data_sz: u32,
    );

    /// void scx_bpf_dump_bstr(char *fmt, unsigned long long *data, u32 data__sz)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_dump_bstr(
        fmt: *const u8,
        data: *const u64,
        data_sz: u32,
    );

    // ----- CPU performance (ext.c:7098/7125/7152) -----

    /// u32 scx_bpf_cpuperf_cap(s32 cpu)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_cpuperf_cap(cpu: i32) -> u32;

    /// u32 scx_bpf_cpuperf_cur(s32 cpu)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_cpuperf_cur(cpu: i32) -> u32;

    /// void scx_bpf_cpuperf_set(s32 cpu, u32 perf)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_cpuperf_set(cpu: i32, perf: u32);

    // ----- Topology / cpumask getters (ext.c:7202/7220/7228/7237) -----

    /// u32 scx_bpf_nr_node_ids(void)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_nr_node_ids() -> u32;

    /// const struct cpumask *scx_bpf_get_possible_cpumask(void)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_get_possible_cpumask() -> *const cpumask;

    /// const struct cpumask *scx_bpf_get_online_cpumask(void)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_get_online_cpumask() -> *const cpumask;

    /// void scx_bpf_put_cpumask(const struct cpumask *cpumask)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_put_cpumask(mask: *const cpumask);

    // ----- Task / runqueue queries (ext.c:7251/7269/7298/7324) -----

    /// bool scx_bpf_task_running(const struct task_struct *p)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_task_running(p: *const task_struct) -> bool;

    /// struct rq *scx_bpf_cpu_rq(s32 cpu)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_cpu_rq(cpu: i32) -> *mut rq;

    /// struct rq *scx_bpf_locked_rq(void)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_locked_rq() -> *mut rq;

    /// struct task_struct *scx_bpf_cpu_curr(s32 cpu)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_cpu_curr(cpu: i32) -> *mut task_struct;

    // ----- cgroup (ext.c:7352) — also requires CONFIG_CGROUP_SCHED -----

    /// struct cgroup *scx_bpf_task_cgroup(struct task_struct *p)
    #[cfg(all(CONFIG_SCHED_CLASS_EXT = "y", CONFIG_CGROUP_SCHED = "y"))]
    pub(crate) fn scx_bpf_task_cgroup(p: *mut task_struct) -> *mut cgroup;

    // ----- Misc (ext.c:7403/7463) -----

    /// u64 scx_bpf_now(void)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_now() -> u64;

    /// void scx_bpf_events(struct scx_event_stats *events, size_t events__sz)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_events(
        events: *mut scx_event_stats,
        events_sz: usize,
    );

    // ----- Idle / NUMA (ext_idle.c) -----

    /// int scx_bpf_cpu_node(s32 cpu) (ext_idle.c:950)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_cpu_node(cpu: i32) -> i32;

    /// s32 scx_bpf_select_cpu_and(struct task_struct *p, s32 prev_cpu,
    ///                            u64 wake_flags, const struct cpumask *cpus_allowed,
    ///                            u64 flags) (ext_idle.c:1048)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_select_cpu_and(
        p: *mut task_struct,
        prev_cpu: i32,
        wake_flags: u64,
        cpus_allowed: *const cpumask,
        flags: u64,
    ) -> i32;

    /// const struct cpumask *scx_bpf_get_idle_cpumask_node(int node) (ext_idle.c:1072)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_get_idle_cpumask_node(node: i32) -> *const cpumask;

    /// const struct cpumask *scx_bpf_get_idle_cpumask(void) (ext_idle.c:1096)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_get_idle_cpumask() -> *const cpumask;

    /// const struct cpumask *scx_bpf_get_idle_smtmask_node(int node) (ext_idle.c:1127)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_get_idle_smtmask_node(node: i32) -> *const cpumask;

    /// const struct cpumask *scx_bpf_get_idle_smtmask(void) (ext_idle.c:1155)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_get_idle_smtmask() -> *const cpumask;

    /// void scx_bpf_put_idle_cpumask(const struct cpumask *idle_mask) (ext_idle.c:1184)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_put_idle_cpumask(mask: *const cpumask);

    /// bool scx_bpf_test_and_clear_cpu_idle(s32 cpu) (ext_idle.c:1204)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_test_and_clear_cpu_idle(cpu: i32) -> bool;

    /// s32 scx_bpf_pick_idle_cpu_node(const struct cpumask *cpus_allowed,
    ///                                int node, u64 flags) (ext_idle.c:1242)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_pick_idle_cpu_node(
        cpus_allowed: *const cpumask,
        node: i32,
        flags: u64,
    ) -> i32;

    /// s32 scx_bpf_pick_idle_cpu(const struct cpumask *cpus_allowed,
    ///                           u64 flags) (ext_idle.c:1282)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_pick_idle_cpu(
        cpus_allowed: *const cpumask,
        flags: u64,
    ) -> i32;

    /// s32 scx_bpf_pick_any_cpu_node(const struct cpumask *cpus_allowed,
    ///                               int node, u64 flags) (ext_idle.c:1325)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_pick_any_cpu_node(
        cpus_allowed: *const cpumask,
        node: i32,
        flags: u64,
    ) -> i32;

    /// s32 scx_bpf_pick_any_cpu(const struct cpumask *cpus_allowed,
    ///                          u64 flags) (ext_idle.c:1372)
    #[cfg(CONFIG_SCHED_CLASS_EXT = "y")]
    pub(crate) fn scx_bpf_pick_any_cpu(
        cpus_allowed: *const cpumask,
        flags: u64,
    ) -> i32;
}

// Global variables
unsafe extern "C" {
    /// `extern unsigned long volatile __cacheline_aligned_in_smp
    /// __jiffy_arch_data jiffies;`
    ///
    /// Real definition done via linker script (`arch/x86/kernel/vmlinux.lds.S`)
    /// and is made an alias to `jiffies_64` on x86
    pub(crate) static jiffies: u64;

    /// `DEFINE_PER_CPU(int, numa_node);`
    pub(crate) static numa_node: i32;

    /// `DEFINE_PER_CPU(struct rex_cleanup_entry[64], rex_cleanup_entries)
    /// ____cacheline_aligned = { 0 };`
    ///
    /// Used for cleanup upon panic
    ///
    /// Pointee type omitted since this per-cpu variable will never be directly
    /// dereferenced, it is always used for per-cpu address calculation
    ///
    /// Allow the use of rust fn ptr as the function is only called in Rust
    #[allow(improper_ctypes)]
    pub(crate) static mut rex_cleanup_entries: [CleanupEntry; ENTRIES_SIZE];

    /// `DEFINE_PER_CPU(void *, rex_stack_ptr);`
    ///
    /// Top of the per-cpu stack for rex programs
    pub(crate) static rex_stack_ptr: u64;

    /// `DECLARE_PER_CPU_CACHE_HOT(struct task_struct *, current_task);`
    ///
    /// Per-cpu pointer of the current task
    // rustc properly treats the empty `lock_class_key` as zero-sized
    #[allow(improper_ctypes)]
    pub(crate) static current_task: *mut task_struct;

    /// `DECLARE_PER_CPU_CACHE_HOT(int, cpu_number);`
    ///
    /// Current CPU number
    pub(crate) static cpu_number: i32;

    ///  `DEFINE_PER_CPU(int, rex_termination_state);`
    ///  
    ///  Used to indidicate whether a BPF program in a CPU is executing
    ///  inside a helper, or inside a panic handler, or just in BPF text.
    pub(crate) static mut rex_termination_state: u8;

    /// DEFINE_PER_CPU_READ_MOSTLY(unsigned long, this_cpu_off) =
    /// BOOT_PERCPU_OFFSET;
    ///
    /// Offset on the current
    pub(crate) static this_cpu_off: u64;

    /// DEFINE_PER_CPU(char[MAX_BPRINTF_BUF], rex_log_buf) = { 0 };
    pub(crate) static mut rex_log_buf: [u8; MAX_BPRINTF_BUF as usize];
}
