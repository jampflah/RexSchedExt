# Rex `sched_ext` Test Plan — All Callbacks and kfuncs

Goal: exercise every `sched_ext` callback supported by `rex-macros` and every
`scx_bpf_*` / `bpf_iter_scx_dsq_*` kfunc wrapped in
[rex/src/sched_ext/](../rex/src/sched_ext/) at least once on a live kernel,
verifying that:

1. The Rust → BPF entry symbol is emitted in the right `link_section` and the
   kernel actually invokes it.
2. The kfunc's GOT relocation resolves and the call returns sane values without
   triggering the Rex / sched_ext watchdog.
3. The safe wrappers (`Cpumask`, `Rq`, `BpfIterScxDsq`, …) round-trip kernel
   pointers correctly.

Authoritative inventories used to build this plan:

- Callbacks: [rex-macros/src/sched_ext.rs](../rex-macros/src/sched_ext.rs) —
  every `expand_*` arm in `SchedExt::expand`.
- kfunc wrappers: [rex/src/sched_ext/sched_ext_impl.rs](../rex/src/sched_ext/sched_ext_impl.rs)
  + the `extern "C"` block in [rex/src/ffi.rs](../rex/src/ffi.rs).
- Existing baseline scheduler: [samples/scx_simple/src/main.rs](../samples/scx_simple/src/main.rs).

---

## Status — 2026-04-29

| Stage | Sample(s)                                              | State        | Commits                                |
| ----- | ------------------------------------------------------ | ------------ | -------------------------------------- |
| 1     | `scx_simple`                                           | ✅ done      | `38794a5`                              |
| 2     | `scx_kfunc_smoke` (+ `ScxEventStats` safe API)         | ✅ done      | `cba8894`, `2618f63`                   |
| 3     | `scx_vtime`, `scx_dsq_move` (+ `BpfIterScxDsq` rework) | ✅ done      | `03d5b1d`, `40ddd23`, `5c626db`        |
| 4     | `scx_select`, `scx_cpuperf`                            | ⏳ pending   |                                        |
| 5     | `scx_lifecycle` / `scx_runstate` / `scx_yield` / `scx_dequeue` / `scx_idle` / `scx_weight_mask` / `scx_core_sched` / `scx_cpu_hotplug` | ⏳ pending |   |
| 6     | `scx_cgroup` (gated on `CONFIG_EXT_GROUP_SCHED=y`)     | ⏳ pending   |                                        |
| 7     | `scx_dump`, `scx_error`                                | ⏳ pending   |                                        |
| 8     | Negative tests (§3)                                    | ⏳ pending   |                                        |
| –     | `scripts/ci/scx-test.sh` + coverage gate (§5)          | ⏳ pending   |                                        |

**Coverage today: 32 / 49 kfuncs (~65%), 5 / 27 callbacks (~19%), 4 samples wired into `meson test`.**

**Real bugs the harness surfaced and fixed:**

1. `samples/scx_simple` shipped with `STALL_MODE = 1` (the soft-stall negative path) instead of `0`. The first end-to-end run of the new harness exposed the watchdog-disable pattern in `dmesg`. Fixed in commit `38794a5`.
2. `BpfIterScxDsq::new() -> Result<Self, _>` returned a self-referential 48 B struct by value. The kernel's `INIT_DSQ_LIST_CURSOR` writes `&kit->cursor.node` into `kit->cursor.node.{next,prev}`; after Rust moved the struct into the caller's slot those embedded pointers became stale, so the first `next()` call walked freed stack memory while holding `dsq->lock` and wedged the entire guest. Replaced the API with `BpfIterScxDsq::uninit()` (const, no kfunc) + `BpfIterScxDsq::open(&mut self, ...)` so the kernel's self-pointers reference the caller's stable stack address. Fixed in commit `03d5b1d`.

**API gaps closed:**

- `ScxEventStats` now has a safe `zeroed()` constructor and `as_i64_slice()` accessor; `scx_bpf_events` is no longer `unsafe fn`. Commit `cba8894`.

---

## 0. Test harness conventions

Each test is a Rex sample under `samples/scx_<name>/` with the same shape as
`scx_simple`:

- `Cargo.toml` + `src/main.rs` (`#![no_std]`, `#![no_main]`).
- `loader.c` derived from `samples/scx_simple/loader.c`.
- `meson.build` registering both targets.
- A single `#[rex_sched_ext_ops]` static named `<name>_ops` so the
  `.struct_ops` ELF section is non-empty (otherwise LTO drops it — see commit
  `399c84b` "SchedExtOps metadata was being optimized away").

Common assertions emitted from each callback via `rex_printk!`:

- `[scx_<name>] <callback>: pid=<pid> ...` once per invocation.
- For kfunc tests, also log the returned value so the dmesg trace is the
  oracle.

Common verification steps after `cargo build && ./loader`:

1. `dmesg -w` shows the expected `[scx_<name>] <callback>` lines under
   workload (`yes > /dev/null & sleep 5; kill %1`).
2. `cat /sys/kernel/sched_ext/state` shows `enabled` and the scheduler name.
3. `cat /sys/kernel/sched_ext/<id>/ops` lists all installed callbacks.
4. `bpftool prog show` confirms the Rex program is loaded.
5. Ctrl-C the loader → `dmesg` shows clean detach (no
   `scx_disable_rex returned -ENOENT`, no kobject leak per
   [rex-watchdog-disable-leak.md](rex-watchdog-disable-leak.md)).

Tests that need cgroups must mount cgroup v2 with the cpu controller and
move the workload into a child cgroup before the assertion checks.

A helper `tools/run-scx-test.sh <sample>` should:

- Snapshot `/sys/kernel/debug/sched/ext_stats` (or `ext_events`) before/after.
- Capture dmesg between attach and detach.
- Diff against an `expected.txt` per sample (golden trace of the callback
  log lines, order-insensitive for the runtime callbacks).

---

## 1. Callback coverage matrix

One sample per row, unless noted (some can share a sample). Every sample also
implements `init` / `exit` (free) and routes work through `enqueue` +
`dispatch` so the scheduler is actually viable.

| Sample                  | Primary callbacks under test                               | Trigger                                                                 |
| ----------------------- | ---------------------------------------------------------- | ----------------------------------------------------------------------- |
| `scx_simple`            | `select_cpu`, `enqueue`, `dispatch`, `init`, `exit`        | Already present. Run with `STALL_MODE = 0`.                             |
| `scx_lifecycle`         | `init_task`, `exit_task`, `enable`, `disable`              | `fork()` / `exit()` of a short-lived child, plus attach / detach.       |
| `scx_runstate`          | `runnable`, `running`, `stopping`, `quiescent`, `tick`     | Run a CPU-bound `yes` plus a `sleep` loop to force every transition.    |
| `scx_yield`             | `yield`                                                    | Workload calls `sched_yield()` in a tight loop (write a 5-line C tool). |
| `scx_core_sched`        | `core_sched_before`                                        | Boot with `sched_core` enabled; pin two SMT siblings of the same task.  |
| `scx_weight_mask`       | `set_weight`, `set_cpumask`                                | `chrt -r 50` then `taskset -cp` on the workload pid.                    |
| `scx_idle`              | `update_idle`                                              | Bring CPUs in/out of idle with a single-thread workload.                |
| `scx_dequeue`           | `dequeue`                                                  | `kill -STOP` then `kill -CONT` to force re-queue/de-queue.              |
| `scx_cpu_hotplug`       | `cpu_online`, `cpu_offline`, `cpu_acquire`, `cpu_release`  | `echo 0 > /sys/devices/system/cpu/cpuN/online` cycling.                 |
| `scx_dump`              | `dump`, `dump_cpu`, `dump_task`                            | `echo 1 > /sys/kernel/sched_ext/<id>/dump` (or trigger via watchdog).   |
| `scx_cgroup`            | `cgroup_init`, `cgroup_exit`, `cgroup_prep_move`, `cgroup_move`, `cgroup_cancel_move`, `cgroup_set_weight`, `cgroup_set_bandwidth`, `cgroup_set_idle` | `mkdir /sys/fs/cgroup/test`, write `cgroup.procs`, `cpu.weight`, `cpu.max`, `cpu.idle`. |

Notes:

- `cgroup_*` callbacks are gated on `CONFIG_EXT_GROUP_SCHED=y` per the
  `#[cfg]` in [rex-macros/src/sched_ext.rs](../rex-macros/src/sched_ext.rs).
  The sample must be compiled against a kernel built with that flag — assert
  it at runtime with `cat /sys/kernel/sched_ext/features`.
- `cpu_acquire` / `cpu_release` only fire when another scheduling class
  preempts an SCX task. Pair with a brief `chrt -r 99` deadline workload to
  steal CPUs from SCX.
- The "exit reason" fields delivered to `exit` (`ScxExitInfo`) must be
  exercised in three modes: `SCX_EXIT_UNREG` (clean detach), `SCX_EXIT_ERROR`
  (call `scx_bpf_error_str` from the sample), `SCX_EXIT_ERROR_STALL` (reuse
  `STALL_MODE = 1` in `scx_simple`).

---

## 2. kfunc coverage matrix

One row per wrapper in
[rex/src/sched_ext/sched_ext_impl.rs](../rex/src/sched_ext/sched_ext_impl.rs).
"Sample" indicates which scheduler exercises the call; many fold cleanly into
a shared `scx_kfunc_smoke` scheduler that calls each kfunc once and logs the
result.

### 2.1 DSQ insert / dispatch

| kfunc                                  | Sample               | Assertion                                                               |
| -------------------------------------- | -------------------- | ----------------------------------------------------------------------- |
| `scx_bpf_dsq_insert`                   | `scx_simple`         | Existing — covered by enqueue path.                                     |
| `scx_bpf_dsq_insert_v2`                | `scx_kfunc_smoke`    | Returns `true` while `scx_root` valid; log return value.                |
| `scx_bpf_dsq_insert_vtime`             | `scx_vtime`          | Insert into vtime-ordered DSQ; observe dispatch order matches vtimes.   |
| `scx_bpf_dsq_insert_vtime_args` (`__scx_bpf_dsq_insert_vtime`) | `scx_vtime`          | Same workload, alternate ABI path. Log `true` return.                   |

### 2.2 DSQ move / consume / iterator

| kfunc                                  | Sample            | Assertion                                                              |
| -------------------------------------- | ----------------- | ---------------------------------------------------------------------- |
| `scx_bpf_dsq_move_to_local` / `scx_bpf_consume` | `scx_simple` | Existing.                                                              |
| `scx_bpf_dsq_move`                     | `scx_dsq_move`    | Iterate a custom DSQ, move every other task to a second DSQ; verify count via `scx_bpf_dsq_nr_queued`. |
| `scx_bpf_dsq_move_vtime`               | `scx_dsq_move`    | Same scheduler, vtime path.                                            |
| `scx_bpf_dsq_move_set_slice`           | `scx_dsq_move`    | Set slice before move; verify `tick()` interval observed by `running`. |
| `scx_bpf_dsq_move_set_vtime`           | `scx_dsq_move`    | Set vtime before move; observe ordering.                               |
| `bpf_iter_scx_dsq_new` / `_next` / `_destroy` (via `BpfIterScxDsq`) | `scx_dsq_move` | Iterate >0 tasks in dispatch; ensure `Drop` calls `_destroy` (no leaks across attach/detach cycles). |
| `scx_bpf_dsq_peek`                     | `scx_dsq_move`    | Peek matches first iterator yield.                                     |

### 2.3 DSQ lifecycle / counters

| kfunc                          | Sample            | Assertion                                                  |
| ------------------------------ | ----------------- | ---------------------------------------------------------- |
| `scx_bpf_create_dsq`           | every             | Already covered by `scx_simple::init`.                     |
| `scx_bpf_destroy_dsq`          | `scx_kfunc_smoke` | Create then destroy in `init`; verify subsequent `nr_queued` returns negative. |
| `scx_bpf_dsq_nr_queued`        | `scx_dsq_move`    | Compare against expected enqueue count after a burst.      |

### 2.4 CPU selection / idle picking

| kfunc                              | Sample           | Assertion                                                             |
| ---------------------------------- | ---------------- | --------------------------------------------------------------------- |
| `scx_bpf_select_cpu_dfl`           | `scx_simple`     | Existing.                                                             |
| `scx_bpf_select_cpu_and`           | `scx_select`     | Restrict via current task `cpus_ptr`; assert returned CPU is a member. |
| `scx_bpf_select_cpu_and_args` (`__scx_bpf_select_cpu_and`) | `scx_select`     | Same scheduler, args-struct ABI.                                      |
| `scx_bpf_pick_idle_cpu`            | `scx_select`     | Compare against `scx_bpf_get_idle_cpumask`.                           |
| `scx_bpf_pick_idle_cpu_node`       | `scx_select`     | Restrict to NUMA node 0; verify `scx_bpf_cpu_node` of result == 0.    |
| `scx_bpf_pick_any_cpu`             | `scx_select`     | Always returns a CPU within the mask, even when fully busy.           |
| `scx_bpf_pick_any_cpu_node`        | `scx_select`     | Same, scoped to one node.                                             |
| `scx_bpf_test_and_clear_cpu_idle`  | `scx_select`     | Pick an idle CPU, then verify it is no longer in the idle mask.       |

### 2.5 cpumask / topology getters

| kfunc                                  | Sample           | Assertion                                                                 |
| -------------------------------------- | ---------------- | ------------------------------------------------------------------------- |
| `scx_bpf_get_possible_cpumask` / `_put_cpumask` | `scx_kfunc_smoke` | Get → log popcount via `nr_cpu_ids` → put. No leak across 100 cycles (kmemleak clean). |
| `scx_bpf_get_online_cpumask`           | `scx_kfunc_smoke` | Popcount equals online CPUs in `/sys/devices/system/cpu/online`.          |
| `scx_bpf_get_idle_cpumask` / `_put_idle_cpumask` | `scx_kfunc_smoke` | Popcount monotonically decreases under `yes`-load.                         |
| `scx_bpf_get_idle_cpumask_node`        | `scx_kfunc_smoke` | Restricted to node 0; popcount ≤ system idle popcount.                    |
| `scx_bpf_get_idle_smtmask`             | `scx_kfunc_smoke` | On SMT systems, popcount ≤ idle cpumask popcount.                         |
| `scx_bpf_get_idle_smtmask_node`        | `scx_kfunc_smoke` | Same, per-node.                                                           |
| `scx_bpf_nr_cpu_ids`                   | every             | Equals `nproc`.                                                           |
| `scx_bpf_nr_node_ids`                  | `scx_kfunc_smoke` | Equals `numactl -H` node count.                                           |

### 2.6 CPU & runqueue helpers

| kfunc                  | Sample           | Assertion                                                                  |
| ---------------------- | ---------------- | -------------------------------------------------------------------------- |
| `scx_bpf_kick_cpu`     | `scx_select`     | Kick a remote CPU with `SCX_KICK_PREEMPT`; observe a fresh `dispatch()` on it. |
| `scx_bpf_task_cpu`     | `scx_simple`     | Already implicit; log it from `enqueue`.                                   |
| `scx_bpf_cpu_node`     | `scx_kfunc_smoke` | For each cpu, must equal `/sys/devices/system/cpu/cpuN/topology/physical_package_id`. |
| `scx_bpf_cpu_rq`       | `scx_kfunc_smoke` | Returns non-null for any valid cpu.                                        |
| `scx_bpf_locked_rq`    | inside `enqueue`  | Returns non-null while inside an SCX callback; log address.                |
| `scx_bpf_cpu_curr`     | `scx_kfunc_smoke` | For the calling cpu, must equal `bpf_get_current_task` when not idle.      |
| `scx_bpf_task_running` | `scx_runstate`    | True between `running` and `stopping` callbacks for the same pid.          |

### 2.7 Task accessors

| kfunc                          | Sample        | Assertion                                                                |
| ------------------------------ | ------------- | ------------------------------------------------------------------------ |
| `scx_bpf_task_set_slice`       | `scx_runstate`| Set 1 ms slice on workload; observe `tick`/`stopping` fires accordingly. |
| `scx_bpf_task_set_dsq_vtime`   | `scx_vtime`   | Set staggered vtimes; observe ordered dispatch.                          |
| `scx_bpf_task_cgroup`          | `scx_cgroup`  | Cgroup pointer non-null for tasks moved into the test cgroup.            |
| `scx_bpf_reenqueue_local`      | `scx_cpu_hotplug` | After `cpu_offline`, returns count > 0 of re-enqueued tasks.        |
| `scx_bpf_reenqueue_local_v2`   | `scx_cpu_hotplug` | Same, v2 entry point.                                              |

### 2.8 Dispatch context controls

| kfunc                          | Sample            | Assertion                                                              |
| ------------------------------ | ----------------- | ---------------------------------------------------------------------- |
| `scx_bpf_dispatch_nr_slots`    | `scx_kfunc_smoke` | Inside `dispatch`, returns > 0; log.                                   |
| `scx_bpf_dispatch_cancel`      | `scx_kfunc_smoke` | After dispatch, calling cancel must not crash. Verify next dispatch still fires. |

### 2.9 CPU performance

| kfunc                    | Sample          | Assertion                                                              |
| ------------------------ | --------------- | ---------------------------------------------------------------------- |
| `scx_bpf_cpuperf_cap`    | `scx_cpuperf`   | Returns ≤ 1024 (sched_ext perf scale max). Log per cpu.                |
| `scx_bpf_cpuperf_cur`    | `scx_cpuperf`   | Within `[0, cap]`.                                                     |
| `scx_bpf_cpuperf_set`    | `scx_cpuperf`   | Set to `cap / 2`; observe `cur` follow on the next callback (driver-dependent — skip on cpufreq governors that ignore the hint). |

### 2.10 Logging & exit

| kfunc                  | Sample           | Assertion                                                                 |
| ---------------------- | ---------------- | ------------------------------------------------------------------------- |
| `scx_bpf_error_str` (`scx_bpf_error_bstr`) | `scx_error`      | Trip a fatal exit on demand; assert `ScxExitInfo.kind == SCX_EXIT_ERROR`. |
| `scx_bpf_exit_str` (`scx_bpf_exit_bstr`)   | `scx_error`      | Distinct exit code propagates to `info.exit_code`.                        |
| `scx_bpf_dump_str` (`scx_bpf_dump_bstr`)   | `scx_dump`       | Trigger dump via sysrq or sysfs; assert literal string appears in dump.   |

### 2.11 Misc

| kfunc                | Sample            | Assertion                                                                  |
| -------------------- | ----------------- | -------------------------------------------------------------------------- |
| `scx_bpf_now`        | `scx_kfunc_smoke` | Monotonic between callbacks (log delta from previous call).                |
| `scx_bpf_events`     | `scx_kfunc_smoke` | Snapshot into `ScxEventStats`; assert nonzero `nr_dispatched_*` after run. |

---

## 3. Negative tests

These are not "every kfunc must work" — they verify Rex's safety nets:

- **Stall detection** (`STALL_MODE = 1` path): asserts the watchdog disables
  the scheduler and Rex's disable path doesn't leak. Reference:
  [rex-watchdog-disable-leak.md](rex-watchdog-disable-leak.md). Note: the
  `STALL_MODE` constant was removed from `scx_simple` after commit `38794a5`
  so the baseline harness has a deterministic green run; the negative test
  now needs its own sibling sample (`scx_simple_stall_soft`) whose
  `expected.txt` *requires* the watchdog-disable lines instead of forbidding
  them. Verification step: rerun 10× and check `bpftool prog show` count
  returns to baseline after each cycle.
- **Hard spin in callback** (`STALL_MODE = 2`): asserts the per-CPU Rex
  watchdog ([linux/kernel/bpf/rex.c:78](../linux/kernel/bpf/rex.c#L78))
  triggers `rex_terminate()` within ~20 s. Same split as above — lives in
  `scx_simple_stall_hard`.
- **Bad `scx_bpf_create_dsq`** (`scx_dsq_dup`): create the same DSQ id twice;
  expect `Err(-EEXIST)` from the wrapper.
- **`scx_bpf_destroy_dsq` of unknown id**: expect no crash; subsequent
  `scx_bpf_dsq_nr_queued` on that id returns negative.
- **`scx_bpf_kick_cpu` of an offline cpu**: expect no crash, no callback fired
  on that cpu.
- **`scx_bpf_pick_idle_cpu` with empty mask**: returns negative errno.

---

## 4. Execution order

Stage the work bottom-up so a failure in stage N blocks stage N+1:

1. ✅ **Smoke** — `scx_simple` logs every callback it implements (commit
   `38794a5`). The first end-to-end run of the harness caught a real
   `STALL_MODE = 1` mis-default; fixed in the same commit.
2. ✅ **Read-only kfuncs** — `scx_kfunc_smoke` covers §2.5, §2.6 cpu_\*,
   §2.8, §2.11 plus §2.3 destroy + §2.1 v2 ABI (commits `cba8894`,
   `2618f63`). The §2.5 `_node` getters are deferred to a sibling
   per-node sample because they're mutually exclusive with the flat
   getters via `SCX_OPS_BUILTIN_IDLE_PER_NODE`.
3. ✅ **DSQ machinery** — `scx_vtime` (§2.1 vtime + §2.7
   `task_set_dsq_vtime`) and `scx_dsq_move` (§2.2 peek + iterator + four
   move helpers) (commits `40ddd23`, `5c626db`). Surfaced the
   `BpfIterScxDsq` self-referential pointer bug; fix in commit `03d5b1d`.
4. ⏳ **CPU selection** — `scx_select` + `scx_cpuperf`.
5. ⏳ **Lifecycle / runstate / yield / dequeue / hotplug** — covers most of
   the remaining callbacks.
6. ⏳ **cgroup** — gated, last because it requires kernel config
   `CONFIG_EXT_GROUP_SCHED=y`.
7. ⏳ **Dump & error paths** — `scx_dump`, `scx_error`. Run after every
   other sample is green so dumps capture a known-good baseline.
8. ⏳ **Negative tests (Section 3)** — last. Some leave the kernel in a
   degraded state; reboot the VM between runs.

---

## 5. CI hooks

Add a `scripts/ci/scx-test.sh` that:

1. Boots the in-tree kernel under qemu (the existing `flake.nix` already
   builds it).
2. For each sample listed above, runs `tools/run-scx-test.sh <sample>` with
   a 60 s budget.
3. Diffs the captured dmesg trace against `samples/<sample>/expected.txt`.
4. Asserts `bpftool prog show | wc -l` is identical before and after the
   suite (catches the watchdog leak regression).
5. **Coverage gate.** Greps every `pub fn scx_bpf_*` in
   [rex/src/sched_ext/sched_ext_impl.rs](../rex/src/sched_ext/sched_ext_impl.rs)
   and every `pub fn` on `BpfIterScxDsq` in
   [rex/src/sched_ext/wrappers.rs](../rex/src/sched_ext/wrappers.rs) against
   the union of all `samples/scx_*/expected.txt`. Any wrapper not
   referenced by at least one expected.txt fails CI. This is the
   mechanical enforcement of the "coverage matrix is the source-of-truth"
   rule below: it makes it impossible to land a new wrapper without an
   accompanying sample assertion.

The kfunc coverage matrix above is the source-of-truth: any new wrapper
added to [rex/src/sched_ext/sched_ext_impl.rs](../rex/src/sched_ext/sched_ext_impl.rs)
must come with a row here and a sample assertion before it lands. Step 5
of the CI hook above enforces this mechanically once
`scripts/ci/scx-test.sh` is in place.
