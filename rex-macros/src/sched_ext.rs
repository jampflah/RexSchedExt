use proc_macro2::TokenStream;
use proc_macro_error::abort_call_site;
use quote::{format_ident, quote};
use syn::{parse2, ItemFn, Result};

use crate::args::parse_string_args;

pub(crate) struct SchedExt {
    callback: String,
    item: ItemFn,
}

impl SchedExt {
    pub(crate) fn parse(
        attrs: TokenStream,
        item: TokenStream,
    ) -> Result<SchedExt> {
        let item: ItemFn = parse2(item)?;
        let args = parse_string_args(attrs)?;

        let callback = pop_string_args!(args, "callback")
            .unwrap_or_else(|| {
                abort_call_site!(
                    "rex_sched_ext requires a `callback` argument, \
                     e.g. #[rex_sched_ext(callback = \"select_cpu\")]"
                )
            });

        Ok(SchedExt { callback, item })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        let function_name = format!("{fn_name}");
        let prog_ident =
            format_ident!("PROG_{}", fn_name.to_string().to_uppercase());
        let entry_name = format_ident!("__rex_entry_{}", fn_name);
        let section_name = format!(
            "rex/struct_ops/sched_ext_ops/{}",
            self.callback
        );

        let args = (&fn_name, &prog_ident, &entry_name,
                    function_name.as_str(), section_name.as_str());

        let entry_fn = match self.callback.as_str() {
            "select_cpu" => self.expand_select_cpu(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "enqueue" => self.expand_enqueue(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "dequeue" => self.expand_dequeue(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "dispatch" => self.expand_dispatch(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "tick" | "running" | "enable" | "disable" => {
                self.expand_task_only(
                    args.0, args.1, args.2, args.3, args.4,
                )
            }
            "runnable" => self.expand_runnable(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "stopping" => self.expand_stopping(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "quiescent" => self.expand_quiescent(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "yield" => self.expand_yield(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "core_sched_before" => self.expand_core_sched_before(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "set_weight" => self.expand_set_weight(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "set_cpumask" => self.expand_set_cpumask(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "update_idle" => self.expand_update_idle(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "cpu_acquire" => self.expand_cpu_acquire(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "cpu_release" => self.expand_cpu_release(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "cpu_online" | "cpu_offline" => self.expand_cpu_event(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "init" => self.expand_init(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "exit" => self.expand_exit(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "init_task" => self.expand_init_task(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "exit_task" => self.expand_exit_task(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "dump" => self.expand_dump(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "dump_cpu" => self.expand_dump_cpu(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "dump_task" => self.expand_dump_task(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "cgroup_init" => self.expand_cgroup_init(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "cgroup_exit" => self.expand_cgroup_exit(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "cgroup_prep_move" => self.expand_cgroup_prep_move(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "cgroup_move" => self.expand_cgroup_move(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "cgroup_cancel_move" => self.expand_cgroup_cancel_move(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "cgroup_set_weight" => self.expand_cgroup_set_weight(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "cgroup_set_bandwidth" => self.expand_cgroup_set_bandwidth(
                args.0, args.1, args.2, args.3, args.4,
            ),
            "cgroup_set_idle" => self.expand_cgroup_set_idle(
                args.0, args.1, args.2, args.3, args.4,
            ),
            _ => abort_call_site!(
                "Unknown sched_ext callback \"{}\". Supported: \
                 select_cpu, enqueue, dequeue, dispatch, tick, runnable, \
                 running, stopping, quiescent, yield, core_sched_before, \
                 set_weight, set_cpumask, update_idle, cpu_acquire, \
                 cpu_release, cpu_online, cpu_offline, init, exit, \
                 init_task, exit_task, enable, disable, dump, dump_cpu, \
                 dump_task, cgroup_init, cgroup_exit, cgroup_prep_move, \
                 cgroup_move, cgroup_cancel_move, cgroup_set_weight, \
                 cgroup_set_bandwidth, cgroup_set_idle",
                self.callback
            ),
        };

        let tokens = quote! {
            #[inline(always)]
            #item

            #entry_fn
        };

        Ok(tokens)
    }

    // s32 (*select_cpu)(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
    fn expand_select_cpu(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                p: *mut (),
                prev_cpu: i32,
                wake_flags: u64,
            ) -> i32 {
                let task = unsafe { sched_ext::convert_task(p as *mut _) };
                #fn_name(&#prog_ident, &task, prev_cpu, wake_flags)
            }
        }
    }

    // void (*enqueue)(struct task_struct *p, u64 enq_flags)
    fn expand_enqueue(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                p: *mut (),
                enq_flags: u64,
            ) {
                let task = unsafe { sched_ext::convert_task(p as *mut _) };
                #fn_name(&#prog_ident, &task, enq_flags);
            }
        }
    }

    // void (*dequeue)(struct task_struct *p, u64 deq_flags)
    fn expand_dequeue(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                p: *mut (),
                deq_flags: u64,
            ) {
                let task = unsafe { sched_ext::convert_task(p as *mut _) };
                #fn_name(&#prog_ident, &task, deq_flags);
            }
        }
    }

    // void (*dispatch)(s32 cpu, struct task_struct *prev)
    fn expand_dispatch(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                cpu: i32,
                prev: *mut (),
            ) {
                let prev_task = if prev.is_null() {
                    None
                } else {
                    Some(unsafe { sched_ext::convert_task(prev as *mut _) })
                };
                #fn_name(&#prog_ident, cpu, prev_task.as_ref());
            }
        }
    }

    // void (*tick/running/enable/disable)(struct task_struct *p)
    fn expand_task_only(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                p: *mut (),
            ) {
                let task = unsafe { sched_ext::convert_task(p as *mut _) };
                #fn_name(&#prog_ident, &task);
            }
        }
    }

    // void (*runnable)(struct task_struct *p, u64 enq_flags)
    fn expand_runnable(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                p: *mut (),
                enq_flags: u64,
            ) {
                let task = unsafe { sched_ext::convert_task(p as *mut _) };
                #fn_name(&#prog_ident, &task, enq_flags);
            }
        }
    }

    // void (*stopping)(struct task_struct *p, bool runnable)
    fn expand_stopping(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                p: *mut (),
                runnable: bool,
            ) {
                let task = unsafe { sched_ext::convert_task(p as *mut _) };
                #fn_name(&#prog_ident, &task, runnable);
            }
        }
    }

    // void (*quiescent)(struct task_struct *p, u64 deq_flags)
    fn expand_quiescent(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                p: *mut (),
                deq_flags: u64,
            ) {
                let task = unsafe { sched_ext::convert_task(p as *mut _) };
                #fn_name(&#prog_ident, &task, deq_flags);
            }
        }
    }

    // void (*set_weight)(struct task_struct *p, u32 weight)
    fn expand_set_weight(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                p: *mut (),
                weight: u32,
            ) {
                let task = unsafe { sched_ext::convert_task(p as *mut _) };
                #fn_name(&#prog_ident, &task, weight);
            }
        }
    }

    // void (*update_idle)(s32 cpu, bool idle)
    fn expand_update_idle(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(cpu: i32, idle: bool) {
                #fn_name(&#prog_ident, cpu, idle);
            }
        }
    }

    // void (*cpu_online/cpu_offline)(s32 cpu)
    fn expand_cpu_event(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(cpu: i32) {
                #fn_name(&#prog_ident, cpu);
            }
        }
    }

    // s32 (*init)(void)
    fn expand_init(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name() -> i32 {
                #fn_name(&#prog_ident)
            }
        }
    }

    // void (*exit)(struct scx_exit_info *info)
    fn expand_exit(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                info: *const ::rex::sched_ext::ScxExitInfo,
            ) {
                let info_ref = unsafe { &*info };
                #fn_name(&#prog_ident, info_ref);
            }
        }
    }

    // s32 (*init_task)(struct task_struct *p, struct scx_init_task_args *args)
    fn expand_init_task(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                p: *mut (),
                args: *const ::rex::sched_ext::ScxInitTaskArgs,
            ) -> i32 {
                let task = unsafe { sched_ext::convert_task(p as *mut _) };
                let args_ref = unsafe { &*args };
                #fn_name(&#prog_ident, &task, args_ref)
            }
        }
    }

    // void (*exit_task)(struct task_struct *p, struct scx_exit_task_args *args)
    fn expand_exit_task(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                p: *mut (),
                args: *const ::rex::sched_ext::ScxExitTaskArgs,
            ) {
                let task = unsafe { sched_ext::convert_task(p as *mut _) };
                let args_ref = unsafe { &*args };
                #fn_name(&#prog_ident, &task, args_ref);
            }
        }
    }

    // bool (*yield)(struct task_struct *from, struct task_struct *to)
    fn expand_yield(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                from: *mut (),
                to: *mut (),
            ) -> bool {
                let from_task = unsafe { sched_ext::convert_task(from as *mut _) };
                let to_task = if to.is_null() {
                    None
                } else {
                    Some(unsafe { sched_ext::convert_task(to as *mut _) })
                };
                #fn_name(&#prog_ident, &from_task, to_task.as_ref())
            }
        }
    }

    // bool (*core_sched_before)(struct task_struct *a, struct task_struct *b)
    fn expand_core_sched_before(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                a: *mut (),
                b: *mut (),
            ) -> bool {
                let task_a = unsafe { sched_ext::convert_task(a as *mut _) };
                let task_b = unsafe { sched_ext::convert_task(b as *mut _) };
                #fn_name(&#prog_ident, &task_a, &task_b)
            }
        }
    }

    // void (*set_cpumask)(struct task_struct *p, const struct cpumask *cpumask)
    fn expand_set_cpumask(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                p: *mut (),
                cpumask: *const (),
            ) {
                let task = unsafe { sched_ext::convert_task(p as *mut _) };
                #fn_name(&#prog_ident, &task, cpumask);
            }
        }
    }

    // void (*cpu_acquire)(s32 cpu, struct scx_cpu_acquire_args *args)
    fn expand_cpu_acquire(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                cpu: i32,
                args: *const (),
            ) {
                #fn_name(&#prog_ident, cpu, args);
            }
        }
    }

    // void (*cpu_release)(s32 cpu, struct scx_cpu_release_args *args)
    fn expand_cpu_release(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                cpu: i32,
                args: *const (),
            ) {
                #fn_name(&#prog_ident, cpu, args);
            }
        }
    }

    // void (*dump)(struct scx_dump_ctx *ctx)
    fn expand_dump(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(ctx: *const ()) {
                #fn_name(&#prog_ident, ctx);
            }
        }
    }

    // void (*dump_cpu)(struct scx_dump_ctx *ctx, s32 cpu, bool idle)
    fn expand_dump_cpu(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                ctx: *const (),
                cpu: i32,
                idle: bool,
            ) {
                #fn_name(&#prog_ident, ctx, cpu, idle);
            }
        }
    }

    // void (*dump_task)(struct scx_dump_ctx *ctx, struct task_struct *p)
    fn expand_dump_task(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                ctx: *const (),
                p: *mut (),
            ) {
                let task = unsafe { sched_ext::convert_task(p as *mut _) };
                #fn_name(&#prog_ident, ctx, &task);
            }
        }
    }

    // s32 (*cgroup_init)(struct cgroup *cgrp, struct scx_cgroup_init_args *args)
    fn expand_cgroup_init(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                cgrp: *mut (),
                args: *const ::rex::sched_ext::ScxCgroupInitArgs,
            ) -> i32 {
                let args_ref = unsafe { &*args };
                #fn_name(&#prog_ident, cgrp, args_ref)
            }
        }
    }

    // void (*cgroup_exit)(struct cgroup *cgrp)
    fn expand_cgroup_exit(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(cgrp: *mut ()) {
                #fn_name(&#prog_ident, cgrp);
            }
        }
    }

    // s32 (*cgroup_prep_move)(struct task_struct *p,
    //                        struct cgroup *from, struct cgroup *to)
    fn expand_cgroup_prep_move(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                p: *mut (),
                from: *mut (),
                to: *mut (),
            ) -> i32 {
                let task = unsafe { sched_ext::convert_task(p as *mut _) };
                #fn_name(&#prog_ident, &task, from, to)
            }
        }
    }

    // void (*cgroup_move)(struct task_struct *p,
    //                     struct cgroup *from, struct cgroup *to)
    fn expand_cgroup_move(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                p: *mut (),
                from: *mut (),
                to: *mut (),
            ) {
                let task = unsafe { sched_ext::convert_task(p as *mut _) };
                #fn_name(&#prog_ident, &task, from, to);
            }
        }
    }

    // void (*cgroup_cancel_move)(struct task_struct *p,
    //                            struct cgroup *from, struct cgroup *to)
    fn expand_cgroup_cancel_move(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                p: *mut (),
                from: *mut (),
                to: *mut (),
            ) {
                let task = unsafe { sched_ext::convert_task(p as *mut _) };
                #fn_name(&#prog_ident, &task, from, to);
            }
        }
    }

    // void (*cgroup_set_weight)(struct cgroup *cgrp, u32 weight)
    fn expand_cgroup_set_weight(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                cgrp: *mut (),
                weight: u32,
            ) {
                #fn_name(&#prog_ident, cgrp, weight);
            }
        }
    }

    // void (*cgroup_set_bandwidth)(struct cgroup *cgrp,
    //                              u64 period_us, u64 quota_us, u64 burst_us)
    fn expand_cgroup_set_bandwidth(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                cgrp: *mut (),
                period_us: u64,
                quota_us: u64,
                burst_us: u64,
            ) {
                #fn_name(&#prog_ident, cgrp, period_us, quota_us, burst_us);
            }
        }
    }

    // void (*cgroup_set_idle)(struct cgroup *cgrp, bool idle)
    fn expand_cgroup_set_idle(
        &self,
        fn_name: &syn::Ident,
        prog_ident: &syn::Ident,
        entry_name: &syn::Ident,
        function_name: &str,
        section_name: &str,
    ) -> TokenStream {
        quote! {
            #[used]
            static #prog_ident: sched_ext = unsafe { sched_ext::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #section_name)]
            extern "C" fn #entry_name(
                cgrp: *mut (),
                idle: bool,
            ) {
                #fn_name(&#prog_ident, cgrp, idle);
            }
        }
    }
}
