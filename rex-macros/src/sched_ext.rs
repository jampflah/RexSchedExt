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

        let entry_fn = match self.callback.as_str() {
            "select_cpu" => self.expand_select_cpu(
                &fn_name, &prog_ident, &entry_name, &function_name,
                &section_name,
            ),
            "enqueue" => self.expand_enqueue(
                &fn_name, &prog_ident, &entry_name, &function_name,
                &section_name,
            ),
            "dequeue" => self.expand_dequeue(
                &fn_name, &prog_ident, &entry_name, &function_name,
                &section_name,
            ),
            "dispatch" => self.expand_dispatch(
                &fn_name, &prog_ident, &entry_name, &function_name,
                &section_name,
            ),
            "tick" | "running" | "enable" | "disable" | "runnable" => {
                self.expand_task_only(
                    &fn_name, &prog_ident, &entry_name, &function_name,
                    &section_name,
                )
            }
            "stopping" => self.expand_stopping(
                &fn_name, &prog_ident, &entry_name, &function_name,
                &section_name,
            ),
            "quiescent" => self.expand_quiescent(
                &fn_name, &prog_ident, &entry_name, &function_name,
                &section_name,
            ),
            "set_weight" => self.expand_set_weight(
                &fn_name, &prog_ident, &entry_name, &function_name,
                &section_name,
            ),
            "update_idle" => self.expand_update_idle(
                &fn_name, &prog_ident, &entry_name, &function_name,
                &section_name,
            ),
            "cpu_online" | "cpu_offline" => self.expand_cpu_event(
                &fn_name, &prog_ident, &entry_name, &function_name,
                &section_name,
            ),
            "init" => self.expand_init(
                &fn_name, &prog_ident, &entry_name, &function_name,
                &section_name,
            ),
            "exit" => self.expand_exit(
                &fn_name, &prog_ident, &entry_name, &function_name,
                &section_name,
            ),
            "init_task" => self.expand_init_task(
                &fn_name, &prog_ident, &entry_name, &function_name,
                &section_name,
            ),
            "exit_task" => self.expand_exit_task(
                &fn_name, &prog_ident, &entry_name, &function_name,
                &section_name,
            ),
            _ => abort_call_site!(
                "Unknown sched_ext callback \"{}\". Supported: \
                 select_cpu, enqueue, dequeue, dispatch, tick, runnable, \
                 running, stopping, quiescent, set_weight, update_idle, \
                 cpu_online, cpu_offline, init_task, exit_task, enable, \
                 disable, init, exit",
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

    // void (*tick/running/enable/disable/runnable)(struct task_struct *p)
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
}
