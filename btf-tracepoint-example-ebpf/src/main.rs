#![no_std]
#![no_main]

use aya_bpf::{
    macros::btf_tracepoint,
    programs::BtfTracePointContext,
};
use aya_log_ebpf::info;

#[btf_tracepoint(name="sched_process_fork")]
pub fn sched_process_fork(ctx: BtfTracePointContext) -> i32 {
    match try_sched_process_fork(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_process_fork(ctx: BtfTracePointContext) -> Result<i32, i32> {
    info!(&ctx, "tracepoint sched_process_fork called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
