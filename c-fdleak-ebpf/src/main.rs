#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{BPF_F_FAST_STACK_CMP, BPF_F_REUSE_STACKID, BPF_F_USER_STACK},
    cty::{c_int, c_long},
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user, gen::bpf_ktime_get_ns},
    macros::{map, uprobe, uretprobe},
    maps::{stack_trace::StackTrace, HashMap},
    programs::{ProbeContext, RetProbeContext},
};
use aya_log_ebpf::info;
use c_fdleak_common::{FdInfo, FDS_MAX_ENTRIES, STACK_TRACE_MAX_ENTRIES};

const STACK_FLAGS: u32 = BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID;

#[map]
static FDS: HashMap<c_int, FdInfo> = HashMap::with_max_entries(FDS_MAX_ENTRIES, 0);

#[map]
static PIPE_FDS: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);

#[map]
static STACK_TRACES: StackTrace = StackTrace::with_max_entries(STACK_TRACE_MAX_ENTRIES, 0);

#[no_mangle]
static TRACE_ALL: bool = false;

#[uretprobe]
pub fn open_exit(ctx: RetProbeContext) -> u32 {
    match try_open_exit(ctx) {
        Ok(rc) => rc,
        Err(_) => 1,
    }
}

fn try_open_exit(ctx: RetProbeContext) -> Result<u32, c_long> {
    let fd: c_int = ctx.ret().ok_or(1)?;
    gen_open_exit(&ctx, fd)
}

#[uprobe]
pub fn close_enter(ctx: ProbeContext) -> u32 {
    match try_close_enter(ctx) {
        Ok(rc) => rc,
        Err(_) => 1,
    }
}

fn try_close_enter(ctx: ProbeContext) -> Result<u32, c_long> {
    let fd: c_int = ctx.arg(0).ok_or(1)?;
    gen_close_enter(&ctx, fd)
}

#[uprobe]
pub fn pipe_enter(ctx: ProbeContext) -> u32 {
    match try_pipe_enter(ctx) {
        Ok(rc) => rc,
        Err(_) => 1,
    }
}

fn try_pipe_enter(ctx: ProbeContext) -> Result<u32, c_long> {
    let pipefd_ptr: u64 = ctx.arg(0).ok_or(1)?;

    let tid = bpf_get_current_pid_tgid() as u32;
    PIPE_FDS.insert(&tid, &pipefd_ptr, 0)?;

    Ok(0)
}

#[uretprobe]
pub fn pipe_exit(ctx: RetProbeContext) -> u32 {
    match try_pipe_exit(ctx) {
        Ok(rc) => rc,
        Err(_) => 1,
    }
}

fn try_pipe_exit(ctx: RetProbeContext) -> Result<u32, c_long> {
    let ret: c_int = ctx.ret().ok_or(1)?;

    if ret != 0 {
        return Ok(0);
    }

    let tid = bpf_get_current_pid_tgid() as u32;

    let pipefd_ptr = unsafe { PIPE_FDS.get(&tid).ok_or(0)? };
    let pipefd_ptr = *pipefd_ptr as *const c_int;

    let pipefd_0 = unsafe { bpf_probe_read_user(pipefd_ptr)? };
    let pipefd_1 = unsafe { bpf_probe_read_user(pipefd_ptr.offset(1))? };

    PIPE_FDS.remove(&tid)?;

    gen_open_exit(&ctx, pipefd_0)?;
    gen_open_exit(&ctx, pipefd_1)?;

    Ok(0)
}

#[uprobe]
pub fn dup2_enter(ctx: ProbeContext) -> u32 {
    match try_dup2_enter(ctx) {
        Ok(rc) => rc,
        Err(_) => 1,
    }
}

fn try_dup2_enter(ctx: ProbeContext) -> Result<u32, c_long> {
    let oldfd: c_int = ctx.arg(0).ok_or(1)?;
    let newfd: c_int = ctx.arg(1).ok_or(1)?;

    if oldfd < 0 || newfd < 0 {
        return Ok(0);
    }

    gen_close_enter(&ctx, newfd)
}

#[uretprobe]
pub fn dup2_exit(ctx: RetProbeContext) -> u32 {
    match try_dup2_exit(ctx) {
        Ok(rc) => rc,
        Err(_) => 1,
    }
}

fn try_dup2_exit(ctx: RetProbeContext) -> Result<u32, c_long> {
    let newfd: c_int = ctx.ret().ok_or(1)?;
    gen_open_exit(&ctx, newfd)
}

fn gen_open_exit(ctx: &RetProbeContext, fd: c_int) -> Result<u32, c_long> {
    if fd < 0 {
        return Ok(0);
    }

    let timestamp_ns = unsafe { bpf_ktime_get_ns() };
    let stack_id = unsafe { STACK_TRACES.get_stackid(ctx, STACK_FLAGS as u64)? };

    let info = FdInfo::new(timestamp_ns, stack_id);
    FDS.insert(&fd, &info, 0)?;

    let trace_all = unsafe { core::ptr::read_volatile(&TRACE_ALL) };
    if trace_all {
        info!(ctx, "open exited, fd={}\n", fd);
    }

    Ok(0)
}

fn gen_close_enter(ctx: &ProbeContext, fd: c_int) -> Result<u32, c_long> {
    if let Some(_) = unsafe { FDS.get(&fd) } {
        FDS.remove(&fd)?;

        let trace_all = unsafe { core::ptr::read_volatile(&TRACE_ALL) };
        if trace_all {
            info!(ctx, "close entered, fd={}\n", fd);
        }
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
