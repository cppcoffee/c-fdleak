use std::collections::HashMap;
use std::env;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use aya::maps::{HashMap as EbpfHashMap, StackTraceMap};
use aya::programs::UProbe;
use aya::util::kernel_symbols;
use aya::Ebpf;
use blazesym::symbolize::{Process, Source, Symbolizer};
use blazesym::Pid;
use clap::Parser;
use libc::{c_int, pid_t};
use log::{debug, info, warn};

use c_fdleak::symbol::symbolize_stack_frames;
use c_fdleak::util::{dump_to_file, get_binary_path_by_pid, wait_for_termination_signal};
use c_fdleak_common::FdInfo;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, help = "pid of the process")]
    pid: pid_t,

    #[clap(short, long, default_value = "30", help = "timeout in seconds")]
    timeout: u64,

    #[clap(short, long, default_value = "/tmp/fdleak.out", help = "output file")]
    output: PathBuf,

    #[clap(short, long, default_value = "false", help = "verbose mode")]
    verbose: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut n;

    let opt = Opt::parse();

    // set log level, when RUST_LOG env not set
    if env::var("RUST_LOG").is_err() {
        let s = if opt.verbose { "debug" } else { "info" };

        env::var("RUST_LOG")
            .err()
            .map(|_| env::set_var("RUST_LOG", s));
    }

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/c-fdleak"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    n = attach_uprobes(&mut ebpf, &Path::new("libc"), Some(opt.pid));
    if n == 0 {
        // try to attach uprobes to the binary path (statically linked binary)
        let bin_path = get_binary_path_by_pid(opt.pid)
            .await
            .context("failed to get binary path by pid")?;

        n = attach_uprobes(&mut ebpf, &bin_path, Some(opt.pid));
        if n == 0 {
            bail!("failed to attach uprobes, not found probe points");
        }
    }

    info!("attached probe points {} to {}", n, opt.pid);
    info!("wait for {}s or press ctrl+c to start dump", opt.timeout);

    wait_for_termination_signal(opt.timeout).await;

    let map = dump_stack_frames(&mut ebpf, opt.pid)
        .await
        .context("failed to dump stack frames")?;
    dump_to_file(&opt.output, &map).await?;

    info!("dump stack frame to {:?}", opt.output);

    Ok(())
}

fn attach_uprobes(ebpf: &mut Ebpf, bin: &Path, pid: Option<i32>) -> usize {
    let mut count = 0;

    let probes = [
        // file
        ("open", "open_exit"),
        ("openat", "open_exit"),
        ("openat2", "open_exit"),
        ("creat", "open_exit"),
        ("mkstemp", "open_exit"),
        ("close", "close_enter"),
        // dup
        ("dup", "open_exit"),
        ("dup2", "dup2_enter"),
        ("dup2", "dup2_exit"),
        ("dup3", "dup2_enter"),
        ("dup3", "dup2_exit"),
        // pipe
        ("pipe", "pipe_enter"),
        ("pipe", "pipe_exit"),
        ("pipe2", "pipe_enter"),
        ("pipe2", "pipe_exit"),
        ("mkfifo", "open_exit"),
        // socket
        ("socket", "open_exit"),
        ("accept", "open_exit"),
        // other
        ("memfd_create", "open_exit"),
    ];

    for probe in &probes {
        match attach_uprobe(ebpf, bin, pid, *probe) {
            Ok(_) => count += 1,
            Err(e) => {
                debug!("failed to attach uprobe {} to {}: {}", probe.1, probe.0, e)
            }
        }
    }

    count
}

fn attach_uprobe(
    ebpf: &mut Ebpf,
    path: &Path,
    pid: Option<i32>,
    probe: (&str, &str),
) -> Result<()> {
    let program: &mut UProbe = ebpf.program_mut(probe.1).unwrap().try_into()?;
    program.load()?;
    program.attach(Some(probe.0), 0, path, pid)?;

    Ok(())
}

async fn dump_stack_frames(ebpf: &mut Ebpf, pid: pid_t) -> Result<HashMap<String, u64>> {
    let mut result: HashMap<String, u64> = HashMap::new();

    let src = Source::Process(Process::new(Pid::Pid(NonZeroU32::new(pid as u32).unwrap())));
    let symbolizer = Symbolizer::new();
    let ksyms = kernel_symbols().context("failed to load kernel symbols")?;

    let stack_traces = StackTraceMap::try_from(ebpf.map("STACK_TRACES").unwrap())?;
    let (fd_count, fds) = collapse_fd_map(ebpf).context("failed to collapse fds map")?;

    for (stack_id, count) in fds.iter() {
        let stack_trace = stack_traces.get(stack_id, 0)?;
        let stack_frame = symbolize_stack_frames(&stack_trace, &symbolizer, &src, &ksyms)?;

        result
            .entry(stack_frame)
            .and_modify(|x| *x += count)
            .or_insert(*count);
    }

    info!(
        "total {} file descriptors, {} stack frames",
        fd_count,
        result.len()
    );

    Ok(result)
}

fn collapse_fd_map(ebpf: &Ebpf) -> Result<(usize, HashMap<u32, u64>)> {
    let mut n = 0;
    let mut m = HashMap::new();
    let fds: EbpfHashMap<_, c_int, FdInfo> = EbpfHashMap::try_from(ebpf.map("FDS").unwrap())?;

    for item in fds.iter() {
        let (_key, value) = item.context(format!("failed to iter FDS map"))?;
        let stack_id = value.stack_id as u32;

        m.entry(stack_id).and_modify(|x| *x += 1).or_insert(1);

        n += 1;
    }

    Ok((n, m))
}
