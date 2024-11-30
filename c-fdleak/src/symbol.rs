use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use aya::maps::stack_trace::StackTrace;
use blazesym::symbolize::{CodeInfo, Input, Source, Sym, Symbolizer};

pub fn symbolize_stack_frames(
    stack_trace: &StackTrace,
    symbolizer: &Symbolizer,
    src: &Source,
    ksyms: &BTreeMap<u64, String>,
) -> Result<String> {
    let addrs: Vec<_> = stack_trace.frames().iter().rev().map(|x| x.ip).collect();

    let syms = symbolizer
        .symbolize(src, Input::AbsAddr(&addrs))
        .map_err(|e| anyhow!(format!("symbolize fail: {}", e)))?;

    let mut buffer = String::with_capacity(128);

    for (sym, addr) in syms.iter().zip(addrs.iter()) {
        if !buffer.is_empty() {
            buffer.push(';');
        }

        let name = match sym.as_sym() {
            Some(x) => format_symbolize(x),
            None => {
                ksymbols_search(ksyms, *addr).unwrap_or_else(|| format!("unknown_0x{:08x}", addr))
            }
        };

        buffer.push_str(&name);
    }

    Ok(buffer)
}

fn format_symbolize(sym: &Sym<'_>) -> String {
    let mut s = sym.name.to_string();

    if let Some(code_info) = &sym.code_info {
        s += format!(" ({})", format_code_info(&code_info)).as_ref();
    } else {
        if sym.inlined.len() > 0 {
            let inlined = &sym.inlined[0];

            s += format!(" <inlined:{}>", inlined.name).as_ref();

            if let Some(code_info) = &inlined.code_info {
                s += format!(" ({})", format_code_info(&code_info)).as_ref();
            }
        }
    }

    s += format!(" +0x{:x}", sym.offset).as_ref();

    s
}

fn format_code_info(code_info: &CodeInfo<'_>) -> String {
    match (code_info.dir.as_ref(), code_info.line) {
        (Some(dir), Some(line)) => {
            format!(
                "{}/{}:{}",
                dir.display(),
                code_info.file.to_string_lossy(),
                line
            )
        }
        (Some(dir), None) => format!("{}/{}", dir.display(), code_info.file.to_string_lossy()),
        (None, Some(line)) => format!("{}:{}", code_info.file.to_string_lossy(), line),
        (None, None) => format!("{}", code_info.file.to_string_lossy()),
    }
}

fn ksymbols_search(ksyms: &BTreeMap<u64, String>, ip: u64) -> Option<String> {
    let (sym_addr, name) = ksyms.range(..=ip).next_back()?;

    let kernel_addr_start = if cfg!(target_pointer_width = "64") {
        0xFFFF_8000_0000_0000
    } else {
        0xC000_0000
    };

    let result = if ip >= kernel_addr_start {
        let offset = ip - sym_addr;
        format!("{}+0x{:x}", name, offset)
    } else {
        name.to_string()
    };

    Some(result)
}
