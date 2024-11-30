#![no_std]

pub const FDS_MAX_ENTRIES: u32 = 1000000;
pub const STACK_TRACE_MAX_ENTRIES: u32 = 10240;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FdInfo {
    pub timestamp_ns: u64,
    pub stack_id: i64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FdInfo {}

impl FdInfo {
    pub fn new(timestamp_ns: u64, stack_id: i64) -> Self {
        Self {
            timestamp_ns,
            stack_id,
        }
    }
}
