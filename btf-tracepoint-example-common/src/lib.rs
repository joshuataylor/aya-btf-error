#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessInfo {
    pub pid: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessInfo {}