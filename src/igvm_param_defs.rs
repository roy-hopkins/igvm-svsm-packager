use zerocopy::AsBytes;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct IgvmParamPage {
    pub cpu_count: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, AsBytes)]
pub struct IgvmParamBlock {
    pub param_page: u32,
    pub cpuid_page: u32,
    pub secrets_page: u32,
    pub memory_map: u32,
    pub launch_fw: u8,
    pub _reserved: [u8; 3],
    pub kernel_size: u32,
    pub kernel_base: u64,
    pub stage2_size: u32,
    pub stage2_base: u64,
    pub fs_size: u32,
    pub fs_base: u64,
}
