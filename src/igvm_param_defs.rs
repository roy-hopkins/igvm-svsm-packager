use zerocopy::AsBytes;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct IgvmParamPage {
    pub cpu_count: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, AsBytes)]
pub struct IgvmParamBlock {
    /// The total size of the parameter area, beginning with the parameter
    /// block itself and including any additional parameter pages which follow.
    pub param_area_size: u32,

    /// The offset, in bytes, from the base of the parameter block to the base
    /// of the parameter page.
    pub param_page_offset: u32,

    /// The offset, in bytes, from the base of the parameter block to the base
    /// of the memory map (which is in IGVM format).
    pub memory_map_offset: u32,

    /// The guest physical address of the CPUID page.
    pub cpuid_page: u32,

    /// The guest physical address of the secrets page.
    pub secrets_page: u32,
    pub memory_map: u32,
    pub launch_fw: u8,
    pub _reserved: [u8; 3],
    pub kernel_size: u32,

    /// The guest physical address of the base of the kernel memory region.
    pub kernel_base: u64,

    pub stage2_size: u32,
    pub stage2_base: u64,
    pub fs_size: u32,
    pub fs_base: u64,
}
