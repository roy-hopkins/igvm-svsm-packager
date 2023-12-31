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

    /// The guest physical address of the start of the guest firmware. The
    /// permissions on the pages in the firmware range are adjusted to the guest
    /// VMPL.
    pub fw_start: u32,

    /// The number of pages of guest firmware. If the firmware size is zero then
    /// no firmware is launched after initialization is complete.
    pub fw_size: u32,

    /// The number of bytes in the kernel memory region.
    pub kernel_size: u32,

    /// The guest physical address of the base of the kernel memory region.
    pub kernel_base: u64,

    pub stage2_size: u32,
    pub stage2_base: u64,
    pub fs_size: u32,
    pub fs_base: u64,
}
