// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

use clap::{Parser, ValueEnum};
use igvm::snp_defs::{SevFeatures, SevVmsa};
use igvm::{IgvmDirectiveHeader, IgvmFile, IgvmPlatformHeader, IgvmRevision};
use igvm_defs::{
    IgvmPageDataFlags, IgvmPageDataType, IgvmPlatformType, IGVM_VHS_PARAMETER,
    IGVM_VHS_PARAMETER_INSERT, IGVM_VHS_SUPPORTED_PLATFORM, PAGE_SIZE_4K,
};
use igvm_params::{IgvmParamBlock, IgvmParamBlockFwInfo};
use ovmfmeta::parse_ovmf_metadata;
use std::cmp;
use std::error::Error;
use std::fs::metadata;
use std::io::Write;
use std::mem::size_of;
use std::process::exit;
use std::{fs::File, io::Read};
use zerocopy::AsBytes;
use zerocopy::FromZeroes;

mod gdt;
mod igvm_params;
mod ovmfmeta;
mod pagetable;
mod vpcontext;

const COMPATIBILITY_MASK: u32 = 1;

const SECRETS_PAGE: u32 = 0x9e000;
const CPUID_PAGE: u32 = 0x9f000;

// Parameter area indices
const IGVM_GENERAL_PARAMS_PA: u32 = 0;
const IGVM_MEMORY_MAP_PA: u32 = 1;

#[derive(Parser, Debug)]
struct Args {
    /// Stage 2 binary file
    #[arg(short, long)]
    stage2: String,

    /// Kernel elf file
    #[arg(short, long)]
    kernel: String,

    /// Optional filesystem image
    #[arg(long)]
    filesystem: Option<String>,

    /// Optional firmware file, e.g. OVMF.fd
    #[arg(short, long)]
    firmware: Option<String>,

    /// Output filename for the generated IGVM file
    #[arg(short, long)]
    output: String,

    /// COM port to use for the SVSM console. Valid values are 1-4
    #[arg(short, long, default_value_t = 1, value_parser = clap::value_parser!(i32).range(1..=4))]
    comport: i32,

    /// Hypervisor to generate IGVM file for
    #[arg(value_enum)]
    hypervisor: Hypervisor,

    /// Print verbose output
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Hypervisor {
    /// Build an IGVM file compatible with QEMU
    QEMU,

    /// Build an IGVM file compatible with Hyper-V
    HyperV,
}

#[repr(C, packed(1))]
#[derive(AsBytes)]
struct Stage2Stack {
    pub kernel_start: u32,
    pub kernel_end: u32,
    pub filesystem_start: u32,
    pub filesystem_end: u32,
    pub igvm_param_block: u32,
    pub reserved: u32,
}

fn port_address(port: i32) -> u16 {
    match port {
        1 => 0x3f8,
        2 => 0x2f8,
        3 => 0x3e8,
        4 => 0x2e8,
        _ => 0,
    }
}

fn new_platform(compatibility_mask: u32, platform_type: IgvmPlatformType) -> IgvmPlatformHeader {
    IgvmPlatformHeader::SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM {
        compatibility_mask,
        highest_vtl: 0,
        platform_type,
        platform_version: 1,
        shared_gpa_boundary: 0,
    })
}

fn new_page_data(gpa: u64, compatibility_mask: u32, data: Vec<u8>) -> IgvmDirectiveHeader {
    IgvmDirectiveHeader::PageData {
        gpa,
        compatibility_mask,
        flags: IgvmPageDataFlags::new(),
        data_type: IgvmPageDataType::NORMAL,
        data,
    }
}

fn default_param_block(args: &Args) -> IgvmParamBlock {
    let param_page_offset = PAGE_SIZE_4K as u32;
    let memory_map_offset = param_page_offset + PAGE_SIZE_4K as u32;
    let memory_map_end_offset = memory_map_offset + PAGE_SIZE_4K as u32;

    IgvmParamBlock {
        param_area_size: memory_map_end_offset,
        param_page_offset,
        memory_map_offset,
        guest_context_offset: 0,
        cpuid_page: CPUID_PAGE,
        secrets_page: SECRETS_PAGE,
        debug_serial_port: port_address(args.comport),
        _reserved: [0u16; 3],
        firmware: IgvmParamBlockFwInfo::default(),
        kernel_reserved_size: 0,
        kernel_size: 0,
        kernel_base: 0,
        vtom: 0,
    }
}

fn construct_initial_vmsa(args: &Args, start_gpa: u64, directives: &mut Vec<IgvmDirectiveHeader>) {
    let mut vmsa_box = SevVmsa::new_box_zeroed();
    let vmsa = vmsa_box.as_mut();

    // Establish CS as a 32-bit code selector.
    vmsa.cs.attrib = 0xc9b;
    vmsa.cs.limit = 0xffffffff;
    vmsa.cs.selector = 0x08;

    // Establish all data segments as generic data selectors.
    vmsa.ds.attrib = 0xa93;
    vmsa.ds.limit = 0xffffffff;
    vmsa.ds.selector = 0x10;
    vmsa.ss = vmsa.ds;
    vmsa.es = vmsa.ds;
    vmsa.fs = vmsa.ds;
    vmsa.gs = vmsa.ds;

    // EFER.SVME.
    vmsa.efer = 0x1000;

    // CR0.PE | CR0.NE.
    vmsa.cr0 = 0x21;

    // CR4.MCE.
    vmsa.cr4 = 0x40;

    vmsa.pat = 0x0007040600070406;
    vmsa.xcr0 = 1;
    vmsa.rflags = 2;
    vmsa.rip = 0x10000;
    vmsa.rsp = vmsa.rip - size_of::<Stage2Stack>() as u64;

    let mut features = SevFeatures::new();
    features.set_snp(true);
    features.set_restrict_injection(true);
    vmsa.sev_features = features;

    directives.push(IgvmDirectiveHeader::SnpVpContext {
        gpa: start_gpa,
        compatibility_mask: COMPATIBILITY_MASK,
        vp_index: 0,
        vmsa: vmsa_box,
    });

    if args.verbose {
        println!(
            "{:#010x}-{:#010x} VMSA",
            start_gpa,
            start_gpa + PAGE_SIZE_4K
        );
    }
}

fn construct_empty_pages(
    args: &Args,
    start_gpa: u64,
    size: u64,
    data_type: IgvmPageDataType,
    directives: &mut Vec<IgvmDirectiveHeader>,
    description: &str,
) {
    if args.verbose {
        println!(
            "{:#010x}-{:#010x} \"{}\" empty data",
            start_gpa,
            start_gpa + size,
            description
        );
    }
    for gpa in (start_gpa..(start_gpa + size)).step_by(PAGE_SIZE_4K as usize) {
        directives.push(IgvmDirectiveHeader::PageData {
            gpa,
            compatibility_mask: COMPATIBILITY_MASK,
            flags: IgvmPageDataFlags::new(),
            data_type,
            data: vec![],
        });
    }
}

fn construct_data_pages(
    args: &Args,
    start_gpa: u64,
    data: &[u8],
    directives: &mut Vec<IgvmDirectiveHeader>,
    description: &str,
) {
    if args.verbose {
        println!(
            "{:#010x}-{:#010x} \"{}\" mem data",
            start_gpa,
            start_gpa + data.len() as u64,
            description
        );
    }
    for offset in (0..data.len()).step_by(PAGE_SIZE_4K as usize) {
        let page = data[offset..(offset + PAGE_SIZE_4K as usize)].to_vec();
        directives.push(IgvmDirectiveHeader::PageData {
            gpa: start_gpa + offset as u64,
            compatibility_mask: COMPATIBILITY_MASK,
            flags: IgvmPageDataFlags::new(),
            data_type: IgvmPageDataType::NORMAL,
            data: page,
        });
    }
}

fn construct_data_pages_from_file(
    args: &Args,
    path: &String,
    gpa_base: u64,
    directives: &mut Vec<IgvmDirectiveHeader>,
) -> u64 {
    let mut gpa = gpa_base;
    let mut in_file = File::open(path).expect("Could not open input file");
    let mut buf = vec![0; 4096];

    while let Ok(len) = in_file.read(&mut buf) {
        if len == 0 {
            break;
        }
        directives.push(new_page_data(gpa, 1, buf));
        gpa += PAGE_SIZE_4K;
        buf = vec![0; 4096];
    }
    if args.verbose {
        println!("{:#010x}-{:#010x} \"{}\" file data", gpa_base, gpa, path);
    }
    gpa - gpa_base
}

fn construct_firmware_pages(
    args: &Args,
    param_block: &mut IgvmParamBlock,
    directives: &mut Vec<IgvmDirectiveHeader>,
) -> Result<(), Box<dyn Error>> {
    if let Some(firmware) = &args.firmware {
        match args.hypervisor {
            Hypervisor::QEMU => {
                parse_ovmf_metadata(firmware, &mut param_block.firmware)?;
                // OVMF must be located to end at 4GB.
                let len = metadata(firmware)?.len() as usize;
                if len > 0xffffffff {
                    return Err("OVMF firmware is too large".into());
                }
                param_block.firmware.start = (0xffffffff - len + 1) as u32;
                param_block.firmware.size = len as u32;
                construct_data_pages_from_file(
                    args,
                    firmware,
                    param_block.firmware.start as u64,
                    directives,
                );
            }
            Hypervisor::HyperV => todo!(),
        }
    }
    Ok(())
}

fn construct_param_block(
    args: &Args,
    gpa: u64,
    param_block: &IgvmParamBlock,
    directives: &mut Vec<IgvmDirectiveHeader>,
) -> Result<u64, Box<dyn Error>> {
    // The param block contents are complete now. Populate the data page.
    let param_block_data = unsafe {
        let ptr = param_block as *const IgvmParamBlock as *const [u8; size_of::<IgvmParamBlock>()];
        &*ptr
    };
    if param_block_data.len() > PAGE_SIZE_4K as usize {
        return Err("IGVM parameter block size exceeds 4K".into());
    }
    let mut param_block_page = [0u8; PAGE_SIZE_4K as usize];
    param_block_page[..param_block_data.len()].clone_from_slice(param_block_data);
    construct_data_pages(
        args,
        gpa,
        &param_block_page,
        directives,
        "IGVM parameter block",
    );
    Ok(PAGE_SIZE_4K)
}

fn construct_parameter_page(
    args: &Args,
    gpa: u64,
    parameter_area_index: u32,
    directive: &mut Vec<IgvmDirectiveHeader>,
    description: &str,
) {
    let param_area = IgvmDirectiveHeader::ParameterArea {
        number_of_bytes: PAGE_SIZE_4K,
        parameter_area_index,
        initial_data: vec![],
    };
    let mm = IgvmDirectiveHeader::MemoryMap(IGVM_VHS_PARAMETER {
        parameter_area_index,
        byte_offset: 0,
    });
    let param_insert = IgvmDirectiveHeader::ParameterInsert(IGVM_VHS_PARAMETER_INSERT {
        gpa,
        compatibility_mask: 1,
        parameter_area_index,
    });

    // Order is important here. You need to declare the area, populate it
    // then insert it.
    directive.push(param_area);
    directive.push(mm);
    directive.push(param_insert);

    if args.verbose {
        println!(
            "{:#010x}-{:#010x} {} parameter",
            gpa,
            gpa + PAGE_SIZE_4K,
            description
        );
    }
}

fn print_fw_metadata(args: &Args, param_block: &IgvmParamBlock) {
    if args.verbose {
        println!("  firmware");
        println!("    start: {:#X}", param_block.firmware.start);
        println!("    size: {:#X}", param_block.firmware.size);
        println!("    secrets_page: {:#X}", param_block.firmware.secrets_page);
        println!("    caa_page: {:#X}", param_block.firmware.caa_page);
        println!("    cpuid_page: {:#X}", param_block.firmware.cpuid_page);
        println!("    reset_addr: {:#X}", param_block.firmware.reset_addr);
        println!(
            "    prevalidated_count: {:#X}",
            param_block.firmware.prevalidated_count
        );
        for i in 0..param_block.firmware.prevalidated_count as usize {
            println!(
                "      prevalidate[{}].base: {:#X}",
                i, param_block.firmware.prevalidated[i].base
            );
            println!(
                "      prevalidate[{}].size: {:#X}",
                i, param_block.firmware.prevalidated[i].size
            );
        }
    }
}

fn print_param_block(args: &Args, param_block: &IgvmParamBlock) {
    if args.verbose {
        println!("igvm_parameter_block:");
        println!("  param_area_size: {:#X}", param_block.param_area_size);
        println!("  param_page_offset: {:#X}", param_block.param_page_offset);
        println!("  memory_map_offset: {:#X}", param_block.memory_map_offset);
        println!(
            "  guest_context_offset: {:#X}",
            param_block.guest_context_offset
        );
        println!("  cpuid_page: {:#X}", param_block.cpuid_page);
        println!("  secrets_page: {:#X}", param_block.secrets_page);
        println!("  debug_serial_port: {:#X}", param_block.debug_serial_port);
        println!("  _reserved[3]: {:#X?}", param_block._reserved);
        print_fw_metadata(args, param_block);
        println!(
            "  kernel_reserved_size: {:#X}",
            param_block.kernel_reserved_size
        );
        println!("  kernel_size: {:#X}", param_block.kernel_size);
        println!("  kernel_base: {:#X}", param_block.kernel_base);
        println!("  vtom: {:#X}", param_block.vtom);
    }
}

fn create_igvm(args: &Args) -> Result<(), Box<dyn Error>> {
    let mut directives: Vec<IgvmDirectiveHeader> = vec![];
    let mut param_block = default_param_block(args);

    // This creates a file with the following guest memory layout:
    //   0x000000-0x00EFFF: zero-filled (must be pre-validated)
    //   0x00F000-0x00FFFF: initial stage 2 stack page
    //   0x010000-0x0nnnnn: stage 2 image
    //   0x0nnnnn-0x09DFFF: zero-filled (must be pre-validated)
    //   0x09E000-0x09EFFF: Secrets page
    //   0x09F000-0x09FFFF: CPUID page
    //   0x100000-0x1nnnnn: kernel
    //   0x1nnnnn-0x1nnnnn: filesystem
    //   0x1nnnnn-0x1nnnnn: IGVM parameter block
    //   0x1nnnnn-0x1nnnnn: general and memory map parameter pages
    //   0xFFnn0000-0xFFFFFFFF: OVMF firmware (QEMU only, if specified)
    construct_empty_pages(
        args,
        0x00000,
        0xf000,
        IgvmPageDataType::NORMAL,
        &mut directives,
        "Low memory",
    );

    // Construct a data object for the stage 2 image.  Stage 2 is always
    // loaded at 64K.
    let stage2_size = construct_data_pages_from_file(args, &args.stage2, 0x10000, &mut directives);
    let mut address = 0x10000 + stage2_size;
    match address.cmp(&0x9e000) {
        cmp::Ordering::Greater => {
            eprintln!("stage 2 image is too large");
            exit(1);
        }
        cmp::Ordering::Less => {
            construct_empty_pages(
                args,
                address,
                0x9e000 - address,
                IgvmPageDataType::NORMAL,
                &mut directives,
                "Stage 2 free space",
            );
        }
        cmp::Ordering::Equal => {}
    }

    // Allocate a page to hold the secrets page.  This is not considered part
    // of the IGVM data.
    construct_empty_pages(
        args,
        0x9e000,
        PAGE_SIZE_4K,
        IgvmPageDataType::SECRETS,
        &mut directives,
        "Secrets page",
    );

    // Allocate the CPUID page
    construct_empty_pages(
        args,
        0x9f000,
        PAGE_SIZE_4K,
        IgvmPageDataType::CPUID_DATA,
        &mut directives,
        "CPUID page",
    );

    // Plan to load the kernel image at a base address of 1 MB unless it must
    // be relocated due to firmware.
    address = 1 << 20;

    // TODO: Read Hyper-V firmware

    // Construct data for the kernel.
    let kernel_address = address;
    let kernel_size =
        construct_data_pages_from_file(args, &args.kernel, kernel_address, &mut directives);
    address += kernel_size;

    // If a filesystem image is present, then load it after the kernel.  It is
    // rounded up to the next page boundary to avoid overlapping with any of
    // the pages in the kernel data object.
    let filesystem_address = address;
    let filesystem_size = if let Some(filesystem) = &args.filesystem {
        construct_data_pages_from_file(args, filesystem, address, &mut directives)
    } else {
        0
    };
    address += filesystem_size;
    let igvm_parameter_block_address = address;

    // Construct the initial stack contents.
    let stage2_stack = Stage2Stack {
        kernel_start: kernel_address as u32,
        kernel_end: (kernel_address + kernel_size) as u32,
        filesystem_start: filesystem_address as u32,
        filesystem_end: (filesystem_address + filesystem_size) as u32,
        igvm_param_block: igvm_parameter_block_address as u32,
        reserved: 0,
    };
    let mut stage2_stack_data = stage2_stack.as_bytes().to_vec();
    let mut stage2_stack_page = vec![0u8; PAGE_SIZE_4K as usize - stage2_stack_data.len()];
    stage2_stack_page.append(&mut stage2_stack_data);
    construct_data_pages(
        args,
        0x00F000,
        stage2_stack_page.as_bytes(),
        &mut directives,
        "Stage 2 stack",
    );

    match args.hypervisor {
        Hypervisor::QEMU => {
            // Place the kernel area at 512 GB with a size of 16 MB.
            param_block.kernel_base = 0x0000008000000000;
            param_block.kernel_size = 0x01000000;
        }
        Hypervisor::HyperV => {
            // Place the kernel area at 64 MB with a size of 16 MB.
            param_block.kernel_base = 0x04000000;
            param_block.kernel_size = 0x01000000;

            // TODO: Fix these lines
            /*
            if fw_info.fw_info.size != 0 {
                // Mark the range between the top of the stage 2 area and the base
                // of memory as a range that needs to be validated.
                param_block.firmware.prevalidated_count = 1;
                param_block.firmware.prevalidated[0].base = 0xA0000;
                param_block.firmware.prevalidated[0].size = fw_info.fw_info.start - 0xA0000;

                igvm_parameter_block->firmware = fw_info.fw_info;
                igvm_parameter_block->vtom = fw_info.vtom;
            } else {
                // Set the shared GPA boundary at bit 46, below the lowest possible
                // C-bit position.
                param_block.vtom = 0x0000400000000000;
            }

            platform->SharedGpaBoundary = igvm_parameter_block->vtom;
            */
        }
    }

    construct_firmware_pages(args, &mut param_block, &mut directives)?;

    // Place the VMSA at the base of the kernel region and mark that page
    // as reserved.
    let vmsa_address = param_block.kernel_base;
    param_block.kernel_reserved_size = PAGE_SIZE_4K as u32;
    construct_initial_vmsa(args, vmsa_address, &mut directives);

    // The param block contents are complete now. Populate the data page.
    let _ = construct_param_block(args, address, &param_block, &mut directives)?;

    // General and memory map parameters
    construct_parameter_page(
        args,
        address + param_block.param_page_offset as u64,
        IGVM_GENERAL_PARAMS_PA,
        &mut directives,
        "General parameters",
    );
    construct_parameter_page(
        args,
        address + param_block.memory_map_offset as u64,
        IGVM_MEMORY_MAP_PA,
        &mut directives,
        "Memory map",
    );
    print_param_block(args, &param_block);

    let file = IgvmFile::new(
        IgvmRevision::V1,
        vec![new_platform(0x1, IgvmPlatformType::SEV_SNP)],
        vec![],
        directives,
    )
    .expect("Failed to create file");
    let mut binary_file = Vec::new();
    file.serialize(&mut binary_file).unwrap();

    let mut file = File::create(&args.output).expect("Could not open file");
    file.write_all(binary_file.as_slice())
        .expect("Failed to write file");

    Ok(())
}

fn main() {
    let args = Args::parse();
    let _ = create_igvm(&args);
}
