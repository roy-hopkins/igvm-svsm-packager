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
use std::error::Error;
use std::fs::metadata;
use std::io::Write;
use std::mem::size_of;
use std::process::exit;
use std::{cmp, vec};
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

struct DirectiveEntry {
    gpa_start: u64,
    gpa_end: u64,
    directives: Vec<IgvmDirectiveHeader>,
    description: String,
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

fn construct_initial_vmsa(gpa_start: u64) -> Result<DirectiveEntry, Box<dyn Error>> {
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

    let directives = vec![IgvmDirectiveHeader::SnpVpContext {
        gpa: gpa_start,
        compatibility_mask: COMPATIBILITY_MASK,
        vp_index: 0,
        vmsa: vmsa_box,
    }];

    Ok(DirectiveEntry {
        gpa_start,
        gpa_end: gpa_start + PAGE_SIZE_4K,
        directives,
        description: "VMSA".into(),
    })
}

fn fill_cpuid_page() {}

fn construct_empty_pages(
    gpa_start: u64,
    size: u64,
    data_type: IgvmPageDataType,
    description: &str,
) -> Result<DirectiveEntry, Box<dyn Error>> {
    let mut directives = Vec::<IgvmDirectiveHeader>::new();
    for gpa in (gpa_start..(gpa_start + size)).step_by(PAGE_SIZE_4K as usize) {
        directives.push(IgvmDirectiveHeader::PageData {
            gpa,
            compatibility_mask: COMPATIBILITY_MASK,
            flags: IgvmPageDataFlags::new(),
            data_type,
            data: vec![],
        });
    }
    Ok(DirectiveEntry {
        gpa_start,
        gpa_end: gpa_start + size,
        directives,
        description: description.into(),
    })
}

fn construct_data_pages_from_file(
    path: &String,
    gpa_start: u64,
) -> Result<DirectiveEntry, Box<dyn Error>> {
    let mut gpa = gpa_start;
    let mut in_file = File::open(path).expect("Could not open input file");
    let mut buf = vec![0; 4096];

    let mut directives = Vec::<IgvmDirectiveHeader>::new();
    while let Ok(len) = in_file.read(&mut buf) {
        if len == 0 {
            break;
        }
        directives.push(new_page_data(gpa, 1, buf));
        gpa += PAGE_SIZE_4K;
        buf = vec![0; 4096];
    }
    Ok(DirectiveEntry {
        gpa_start,
        gpa_end: gpa,
        directives,
        description: path.to_string(),
    })
}

fn construct_firmware_pages(
    args: &Args,
    param_block: &mut IgvmParamBlock,
) -> Result<Option<DirectiveEntry>, Box<dyn Error>> {
    let directive = if let Some(firmware) = &args.firmware {
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
                Some(construct_data_pages_from_file(
                    firmware,
                    param_block.firmware.start as u64,
                )?)
            }
            Hypervisor::HyperV => return Err("Hyper-V firmware not yet implemented".into()),
        }
    } else {
        None
    };
    Ok(directive)
}

fn construct_placeholder(gpa: u64, description: &str) -> Result<DirectiveEntry, Box<dyn Error>> {
    Ok(DirectiveEntry {
        gpa_start: gpa,
        gpa_end: gpa + PAGE_SIZE_4K,
        directives: vec![],
        description: description.into(),
    })
}

fn populate_param_block(
    param_block: &IgvmParamBlock,
    entry: &mut DirectiveEntry,
) -> Result<(), Box<dyn Error>> {
    let param_block_data = unsafe {
        let ptr = param_block as *const IgvmParamBlock as *const [u8; size_of::<IgvmParamBlock>()];
        &*ptr
    };
    if param_block_data.len() > PAGE_SIZE_4K as usize {
        return Err("IGVM parameter block size exceeds 4K".into());
    }
    let mut param_block_page = [0u8; PAGE_SIZE_4K as usize];
    param_block_page[..param_block_data.len()].clone_from_slice(param_block_data);

    entry.directives.push(IgvmDirectiveHeader::PageData {
        gpa: entry.gpa_start,
        compatibility_mask: COMPATIBILITY_MASK,
        flags: IgvmPageDataFlags::new(),
        data_type: IgvmPageDataType::NORMAL,
        data: param_block_page.to_vec(),
    });

    Ok(())
}

fn populate_stage2_stack(
    stage2_stack: &Stage2Stack,
    entry: &mut DirectiveEntry,
) -> Result<(), Box<dyn Error>> {
    let mut stage2_stack_data = stage2_stack.as_bytes().to_vec();
    let mut stage2_stack_page = vec![0u8; PAGE_SIZE_4K as usize - stage2_stack_data.len()];
    stage2_stack_page.append(&mut stage2_stack_data);

    if stage2_stack_page.len() > PAGE_SIZE_4K as usize {
        return Err("Stage 2 stack size exceeds 4K".into());
    }

    entry.directives.push(IgvmDirectiveHeader::PageData {
        gpa: entry.gpa_start,
        compatibility_mask: COMPATIBILITY_MASK,
        flags: IgvmPageDataFlags::new(),
        data_type: IgvmPageDataType::NORMAL,
        data: stage2_stack_page,
    });

    Ok(())
}

fn construct_memory_map_parameter_page(
    gpa: u64,
    parameter_area_index: u32,
    description: &str,
) -> Result<DirectiveEntry, Box<dyn Error>> {
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
        compatibility_mask: COMPATIBILITY_MASK,
        parameter_area_index,
    });

    // Order of the directives is important here. You need to declare the area, populate it
    // then insert it.
    Ok(DirectiveEntry {
        gpa_start: gpa,
        gpa_end: gpa + PAGE_SIZE_4K,
        directives: vec![param_area, mm, param_insert],
        description: description.into(),
    })
}

fn construct_general_parameter_page(
    gpa: u64,
    parameter_area_index: u32,
    description: &str,
) -> Result<DirectiveEntry, Box<dyn Error>> {
    let param_area = IgvmDirectiveHeader::ParameterArea {
        number_of_bytes: 0x1000,
        parameter_area_index: IGVM_GENERAL_PARAMS_PA,
        initial_data: vec![],
    };
    let vp_count = IgvmDirectiveHeader::VpCount(IGVM_VHS_PARAMETER {
        parameter_area_index: IGVM_GENERAL_PARAMS_PA,
        byte_offset: 0,
    });
    let shared = IgvmDirectiveHeader::EnvironmentInfo(IGVM_VHS_PARAMETER {
        parameter_area_index: IGVM_GENERAL_PARAMS_PA,
        byte_offset: 4,
    });
    let param_insert = IgvmDirectiveHeader::ParameterInsert(IGVM_VHS_PARAMETER_INSERT {
        gpa,
        compatibility_mask: COMPATIBILITY_MASK,
        parameter_area_index: IGVM_GENERAL_PARAMS_PA,
    });

    // Order of the directives is important here. You need to declare the area, populate it
    // then insert it.
    Ok(DirectiveEntry {
        gpa_start: gpa,
        gpa_end: gpa + PAGE_SIZE_4K,
        directives: vec![param_area, vp_count, shared, param_insert],
        description: description.into(),
    })
}

fn construct_required_memory(
    param_block: &IgvmParamBlock,
) -> Result<DirectiveEntry, Box<dyn Error>> {
    let required_memory = IgvmDirectiveHeader::RequiredMemory {
        gpa: param_block.kernel_base,
        compatibility_mask: COMPATIBILITY_MASK,
        number_of_bytes: param_block.kernel_size,
        vtl2_protectable: false,
    };

    // Order of the directives is important here. You need to declare the area, populate it
    // then insert it.
    Ok(DirectiveEntry {
        gpa_start: param_block.kernel_base,
        gpa_end: param_block.kernel_base + param_block.kernel_size as u64,
        directives: vec![required_memory],
        description: "Kernel memory".into(),
    })
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

fn build_directives(
    args: &Args,
    directives: &mut Vec<DirectiveEntry>,
) -> Result<(), Box<dyn Error>> {
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
    directives.push(construct_empty_pages(
        0x00000,
        0xf000,
        IgvmPageDataType::NORMAL,
        "Low memory",
    )?);

    // Create a placeholder for the Stage 2 stack page
    directives.push(construct_placeholder(0x00F000, "Stage 2 stack")?);
    let stage2_stack_index = directives.len() - 1;

    // Construct a data object for the stage 2 image.  Stage 2 is always
    // loaded at 64K.
    let stage2_entry = construct_data_pages_from_file(&args.stage2, 0x10000)?;
    let stage2_size = stage2_entry.gpa_end - stage2_entry.gpa_start;
    directives.push(stage2_entry);
    let mut address = 0x10000 + stage2_size;
    match address.cmp(&0x9e000) {
        cmp::Ordering::Greater => {
            eprintln!("stage 2 image is too large");
            exit(1);
        }
        cmp::Ordering::Less => {
            directives.push(construct_empty_pages(
                address,
                0x9e000 - address,
                IgvmPageDataType::NORMAL,
                "Stage 2 free space",
            )?);
        }
        cmp::Ordering::Equal => {}
    }

    // Allocate a page to hold the secrets page.  This is not considered part
    // of the IGVM data.
    directives.push(construct_empty_pages(
        0x9e000,
        PAGE_SIZE_4K,
        IgvmPageDataType::SECRETS,
        "Secrets page",
    )?);

    // Allocate the CPUID page
    directives.push(construct_empty_pages(
        0x9f000,
        PAGE_SIZE_4K,
        IgvmPageDataType::CPUID_DATA,
        "CPUID page",
    )?);

    // Plan to load the kernel image at a base address of 1 MB unless it must
    // be relocated due to firmware.
    address = 1 << 20;

    // TODO: Read Hyper-V firmware

    // Construct data for the kernel.
    let kernel_address = address;
    let kernel_entry = construct_data_pages_from_file(&args.kernel, kernel_address)?;
    let kernel_size = kernel_entry.gpa_end - kernel_entry.gpa_start;
    address += kernel_size;
    directives.push(kernel_entry);

    // If a filesystem image is present, then load it after the kernel.  It is
    // rounded up to the next page boundary to avoid overlapping with any of
    // the pages in the kernel data object.
    let filesystem_address = address;
    let filesystem_size = if let Some(filesystem) = &args.filesystem {
        let fs_entry = construct_data_pages_from_file(filesystem, address)?;
        let fs_size = fs_entry.gpa_end - fs_entry.gpa_start;
        directives.push(fs_entry);
        fs_size
    } else {
        0
    };
    address += filesystem_size;
    let igvm_parameter_block_address = address;

    // Add a placeholder for the parameter block. We populate the contents later.
    directives.push(construct_placeholder(address, "IGVM Parameter block")?);
    let param_block_index = directives.len() - 1;

    // General and memory map parameters
    directives.push(construct_general_parameter_page(
        address + param_block.param_page_offset as u64,
        IGVM_GENERAL_PARAMS_PA,
        "General parameters",
    )?);
    directives.push(construct_memory_map_parameter_page(
        address + param_block.memory_map_offset as u64,
        IGVM_MEMORY_MAP_PA,
        "Memory map",
    )?);

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

    if let Some(fw_entry) = construct_firmware_pages(args, &mut param_block)? {
        directives.push(fw_entry);
    }

    directives.push(construct_required_memory(&param_block)?);

    // Place the VMSA at the base of the kernel region and mark that page
    // as reserved.
    let vmsa_address = param_block.kernel_base;
    param_block.kernel_reserved_size = PAGE_SIZE_4K as u32;
    directives.push(construct_initial_vmsa(vmsa_address)?);

    // Populate the param block and stack contents that we created placeholders for
    populate_param_block(&param_block, directives.get_mut(param_block_index).unwrap())?;

    let stage2_stack = Stage2Stack {
        kernel_start: kernel_address as u32,
        kernel_end: (kernel_address + kernel_size) as u32,
        filesystem_start: filesystem_address as u32,
        filesystem_end: (filesystem_address + filesystem_size) as u32,
        igvm_param_block: igvm_parameter_block_address as u32,
        reserved: 0,
    };
    populate_stage2_stack(
        &stage2_stack,
        directives.get_mut(stage2_stack_index).unwrap(),
    )?;

    print_param_block(args, &param_block);
    Ok(())
}

fn create_igvm(args: &Args) -> Result<(), Box<dyn Error>> {
    let mut entries: Vec<DirectiveEntry> = vec![];
    let mut directives: Vec<IgvmDirectiveHeader> = vec![];
    build_directives(args, &mut entries)?;

    for mut entry in entries {
        if args.verbose {
            if entry.gpa_start != entry.gpa_end {
                println!(
                    "{:#010x}-{:#010x} {}",
                    entry.gpa_start, entry.gpa_end, entry.description
                );
            } else {
                println!("{}", entry.description);
            }
        }
        directives.append(&mut entry.directives)
    }

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
