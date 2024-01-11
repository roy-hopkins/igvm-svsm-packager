// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

use igvm::{IgvmDirectiveHeader, IgvmFile, IgvmPlatformHeader, IgvmRevision};
use igvm_defs::{
    IgvmPageDataFlags, IgvmPageDataType, IgvmPlatformType, IGVM_VHS_PARAMETER,
    IGVM_VHS_PARAMETER_INSERT, IGVM_VHS_SUPPORTED_PLATFORM, PAGE_SIZE_4K,
};
use igvm_param_defs::IgvmParamBlock;
use std::{
    env,
    fs::File,
    io::{Read, Write},
};
use vpcontext::new_vp_context_32;
use zerocopy::AsBytes;

mod gdt;
mod igvm_param_defs;
mod pagetable;
mod vpcontext;

const KERNEL_BASE: u64 = 0xff000000;

const SVSM_BASE: u64 = 0x10000;
const SVSM_STACK: u64 = SVSM_BASE;

const OVMF_CODE_TOP: u64 = 0x100000000;

const CPUID_PAGE: u32 = 636 * 1024;
const SECRETS_PAGE: u32 = 632 * 1024;
const KERNEL_REGION_BASE: u64 = 512 * (1u64 << 30);
const KERNEL_REGION_SIZE: u64 = 256 * (1u64 << 20);

// Parameter area indices
const IGVM_MEMORY_MAP_PA: u32 = 1;
const IGVM_HV_PARAMS_PA: u32 = 2;

#[repr(C)]
#[derive(AsBytes)]
struct SvsmHeap {
    pub base: u64,
    pub size: u64,
}

#[repr(C, packed(1))]
#[derive(Default)]
struct VmcbSeg {
    pub selector: u64,
    pub attrib: u16,
    pub limit: u32,
    pub base: u64,
}

#[repr(C, packed(1))]
struct VmcbSaveArea {
    es: VmcbSeg,
    cs: VmcbSeg,
    ss: VmcbSeg,
    ds: VmcbSeg,
    fs: VmcbSeg,
    gs: VmcbSeg,
    gdtr: VmcbSeg,
    ldtr: VmcbSeg,
    idtr: VmcbSeg,
    tr: VmcbSeg,
    reserved_1: [u8; 43],
    cpl: u8,
    reserved_2: [u8; 4],
    efer: u64,
    reserved_3: [u8; 112],
    cr4: u64,
    cr3: u64,
    cr0: u64,
    dr7: u64,
    dr6: u64,
    rflags: u64,
    rip: u64,
    reserved_4: [u8; 88],
    rsp: u64,
    reserved_5: [u8; 24],
    rax: u64,
    star: u64,
    lstar: u64,
    cstar: u64,
    sfmask: u64,
    kernel_gs_base: u64,
    sysenter_cs: u64,
    sysenter_esp: u64,
    sysenter_eip: u64,
    cr2: u64,
    reserved_6: [u8; 32],
    g_pat: u64,
    dbgctl: u64,
    br_from: u64,
    bro: u64,
    last_excp_from: u64,
    last_excp_to: u64,
}

impl Default for VmcbSaveArea {
    fn default() -> Self {
        Self {
            es: Default::default(),
            cs: Default::default(),
            ss: Default::default(),
            ds: Default::default(),
            fs: Default::default(),
            gs: Default::default(),
            gdtr: Default::default(),
            ldtr: Default::default(),
            idtr: Default::default(),
            tr: Default::default(),
            reserved_1: [0; 43],
            cpl: Default::default(),
            reserved_2: Default::default(),
            efer: Default::default(),
            reserved_3: [0; 112],
            cr4: Default::default(),
            cr3: Default::default(),
            cr0: Default::default(),
            dr7: Default::default(),
            dr6: Default::default(),
            rflags: Default::default(),
            rip: Default::default(),
            reserved_4: [0; 88],
            rsp: Default::default(),
            reserved_5: Default::default(),
            rax: Default::default(),
            star: Default::default(),
            lstar: Default::default(),
            cstar: Default::default(),
            sfmask: Default::default(),
            kernel_gs_base: Default::default(),
            sysenter_cs: Default::default(),
            sysenter_esp: Default::default(),
            sysenter_eip: Default::default(),
            cr2: Default::default(),
            reserved_6: Default::default(),
            g_pat: Default::default(),
            dbgctl: Default::default(),
            br_from: Default::default(),
            bro: Default::default(),
            last_excp_from: Default::default(),
            last_excp_to: Default::default(),
        }
    }
}

fn report_range(desc: &str, gpa: u64, pages: u32) {
    println!("Added pages: {} gpa: {:#x} count: {:#x}", desc, gpa, pages);
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

fn add_metadata_pages(params: &IgvmParamBlock, gpa: u64, pages: &mut Vec<IgvmDirectiveHeader>) {
    let flags = IgvmPageDataFlags::new();

    // IGVM Parameters
    pages.push(IgvmDirectiveHeader::PageData {
        gpa,
        compatibility_mask: 1,
        flags,
        data_type: IgvmPageDataType::NORMAL,
        data: params.as_bytes().to_vec(),
    });

    // SEV_DESC_TYPE_SNP_SEC_MEM
    for index in 0..((SVSM_STACK - 0x1000) / PAGE_SIZE_4K) {
        pages.push(IgvmDirectiveHeader::PageData {
            gpa: index * PAGE_SIZE_4K,
            compatibility_mask: 1,
            flags,
            data_type: IgvmPageDataType::NORMAL,
            data: vec![],
        });
    }
    for index in ((params.stage2_base + params.stage2_size as u64) / PAGE_SIZE_4K)
        ..(SECRETS_PAGE as u64 / PAGE_SIZE_4K)
    {
        pages.push(IgvmDirectiveHeader::PageData {
            gpa: index * PAGE_SIZE_4K,
            compatibility_mask: 1,
            flags,
            data_type: IgvmPageDataType::NORMAL,
            data: vec![],
        });
    }

    // SEV_DESC_TYPE_SNP_SECRETS
    pages.push(IgvmDirectiveHeader::PageData {
        gpa: SECRETS_PAGE as u64,
        compatibility_mask: 1,
        flags,
        data_type: IgvmPageDataType::SECRETS,
        data: vec![],
    });

    // SEV_DESC_TYPE_CPUID
    pages.push(IgvmDirectiveHeader::PageData {
        gpa: CPUID_PAGE as u64,
        compatibility_mask: 1,
        flags,
        data_type: IgvmPageDataType::CPUID_DATA,
        data: vec![],
    });
}

fn add_stack_page(
    params: &IgvmParamBlock,
    directive: &mut Vec<IgvmDirectiveHeader>,
    kernel_pages: u32,
    params_gpa: u32,
) {
    let mut stack = vec![0; 4096];
    unsafe {
        let p = stack.as_mut_ptr() as *mut u32;
        p.offset(1022).write(params_gpa);
        p.offset(1021).write(params.fs_base as u32 + params.fs_size);
        p.offset(1020).write(params.fs_base as u32);
        p.offset(1019)
            .write(KERNEL_BASE as u32 + kernel_pages * 0x1000);
        p.offset(1018).write(KERNEL_BASE as u32);
    }
    directive.push(new_page_data(SVSM_STACK - 0x1000, 1, stack));
    report_range("stack", SVSM_STACK - 0x1000, 1);
}

fn add_svsm_kernel_region(compatibility_mask: u32, pages: &mut Vec<IgvmDirectiveHeader>) {
    let mut gpa = KERNEL_REGION_BASE;
    let mut flags = IgvmPageDataFlags::new();
    flags.set_is_2mb_page(true);
    flags.set_unmeasured(true);

    while gpa < (KERNEL_REGION_BASE + KERNEL_REGION_SIZE) {
        pages.push(IgvmDirectiveHeader::PageData {
            gpa,
            compatibility_mask,
            flags,
            data_type: IgvmPageDataType::NORMAL,
            data: vec![],
        });
        gpa += 0x200000;
    }
}

fn add_pages_from_file(
    path: &String,
    gpa_base: u64,
    directive: &mut Vec<IgvmDirectiveHeader>,
    align_top: bool,
) -> u32 {
    let mut gpa = gpa_base;
    let mut in_file = File::open(path).expect("Could not open input file");
    let mut buf = vec![0; 4096];
    let mut page_count = 0;

    if align_top {
        let file_length = in_file
            .metadata()
            .expect("Failed to query input file length")
            .len();
        let offset: u64 = (file_length + 0xfff) & !0xfff;
        gpa = gpa_base - offset;
    }

    while let Ok(len) = in_file.read(&mut buf) {
        if len == 0 {
            break;
        }
        directive.push(new_page_data(gpa, 1, buf));
        gpa += PAGE_SIZE_4K;
        buf = vec![0; 4096];
        page_count += 1;
    }
    report_range(
        path.as_str(),
        gpa - (page_count as u64 * 0x1000),
        page_count,
    );
    page_count
}

fn add_memory_map(gpa: u64, directive: &mut Vec<IgvmDirectiveHeader>) {
    let param_area = IgvmDirectiveHeader::ParameterArea {
        number_of_bytes: 0x1000,
        parameter_area_index: IGVM_MEMORY_MAP_PA,
        initial_data: vec![],
    };
    let mm = IgvmDirectiveHeader::MemoryMap(IGVM_VHS_PARAMETER {
        parameter_area_index: IGVM_MEMORY_MAP_PA,
        byte_offset: 0,
    });
    let param_insert = IgvmDirectiveHeader::ParameterInsert(IGVM_VHS_PARAMETER_INSERT {
        gpa,
        compatibility_mask: 1,
        parameter_area_index: IGVM_MEMORY_MAP_PA,
    });

    // Order is important here. You need to declare the area, populate it
    // then insert it.
    directive.push(param_area);
    directive.push(mm);
    directive.push(param_insert);

    report_range("memory map", gpa, 1);
}

fn add_params(gpa: u64, directive: &mut Vec<IgvmDirectiveHeader>) {
    let param_area = IgvmDirectiveHeader::ParameterArea {
        number_of_bytes: 0x1000,
        parameter_area_index: IGVM_HV_PARAMS_PA,
        initial_data: vec![],
    };
    let vp_count = IgvmDirectiveHeader::VpCount(IGVM_VHS_PARAMETER {
        parameter_area_index: IGVM_HV_PARAMS_PA,
        byte_offset: 0,
    });
    let shared = IgvmDirectiveHeader::EnvironmentInfo(IGVM_VHS_PARAMETER {
        parameter_area_index: IGVM_HV_PARAMS_PA,
        byte_offset: 4,
    });
    let param_insert = IgvmDirectiveHeader::ParameterInsert(IGVM_VHS_PARAMETER_INSERT {
        gpa,
        compatibility_mask: 1,
        parameter_area_index: IGVM_HV_PARAMS_PA,
    });

    // Order is important here. You need to declare the area, populate it
    // then insert it.
    directive.push(param_area);
    directive.push(vp_count);
    directive.push(shared);
    directive.push(param_insert);

    report_range("params", gpa, 1);
}

fn create_svsm_igvm(in_path: &str, out_filename: &str) {
    let stage2_path = in_path.to_string() + "/stage2.bin";
    let kernel_path = in_path.to_string() + "/kernel.elf";
    let ramfs_path = in_path.to_string() + "/svsm-fs.bin";
    let ovmf_code_path = in_path.to_string() + "/OVMF_CODE.fd";
    let ovmf_vars_path = in_path.to_string() + "/OVMF_VARS.fd";
    let mut directive: Vec<IgvmDirectiveHeader> = vec![];

    // Populate stage2, the kernel elf and the file system consecutively from
    // the base address.
    let stage2_pages = add_pages_from_file(&stage2_path, SVSM_BASE, &mut directive, false);
    let kernel_pages = add_pages_from_file(&kernel_path, KERNEL_BASE, &mut directive, false);
    let ramfs_base = KERNEL_BASE + kernel_pages as u64 * 0x1000;
    let ramfs_pages = add_pages_from_file(&ramfs_path, ramfs_base, &mut directive, false);
    let mut ovmf_pages = add_pages_from_file(&ovmf_code_path, OVMF_CODE_TOP, &mut directive, true);
    ovmf_pages += add_pages_from_file(
        &ovmf_vars_path,
        OVMF_CODE_TOP - ovmf_pages as u64 * 0x1000,
        &mut directive,
        true,
    );

    // IGVM parameters - hardcoded parameters defined in this file
    let params_base = ramfs_base + ramfs_pages as u64 * 0x1000;
    // Placeholder for the hypervisor to populate the memory map
    let mm_base = params_base + 0x1000;
    // Placeholder for parameters that must be set by the hypervisor
    let hv_params_base = mm_base + 0x1000;

    let params = IgvmParamBlock {
        param_area_size: 3 * 0x1000,
        param_page_offset: 2 * 0x1000,
        memory_map_offset: 0x1000,
        cpuid_page: CPUID_PAGE,
        secrets_page: SECRETS_PAGE,
        fw_start: (OVMF_CODE_TOP - (ovmf_pages as u64 * 0x1000)) as u32,
        fw_size: ovmf_pages,
        kernel_size: KERNEL_REGION_SIZE as u32,
        kernel_base: KERNEL_REGION_BASE,
        stage2_size: stage2_pages * 0x1000,
        stage2_base: SVSM_BASE,
        fs_size: ramfs_pages * 0x1000,
        fs_base: ramfs_base,
        kernel_reserved_size: 0,
        fw_metadata: (OVMF_CODE_TOP - 0x1000) as u32,
        debug_serial_port: 0x3f8,
        _reserved: 0,
        _reserved2: 0,
    };

    // Add the metadata using the special page types
    add_metadata_pages(&params, params_base, &mut directive);

    // Create the initial stage 2 stack - remembering to add on the parameter pages
    // to the kernel page count.
    add_stack_page(
        &params,
        &mut directive,
        kernel_pages + 3,
        params_base as u32,
    );

    // Add the SVSM heap memory
    add_svsm_kernel_region(1, &mut directive);

    // Reserve space for the memory map. The IGVM loader will populate the parameter
    // area with the actual memory map data.
    add_memory_map(mm_base, &mut directive);

    add_params(hv_params_base, &mut directive);

    // Initial CPU state
    for vp_index in 0..1 {
        directive.push(new_vp_context_32(
            0,
            1,
            SVSM_BASE,
            SVSM_STACK - 24,
            0,
            0,
            0,
            vp_index,
        ));
    }

    let file = IgvmFile::new(
        IgvmRevision::V1,
        vec![new_platform(0x1, IgvmPlatformType::SEV_SNP)],
        vec![],
        directive,
    )
    .expect("Failed to create file");
    let mut binary_file = Vec::new();
    file.serialize(&mut binary_file).unwrap();

    let mut file = File::create(out_filename).expect("Could not open file");
    file.write_all(binary_file.as_slice())
        .expect("Failed to write file");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    /*
    let args = vec![
        "notused".to_string(),
        "/home/rhopkins/src/coco-svsm-branches/rdh-svsm/svsm.bin".to_string(),
        "svsm.igvm".to_string(),
    ];
    */
    if args.len() != 3 {
        println!("Usage igvm_svsm /path/to/svsm_base_dir /path/to/out.igvm");
        return;
    }
    println!("Saving file as svsm.igvm");
    create_svsm_igvm(&args[1], &args[2]);
}
