// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

use gdt::new_gdt;
use igvm::{IgvmDirectiveHeader, IgvmFile, IgvmPlatformHeader, IgvmRevision};
use igvm_defs::{
    IgvmPageDataFlags, IgvmPageDataType, IgvmPlatformType, IGVM_VHS_SUPPORTED_PLATFORM,
    PAGE_SIZE_4K,
};
use pagetable::new_pagetable;
use std::{
    env,
    fs::File,
    io::{Read, Write},
};
use vpcontext::new_vp_context;
use zerocopy::AsBytes;

mod gdt;
mod pagetable;
mod vpcontext;

const SVSM_GDT: u64 = 0xff2ff000;
const SVSM_PAGETABLE: u64 = 0xff300000;
const SVSM_METADATA: u64 = 0xff3ff000;
const SVSM_BASE: u64 = 0xff400000;
const SVSM_HEAP_BASE: u64 = 512 * (1u64 << 30);
const SVSM_HEAP_SIZE: u64 = 256 * (1u64 << 20);

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

fn add_metadata_pages(pages: &mut Vec<IgvmDirectiveHeader>) {
    let flags = IgvmPageDataFlags::new();
    // SEV_DESC_TYPE_SNP_SEC_MEM
    for index in 0..((632 * 1024) / PAGE_SIZE_4K) {
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
        gpa: 632 * 1024,
        compatibility_mask: 1,
        flags,
        data_type: IgvmPageDataType::SECRETS,
        data: vec![],
    });

    // SEV_DESC_TYPE_CPUID
    pages.push(IgvmDirectiveHeader::PageData {
        gpa: 636 * 1024,
        compatibility_mask: 1,
        flags,
        data_type: IgvmPageDataType::CPUID_DATA,
        data: vec![],
    });

    // Information we want to exchange with SVSM
    let heap = SvsmHeap {
        base: SVSM_HEAP_BASE,
        size: SVSM_HEAP_SIZE,
    };
    pages.push(IgvmDirectiveHeader::PageData {
        gpa: SVSM_METADATA,
        compatibility_mask: 1,
        flags,
        data_type: IgvmPageDataType::NORMAL,
        data: heap.as_bytes().to_vec(),
    });
}

fn add_svsm_ram(compatibility_mask: u32, pages: &mut Vec<IgvmDirectiveHeader>) {
    // 512G
    let heap_base = 512 * (1u64 << 30);
    // 256MB
    let heap_size = 256 * (1u64 << 20);
    let mut gpa = heap_base;
    let mut flags = IgvmPageDataFlags::new();
    flags.set_is_2mb_page(true);
    flags.set_unmeasured(true);

    while gpa < (heap_base + heap_size) {
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

fn create_svsm_igvm(in_filename: &str, out_filename: &str) {
    let mut buf = vec![0; 4096];
    let mut directive: Vec<IgvmDirectiveHeader> = vec![];
    let mut in_file = File::open(in_filename).expect("Could not open input file");
    // When bundled with OVMF, the SVSM is located directly below
    // the bottom of the firmware. Now we have detached the SVSM from
    // OVMF it can be located at a different address. This is close
    // to the original, calculated address.
    let mut gpa = SVSM_BASE;

    // Populate the SVSM binary as normal pages
    while let Ok(len) = in_file.read(&mut buf) {
        if len == 0 {
            break;
        }
        directive.push(new_page_data(gpa, 1, buf));
        gpa += PAGE_SIZE_4K;
        buf = vec![0; 4096];
    }

    // Add the metadata using the special page types
    add_metadata_pages(&mut directive);

    // Add the SVSM heap memory
    add_svsm_ram(1, &mut directive);

    // Add the GDT
    let gdt_limit = new_gdt(SVSM_GDT, &mut directive);

    // Add the initial identity mapped page table
    new_pagetable(SVSM_PAGETABLE, &mut directive);

    // Initial CPU state
    for vp_index in 0..8 {
        directive.push(new_vp_context(
            0,
            1,
            SVSM_BASE,
            SVSM_PAGETABLE,
            SVSM_GDT,
            gdt_limit,
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
    let args = vec![
        "notused".to_string(),
        "/home/rhopkins/src/coco-svsm-branches/rdh-svsm/svsm.bin".to_string(),
        "svsm.igvm".to_string(),
    ];
    if args.len() != 3 {
        println!("Usage igvm_svsm /path/to/svsm.bin /path/to/out.igvm");
        return;
    }
    println!("Saving file as svsm.igvm");
    create_svsm_igvm(&args[1], &args[2]);
}
