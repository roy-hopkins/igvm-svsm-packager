// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

use std::{
    env,
    fs::File,
    io::{Read, Write},
};

use igvm::{
    snp_defs::{SevFeatures, SevSelector, SevVirtualInterruptControl, SevVmsa, SevXmmRegister},
    IgvmDirectiveHeader, IgvmFile, IgvmPlatformHeader, IgvmRevision,
};
use igvm_defs::{
    IgvmPageDataFlags, IgvmPageDataType, IgvmPlatformType, IGVM_VHS_SUPPORTED_PLATFORM,
    PAGE_SIZE_4K,
};

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
    let mut flags = IgvmPageDataFlags::new();
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
}

fn new_vp_context(
    gpa: u64,
    compatibility_mask: u32,
    rip: u64,
    vp_index: u16,
) -> IgvmDirectiveHeader {
    let mut vmsa = Box::new(SevVmsa {
        es: SevSelector {
            selector: 16,
            attrib: 0xc093,
            limit: 0xffffffff,
            base: 0,
        },
        cs: SevSelector {
            selector: 8,
            attrib: 0xc09b,
            limit: 0xffffffff,
            base: 0,
        },
        ss: SevSelector {
            selector: 16,
            attrib: 0xc093,
            limit: 0xffffffff,
            base: 0,
        },
        ds: SevSelector {
            selector: 16,
            attrib: 0xc093,
            limit: 0xffffffff,
            base: 0,
        },
        fs: SevSelector {
            selector: 16,
            attrib: 0xc093,
            limit: 0xffffffff,
            base: 0,
        },
        gs: SevSelector {
            selector: 0,
            attrib: 0,
            limit: 0,
            base: 0,
        },
        gdtr: SevSelector {
            selector: 0,
            attrib: 0,
            limit: 0,
            base: 0,
        },
        ldtr: SevSelector {
            selector: 0,
            attrib: 0,
            limit: 0,
            base: 0,
        },
        idtr: SevSelector {
            selector: 0,
            attrib: 0,
            limit: 0,
            base: 0,
        },
        tr: SevSelector {
            selector: 0,
            attrib: 0,
            limit: 0,
            base: 0,
        },
        pl0_ssp: 0,
        pl1_ssp: 0,
        pl2_ssp: 0,
        pl3_ssp: 0,
        u_cet: 0,
        vmsa_reserved1: [0; 2],
        vmpl: 0,
        cpl: 0,
        vmsa_reserved2: 0,
        efer: 0,
        vmsa_reserved3: [0; 26],
        xss: 0,
        cr4: 0,
        cr3: 0,
        cr0: 0x60000011,
        dr7: 0,
        dr6: 0,
        rflags: 0,
        rip,
        dr0: 0,
        dr1: 0,
        dr2: 0,
        dr3: 0,
        dr0_addr_mask: 0,
        dr1_addr_mask: 0,
        dr2_addr_mask: 0,
        dr3_addr_mask: 0,
        vmsa_reserved4: [0; 3],
        rsp: 0,
        s_cet: 0,
        ssp: 0,
        interrupt_ssp_table_addr: 0,
        rax: 0,
        star: 0,
        lstar: 0,
        cstar: 0,
        sfmask: 0,
        kernel_gs_base: 0,
        sysenter_cs: 0,
        sysenter_esp: 0,
        sysenter_epi: 0,
        cr2: 0,
        vmsa_reserved5: [0; 4],
        pat: 0,
        dbgctl: 0,
        last_branch_from_ip: 0,
        last_branch_to_ip: 0,
        last_excp_from_ip: 0,
        last_excp_to_ip: 0,
        vmsa_reserved6: [0; 9],
        spec_ctrl: 0,
        vmsa_reserved7: [0; 8],
        rcx: 0,
        rdx: 0,
        rbx: 0,
        vmsa_reserved8: 0,
        rbp: 0,
        rsi: 0,
        rdi: 0,
        r8: 0,
        r9: 0,
        r10: 0,
        r11: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        vmsa_reserved9: [0; 2],
        exit_info1: 0,
        exit_info2: 0,
        exit_int_info: 0,
        next_rip: 0,
        sev_features: SevFeatures::new(),
        v_intr_cntrl: SevVirtualInterruptControl(0),
        guest_error_code: 0,
        virtual_tom: 0,
        tlb_id: 0,
        pcpu_id: 0,
        event_inject: igvm::snp_defs::SevEventInjectInfo(0),
        xcr0: 0,
        xsave_valid_bitmap: [0; 16],
        x87dp: 0,
        mxcsr: 0,
        x87_ftw: 0,
        x87_fsw: 0,
        x87_fcw: 0,
        x87_op: 0,
        x87_ds: 0,
        x87_cs: 0,
        x87_rip: 0,
        x87_registers1: [0; 32],
        x87_registers2: [0; 32],
        x87_registers3: [0; 16],
        xmm_registers: [SevXmmRegister { low: 0, high: 0 }; 16],
        ymm_registers: [SevXmmRegister { low: 0, high: 0 }; 16],
    });
    IgvmDirectiveHeader::SnpVpContext {
        gpa: 0,
        compatibility_mask,
        vp_index,
        vmsa,
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
    let svsm_gpa = 0xff400000;
    let mut gpa = svsm_gpa;

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

    // Initial CPU state
    for vp_index in 0..8 {
        directive.push(new_vp_context(0, 1, svsm_gpa, vp_index));
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
    if args.len() != 3 {
        println!("Usage igvm_svsm /path/to/svsm.bin /path/to/out.igvm");
        return;
    }
    println!("Saving file as svsm.igvm");
    create_svsm_igvm(&args[1], &args[2]);
}
