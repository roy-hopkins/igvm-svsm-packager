// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

use igvm::{
    snp_defs::{SevFeatures, SevSelector, SevVirtualInterruptControl, SevVmsa, SevXmmRegister},
    IgvmDirectiveHeader,
};

pub fn new_vp_context_32(
    gpa: u64,
    compatibility_mask: u32,
    rip: u64,
    cr3: u64,
    gdt_base: u64,
    gdt_limit: u16,
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
            limit: gdt_limit as u32,
            base: gdt_base,
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
        cr3,
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

pub fn new_vp_context_64(
    gpa: u64,
    compatibility_mask: u32,
    rip: u64,
    cr3: u64,
    gdt_base: u64,
    gdt_limit: u16,
    vp_index: u16,
) -> IgvmDirectiveHeader {
    let mut vmsa = Box::new(SevVmsa {
        es: SevSelector {
            selector: 0x20,
            attrib: 0xa093,
            limit: 0xffffffff,
            base: 0,
        },
        cs: SevSelector {
            selector: 0x18, // 64-bit code
            attrib: 0xa09b,
            limit: 0xffffffff,
            base: 0,
        },
        ss: SevSelector {
            selector: 0x20,
            attrib: 0xa093,
            limit: 0xffffffff,
            base: 0,
        },
        ds: SevSelector {
            selector: 0x20,
            attrib: 0xa093,
            limit: 0xffffffff,
            base: 0,
        },
        fs: SevSelector {
            selector: 0x20,
            attrib: 0xa093,
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
            limit: gdt_limit as u32,
            base: gdt_base,
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
        efer: 0x1101, // EFER.LME
        vmsa_reserved3: [0; 26],
        xss: 0,
        cr4: 0x20, // CR4.PAE
        cr3,
        cr0: 0xe0000011, // + CR0.PG
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
