// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

use igvm::IgvmDirectiveHeader;
use igvm_defs::{IgvmPageDataFlags, IgvmPageDataType};
use zerocopy::AsBytes;

#[derive(Copy, Clone, PartialEq, Eq, AsBytes)]
#[repr(transparent)]
struct Gdt([u64; 512]);

#[allow(dead_code)]
pub fn new_gdt(gdt_gpa: u64, pages: &mut Vec<IgvmDirectiveHeader>) -> u16 {
    let mut entries = [0u64; 512];
    entries[0] = 0;
    // 32 bit code segment
    entries[1] = 0x00cf9a000000ffff;
    // 32 bit data segment
    entries[2] = 0x00cf93000000ffff;
    // 64 bit code segment
    entries[3] = 0x00af9a000000ffff;
    // 64 bit data segment
    entries[4] = 0x00cf92000000ffff;

    let gdt = Gdt(entries);
    pages.push(IgvmDirectiveHeader::PageData {
        gpa: gdt_gpa,
        compatibility_mask: 1,
        flags: IgvmPageDataFlags::new(),
        data_type: IgvmPageDataType::NORMAL,
        data: gdt.as_bytes().to_vec(),
    });

    // Return the 'limit' which is one less than the number of bytes in the GDT table.
    5 * 8 - 1
}
