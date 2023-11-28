// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>
use bitflags::bitflags;
use igvm::IgvmDirectiveHeader;
use igvm_defs::{IgvmPageDataFlags, IgvmPageDataType};
use zerocopy::AsBytes;

pub fn new_pagetable(pt_gpa: u64, pages: &mut Vec<IgvmDirectiveHeader>) {
    let mut level3 = PTPage::default();
    let mut level2 = PTPage::default();
    let mut level1 = vec![PTPage::default(); 5];
    let l2_start = pt_gpa + 0x1000;
    let l1_start = l2_start + 0x1000;

    level3.entries[0].set(
        l2_start + 0x8000000000000,
        PTEntryFlags::PRESENT | PTEntryFlags::WRITABLE | PTEntryFlags::USER,
    );

    // 4 * Level2 entries gives us 4GB address space
    //for (i, l2_entry) in level1.iter_mut().enumerate().take(4) {
    for l2_entry in 0..4 {
        level2.entries[l2_entry].set(
            (l1_start + l2_entry as u64 * 0x1000) + 0x8000000000000,
            PTEntryFlags::PRESENT | PTEntryFlags::WRITABLE | PTEntryFlags::USER,
        );
        for l1_entry in 0..512 {
            level1[l2_entry].entries[l1_entry].set(
                ((l2_entry * 512 + l1_entry) * 0x200000) as u64 + 0x8000000000000,
                PTEntryFlags::PRESENT
                    | PTEntryFlags::WRITABLE
                    | PTEntryFlags::HUGE
                    | PTEntryFlags::GLOBAL,
            )
        }
    }

    let flags = IgvmPageDataFlags::new();
    pages.push(IgvmDirectiveHeader::PageData {
        gpa: pt_gpa,
        compatibility_mask: 1,
        flags,
        data_type: IgvmPageDataType::NORMAL,
        data: level3.as_bytes().to_vec(),
    });
    pages.push(IgvmDirectiveHeader::PageData {
        gpa: l2_start,
        compatibility_mask: 1,
        flags,
        data_type: IgvmPageDataType::NORMAL,
        data: level2.as_bytes().to_vec(),
    });
    for (i, l1_page) in level1.iter().enumerate() {
        pages.push(IgvmDirectiveHeader::PageData {
            gpa: l1_start + i as u64 * 0x1000,
            compatibility_mask: 1,
            flags,
            data_type: IgvmPageDataType::NORMAL,
            data: l1_page.as_bytes().to_vec(),
        });
    }
}

const ENTRY_COUNT: usize = 512;

bitflags! {
    #[derive(Copy, Clone, Debug)]
    pub struct PTEntryFlags: u64 {
        const PRESENT       = 1 << 0;
        const WRITABLE      = 1 << 1;
        const USER      = 1 << 2;
        const ACCESSED      = 1 << 5;
        const DIRTY     = 1 << 6;
        const HUGE      = 1 << 7;
        const GLOBAL        = 1 << 8;
        const NX        = 1 << 63;
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, AsBytes)]
pub struct PTEntry(u64);

impl PTEntry {
    pub fn is_clear(&self) -> bool {
        self.0 == 0
    }

    pub fn clear(&mut self) {
        self.0 = 0;
    }

    pub fn present(&self) -> bool {
        self.flags().contains(PTEntryFlags::PRESENT)
    }

    pub fn raw(&self) -> u64 {
        self.0 as u64
    }

    pub fn flags(&self) -> PTEntryFlags {
        PTEntryFlags::from_bits_truncate(self.0)
    }

    pub fn set(&mut self, addr: u64, flags: PTEntryFlags) {
        assert_eq!(addr & !0x000f_ffff_ffff_f000, 0);
        self.0 = addr | flags.bits();
    }

    pub fn address(&self) -> u64 {
        self.0 & 0x000f_ffff_ffff_f000
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, AsBytes)]
pub struct PTPage {
    entries: [PTEntry; ENTRY_COUNT],
}

impl Default for PTPage {
    fn default() -> Self {
        let entries = [PTEntry::default(); ENTRY_COUNT];
        PTPage { entries }
    }
}
