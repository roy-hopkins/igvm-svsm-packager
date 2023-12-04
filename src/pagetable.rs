// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>
use bitflags::bitflags;
use zerocopy::AsBytes;

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
