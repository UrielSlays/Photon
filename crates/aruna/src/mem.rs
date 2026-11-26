//! Engine memory probe: Windows working set via GetProcessMemoryInfo; other platforms
//! report `None` so the engine still builds cross-platform.

/// Current process working-set (resident) size in bytes, or `None` when the platform or
/// probe cannot measure it. `None` (not `Some(0)`) on non-Windows or probe failure, so a
/// caller cannot mistake "unmeasured" for "0 bytes".
#[cfg(windows)]
pub fn engine_working_set_bytes() -> Option<u64> {
    // PROCESS_MEMORY_COUNTERS layout (psapi.h), declared here to avoid a dependency.
    #[repr(C)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }
    extern "system" {
        fn GetCurrentProcess() -> isize;
    }
    #[link(name = "psapi")]
    extern "system" {
        fn GetProcessMemoryInfo(
            process: isize,
            counters: *mut ProcessMemoryCounters,
            cb: u32,
        ) -> i32;
    }
    unsafe {
        let mut c: ProcessMemoryCounters = std::mem::zeroed();
        c.cb = std::mem::size_of::<ProcessMemoryCounters>() as u32;
        if GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) != 0 {
            Some(c.working_set_size as u64)
        } else {
            None
        }
    }
}

/// Non-Windows fallback: the working set is not measured elsewhere, so return `None`
/// (never a misleading `Some(0)`).
#[cfg(not(windows))]
pub fn engine_working_set_bytes() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn working_set_is_a_plausible_nonzero() {
        let bytes = engine_working_set_bytes().expect("Windows working-set must be measured");
        // A live process holds at least ~1 MB and far less than 100 GB.
        assert!(bytes > 1_000_000, "working set implausibly small: {bytes}");
        assert!(bytes < 100_000_000_000, "working set implausibly large: {bytes}");
    }

    // Keep a test on every platform (so `use super::*` is never an unused import under the
    // `-D warnings` clippy gate, 2026-06-26) AND exercise the non-Windows fallback: it
    // reports `None` ("not measured"), never a misleading `Some(0)`.
    #[test]
    #[cfg(not(windows))]
    fn non_windows_reports_unmeasured() {
        assert!(
            engine_working_set_bytes().is_none(),
            "non-Windows must report the working set as unmeasured (None)"
        );
    }
}
