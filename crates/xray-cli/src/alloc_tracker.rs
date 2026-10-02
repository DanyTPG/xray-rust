use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

pub struct TrackingAllocator<A> {
    inner: A,
}

impl<A> TrackingAllocator<A> {
    pub const fn new(inner: A) -> Self {
        Self { inner }
    }
}

pub static HEAP_ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);
pub static HEAP_DEALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);
pub static HEAP_ACTIVE_BYTES: AtomicI64 = AtomicI64::new(0);
pub static HEAP_PEAK_BYTES: AtomicI64 = AtomicI64::new(0);
pub static HEAP_ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
pub static HEAP_DEALLOC_COUNT: AtomicU64 = AtomicU64::new(0);

pub static HEAP_SMALL_ACTIVE: AtomicI64 = AtomicI64::new(0);
pub static HEAP_MEDIUM_ACTIVE: AtomicI64 = AtomicI64::new(0);
pub static HEAP_LARGE_ACTIVE: AtomicI64 = AtomicI64::new(0);

#[derive(Debug, Clone, Copy, Default)]
pub struct AllocTelemetry {
    pub active_bytes: i64,
    pub peak_bytes: i64,
    pub total_allocated: u64,
    pub total_deallocated: u64,
    pub alloc_count: u64,
    pub dealloc_count: u64,
    pub small_bytes: i64,
    pub medium_bytes: i64,
    pub large_bytes: i64,
}

pub fn alloc_telemetry() -> AllocTelemetry {
    AllocTelemetry {
        active_bytes: HEAP_ACTIVE_BYTES.load(Ordering::Relaxed),
        peak_bytes: HEAP_PEAK_BYTES.load(Ordering::Relaxed),
        total_allocated: HEAP_ALLOCATED_BYTES.load(Ordering::Relaxed),
        total_deallocated: HEAP_DEALLOCATED_BYTES.load(Ordering::Relaxed),
        alloc_count: HEAP_ALLOC_COUNT.load(Ordering::Relaxed),
        dealloc_count: HEAP_DEALLOC_COUNT.load(Ordering::Relaxed),
        small_bytes: HEAP_SMALL_ACTIVE.load(Ordering::Relaxed),
        medium_bytes: HEAP_MEDIUM_ACTIVE.load(Ordering::Relaxed),
        large_bytes: HEAP_LARGE_ACTIVE.load(Ordering::Relaxed),
    }
}

unsafe impl<A: GlobalAlloc> GlobalAlloc for TrackingAllocator<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = self.inner.alloc(layout);
        if !ptr.is_null() {
            let size = layout.size() as i64;
            HEAP_ALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
            HEAP_ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            let active = HEAP_ACTIVE_BYTES.fetch_add(size, Ordering::Relaxed) + size;
            let mut peak = HEAP_PEAK_BYTES.load(Ordering::Relaxed);
            while active > peak {
                match HEAP_PEAK_BYTES.compare_exchange_weak(
                    peak,
                    active,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(actual) => peak = actual,
                }
            }
            if layout.size() < 1024 {
                HEAP_SMALL_ACTIVE.fetch_add(size, Ordering::Relaxed);
            } else if layout.size() <= 65536 {
                HEAP_MEDIUM_ACTIVE.fetch_add(size, Ordering::Relaxed);
            } else {
                HEAP_LARGE_ACTIVE.fetch_add(size, Ordering::Relaxed);
            }
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.inner.dealloc(ptr, layout);
        let size = layout.size() as i64;
        HEAP_DEALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        HEAP_DEALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        HEAP_ACTIVE_BYTES.fetch_sub(size, Ordering::Relaxed);
        if layout.size() < 1024 {
            HEAP_SMALL_ACTIVE.fetch_sub(size, Ordering::Relaxed);
        } else if layout.size() <= 65536 {
            HEAP_MEDIUM_ACTIVE.fetch_sub(size, Ordering::Relaxed);
        } else {
            HEAP_LARGE_ACTIVE.fetch_sub(size, Ordering::Relaxed);
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = self.inner.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            let old_size = layout.size();
            let old_s = old_size as i64;
            let new_s = new_size as i64;
            let diff = new_s - old_s;

            if diff > 0 {
                HEAP_ALLOCATED_BYTES.fetch_add(diff as u64, Ordering::Relaxed);
            } else {
                HEAP_DEALLOCATED_BYTES.fetch_add((-diff) as u64, Ordering::Relaxed);
            }

            let active = HEAP_ACTIVE_BYTES.fetch_add(diff, Ordering::Relaxed) + diff;
            let mut peak = HEAP_PEAK_BYTES.load(Ordering::Relaxed);
            while active > peak {
                match HEAP_PEAK_BYTES.compare_exchange_weak(
                    peak,
                    active,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(actual) => peak = actual,
                }
            }

            if old_size < 1024 {
                HEAP_SMALL_ACTIVE.fetch_sub(old_s, Ordering::Relaxed);
            } else if old_size <= 65536 {
                HEAP_MEDIUM_ACTIVE.fetch_sub(old_s, Ordering::Relaxed);
            } else {
                HEAP_LARGE_ACTIVE.fetch_sub(old_s, Ordering::Relaxed);
            }

            if new_size < 1024 {
                HEAP_SMALL_ACTIVE.fetch_add(new_s, Ordering::Relaxed);
            } else if new_size <= 65536 {
                HEAP_MEDIUM_ACTIVE.fetch_add(new_s, Ordering::Relaxed);
            } else {
                HEAP_LARGE_ACTIVE.fetch_add(new_s, Ordering::Relaxed);
            }
        }
        new_ptr
    }
}
