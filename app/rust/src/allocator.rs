// This local implementation of allocator replaces the embedded_alloc. This is required in order to PIC some necessary points.
// Otherwise, we faced segmentation faults (app signal 11 crash),

// use embedded_alloc::Heap;

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use bolos::{pic::PIC};

pub struct MyAlloc(pub(crate) PIC<BumpAllocator>);

pub struct BumpAllocator {
    heap: AtomicUsize,
    size: AtomicUsize,
    next: UnsafeCell<usize>,
    initialized: AtomicBool,
}

unsafe impl Sync for BumpAllocator {}
unsafe impl Sync for MyAlloc {}

impl BumpAllocator {
    pub(crate) const fn new() -> Self {
        Self {
            heap: AtomicUsize::new(0),
            size: AtomicUsize::new(0),
            next: UnsafeCell::new(0),
            initialized: AtomicBool::new(false),
        }
    }

    pub fn init(&self, start: *const u8, size: usize) {
        self.heap.store(start as usize, Ordering::SeqCst);
        self.size.store(size, Ordering::SeqCst);
        unsafe { *self.next.get() = 0 };
        self.initialized.store(true, Ordering::SeqCst);
    }
}

unsafe impl GlobalAlloc for MyAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // pic to get back the runtime pointer
        // with this we try to operate on a well-formed pointer
        let allocator = self.0.get_ref();
        if !allocator.initialized.load(Ordering::SeqCst) {
            return null_mut();
        }

        let size = layout.size();
        let align = layout.align();

        let mut next = *allocator.next.get();
        next = (next + align - 1) & !(align - 1);

        if next + size > allocator.size.load(Ordering::SeqCst) {
            null_mut()
        } else {
            let heap_start = allocator.heap.load(Ordering::SeqCst) as *mut u8;
            let alloc = heap_start.add(next);
            *allocator.next.get() = next + size;
            alloc
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}