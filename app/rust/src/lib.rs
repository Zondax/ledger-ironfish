/*******************************************************************************
*   (c) 2018 - 2024 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
#![no_std]
#![no_builtins]
#![allow(dead_code, unused_imports)]

use core::panic::PanicInfo;

use constants::SPENDING_KEY_GENERATOR;
mod constants;

use jubjub::{AffinePoint, ExtendedPoint, Fr};

use core::mem::MaybeUninit;
use critical_section::RawRestoreState;
// use embedded_alloc::Heap;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bolos::{lazy_static, pic::PIC};

#[lazy_static]
static mut BUFFER: [u8; 2048] = [0u8; 2048];

struct MyAlloc(PIC<BumpAllocator>);

#[global_allocator]
static mut ALLOCATOR: MyAlloc = MyAlloc(PIC::new(BumpAllocator::new()));

pub struct BumpAllocator {
    heap: AtomicUsize,
    size: AtomicUsize,
    next: UnsafeCell<usize>,
    initialized: AtomicBool,
}

unsafe impl Sync for BumpAllocator {}
unsafe impl Sync for MyAlloc {}

impl BumpAllocator {
    const fn new() -> Self {
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

struct CriticalSection;
critical_section::set_impl!(CriticalSection);

/// Default empty implementation as we don't have concurrency.
unsafe impl critical_section::Impl for CriticalSection {
    unsafe fn acquire() -> RawRestoreState {}
    unsafe fn release(_restore_state: RawRestoreState) {}
}

// ParserError should mirror parser_error_t from parser_common.
// At the moment, just implement OK or Error
#[repr(C)]
#[derive(PartialEq, Debug)]
pub enum ParserError {
    ParserOk = 0,
    ParserUnexpectedError = 5,
}

#[repr(C)]
pub enum ConstantKey {
    SpendingKeyGenerator,
    ProofGenerationKeyGenerator,
    PublicKeyGenerator,
}

/// Initializes the heap memory for the global allocator.
///
/// The heap is stored in the stack, and has a fixed size.
/// This method is called just before [sample_main].
#[no_mangle]
pub extern "C" fn heap_init() -> ParserError {
    unsafe {
        let allocator = ALLOCATOR.0.get_mut();
        allocator.init(BUFFER.as_ptr(), 12500);
    }
    ParserError::ParserOk
}

#[no_mangle]
pub extern "C" fn from_bytes_wide(input: &[u8; 64], output: &mut [u8; 32]) -> ParserError {
    let result = Fr::from_bytes_wide(input).to_bytes();
    output.copy_from_slice(&result[0..32]);
    ParserError::ParserOk
}

#[no_mangle]
pub extern "C" fn scalar_multiplication(
    input: &[u8; 32],
    key: ConstantKey,
    output: *mut [u8; 32],
) -> ParserError {
    let key_point = match key {
        ConstantKey::SpendingKeyGenerator => constants::SPENDING_KEY_GENERATOR,
        ConstantKey::ProofGenerationKeyGenerator => constants::PROOF_GENERATION_KEY_GENERATOR,
        ConstantKey::PublicKeyGenerator => constants::PUBLIC_KEY_GENERATOR,
    };

    let extended_point = key_point.multiply_bits(input);
    let result = AffinePoint::from(&extended_point);

    unsafe {
        let output_slice = &mut *output;
        output_slice.copy_from_slice(&result.to_bytes());
    }

    ParserError::ParserOk
}

#[no_mangle]
pub extern "C" fn randomizeKey(
    key: &[u8; 32],
    randomness: &[u8; 32],
    output: &mut [u8; 32],
) -> ParserError {
    let mut skfr = Fr::from_bytes(key).unwrap();
    let alphafr = Fr::from_bytes(randomness).unwrap();
    skfr += alphafr;
    output.copy_from_slice(&skfr.to_bytes());

    ParserError::ParserOk
}

#[no_mangle]
pub extern "C" fn compute_sbar(
    s: &[u8; 32],
    r: &[u8; 32],
    rsk: &[u8; 32],
    sbar: &mut [u8; 32],
) -> ParserError {
    let s_point = Fr::from_bytes(s).unwrap();
    let r_point = Fr::from_bytes(r).unwrap();
    let rsk_point = Fr::from_bytes(rsk).unwrap();

    let sbar_tmp = r_point + s_point * rsk_point;
    sbar.copy_from_slice(&sbar_tmp.to_bytes());

    ParserError::ParserOk
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

fn debug(_msg: &str) {}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::println; // Make `println!` explicitly available for tests
}
