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

use constants::{SPENDING_KEY_GENERATOR};
mod constants;

use jubjub::{Fr, AffinePoint, ExtendedPoint};

use embedded_alloc::Heap;
use critical_section::RawRestoreState;
use core::mem::MaybeUninit;

// TODO Adjust this number to a reasonable value, as 12500 was a value provided by Ironfish from their tests.
const HEAP_SIZE: usize = 1000;

#[global_allocator]
static HEAP: Heap = Heap::empty();

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
extern "C" fn heap_init() {
    static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
    unsafe { HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE) }
}

#[no_mangle]
pub extern "C" fn from_bytes_wide(input: &[u8; 64], output: &mut [u8; 32]) -> ParserError {
    let result = Fr::from_bytes_wide(input).to_bytes();
    output.copy_from_slice(&result[0..32]);
    ParserError::ParserOk
}

#[no_mangle]
pub extern "C" fn scalar_multiplication(input: &[u8; 32], key: ConstantKey, output: *mut [u8; 32]) -> ParserError {
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
pub extern "C" fn randomizeKey(key: &[u8; 32], randomness: &[u8; 32], output: &mut [u8; 32]) -> ParserError {

    let mut skfr = Fr::from_bytes(key).unwrap();
    let alphafr = Fr::from_bytes(randomness).unwrap();
    skfr += alphafr;
    output.copy_from_slice(&skfr.to_bytes());

    ParserError::ParserOk
}

#[no_mangle]
pub extern "C" fn compute_sbar( s:  &[u8; 32], r:  &[u8; 32], rsk:  &[u8; 32], sbar:  &mut [u8; 32]) -> ParserError{
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
