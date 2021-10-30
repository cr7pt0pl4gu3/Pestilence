# Pestilence
### What is pestilence?
Pestilence is a shellcode loader written in rust. It strives to evade modern EDR solutions.
### How does it work?
It loads AES-128-CFB encrypted shellcode (including the key and IV) into the .text PE section during the build stage.
During the execution, it decrypts the shellcode stub and executes it in memory by using NtAllocateVirtualMemory,
NtProtectVirtualMemory mixed with sleeps. Interestingly, it does not inject or create a new thread, 
instead jumping to the newly allocated memory using asm! rust macro. 
# Installation
### Requirements
* python3 (tested with 3.10) + pycryptodomex
* rust (nightly-x86_64-pc-windows-msvc toolchain)
* visual studio 2019 build tools
### How to install them
#### vs2019 build tools
Download and install vs2019 build tools from here:
```
https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2019
```
Make sure that you select "Desktop development with C++" option.
#### python3 + pycryptodome
Download and install python using this link (do not forget to add it to PATH):
```
https://www.python.org/ftp/python/3.10.0/python-3.10.0-amd64.exe
```
Install pycryptodomex:
```shell
pip3 install pycryptodomex
```
#### rust
Install rust using rustup from this link:
```
https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe
```
* Install the C++ build tools if asked.
* Be sure to choose "customize installation".

Modify install settings:
```
Default host triple? [x86_64-pc-windows-msvc]
Default toolchain? [nightly]
Profile? [default]
Modify PATH variable? [Y]
```
Proceed with installation.
# Usage
Open powershell and thrive:
```shell
git clone https://github.com/cr7pt0pl4gu3/Pestilence
cd Pestilence
cp /path/to/raw/shellcode.bin shellcode.bin
python encrypt_shellcode.py
cargo build --release
```
Note: shellcode must be named "shellcode.bin"!
#### Good luck! I hope that pestilence helped you.