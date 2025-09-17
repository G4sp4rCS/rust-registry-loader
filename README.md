# Registry Loader (Rust)

This project demonstrates how to read an encrypted payload from the Windows Registry, decrypt it with RC4, and execute it from memory using Rust and the WinAPI.

⚠️ **Disclaimer:**  
This project is for educational and research purposes only. Running shellcode loaders outside of a controlled lab environment is dangerous and potentially illegal. Use this only in your own lab for learning purposes.

---

## 🦀 Features

- Reads a binary value (`REG_BINARY`) from the Windows Registry:
  - Subkey: `HKEY_CURRENT_USER\Control Panel`
  - Value: `MalDevAcademy`
- Decrypts the value using RC4 with a fixed 16-byte key.
- Allocates executable memory with `VirtualAlloc`.
- Copies the decrypted payload into memory.
- Changes memory protection to executable (`VirtualProtect`).
- Spawns a new thread (`CreateThread`) to execute the payload.
- Waits for the thread to complete with `WaitForSingleObject`.

---

## ⚙️ How It Works

1. Read Registry Value  
   Uses `RegGetValueA` to fetch the payload stored in the Registry.

2. RC4 Decryption  
   A simple RC4 implementation decrypts the payload with the predefined key:

   ```rust
   const RC4_KEY: [u8; 16] = [0x0E, 0x56, 0x75, 0xA4, ...];
    ```

4. Memory Allocation
The decrypted payload is copied into a buffer allocated with VirtualAlloc.

5. Execution
Memory protections are updated with VirtualProtect, and the shellcode is executed in a new thread with CreateThread.