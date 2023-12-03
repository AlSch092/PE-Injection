# Injection Technique: Loaded Module Reflection
Evasion & Injection Technique: Copies the current process module into a target process and begins execution (Windows)  

This example shows how we can mirror a loaded module (exe or dll) into another running process, which creates a 'rogue' module running inside the target process. Similar to shellcode injection, but has features of DLL/process injection. The injected module is undetected by most anti-cheat systems, thus it can be used for reading and writing memory.

Steps Taken:  
1. Open the target process and allocate space greater or equal to the payload's image size using `VirtualAllocEx`  
2. Take the address for our new allocated buffer and write over the NT Optional header's ImageBase member with this address  
3. Copy all bytes from payload image to a buffer, write it into the target process using `WriteProcessMemory` after calling `VirtualProtectEx`  
4. Calculate the offset to our image's `main` routine by subtracting the address of `main` from the payload's image base  
5. Use the `main` offset (added with step 1's address) with `CreateRemoteThread` to make a new thread in our target process and begin program flow  

WinAPI and functions loaded from libraries should be calculated at runtime using function pointers in our payload code. This is because addresses will likely change between processes for most libraries: MSVCR120.dll might be loaded at different addresses in different processes. In this example we're injecting a process into the 'x64dbg.exe' process, which can be seen in the second screencap below. 

We can also inject DLLs into remote processes with this technique. We go through the same steps as above, but call `LoadLibrary` in our host/loader process before step 1. We then take the loaded dll image and copy its bytes to the target process, and point our remote thread at the offset of `DllMain` instead of `main`. A pattern scanner can be used to easily grab the offset of `DllMain` in our payload DLL. We then create a remote thread on `dllMain`, and we've now successfully loaded an unmanaged 'rogue' DLL in our target.  

![Screenshot](example.png)  
![Screenshot](example2.png)  

If you feel there's anything wrong or missing from this example, feel free to open an issue or pull request!
