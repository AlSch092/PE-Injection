## Injection Technique: Loaded Module Reflection  
Evasion & Injection Technique: Copies the current process into a target process and begins execution. Same concept as PE Injection.

# What is this?  
This example shows how we can inject the current PE image into another running process and execute some payload. The injected code is undetected by most usermode anti-cheat systems and won't show up from DLL walking. The code example has been expanded to show how a working Win32 GUI can be spawned; the GUI can then be used for some other logic, providing us a foothold onto the target process.

# Steps Taken:  
1. Open the target process and allocate space greater or equal to the payload's image size using `VirtualAllocEx`  
2. Take the address for our new allocated buffer and write over the NT Optional header's ImageBase member with this address  
3. Copy all bytes from payload image to a buffer, write it into the target process using `WriteProcessMemory` after calling `VirtualProtectEx`  
4. Calculate the offset to our image's `main` routine by subtracting the address of `main` from the payload's image base  
5. Use the `main` offset (added with step 1's address) with `CreateRemoteThread` to make a new thread in our target process and begin program flow  

In summary, this technique allocates some space in the target, writes the current process module bytes to it, finds the 'WinMain' or 'Main' or 'Dllmain' offset, then creates a remote thread at that offset to execute the payload.  

# Prevention/Detection Methods 
1. A TLS callback can be used to prevent unknown threads being created in the target process.
2. Window Creation handles & registering window classes can be monitored for foreign GUIs, as we use `CreateWindow` to spawn a user-controllable interface in the target application.
3. Preventing foreign calls to `OpenProcess` from succeeding will make the entire technique fail

# Notice  
For this technique it's recommended to call WINAPI function pointers with their address calculated at runtime using GetProcAddress. If your process calls out to a function in a module which is not loaded in the target process, this will likely fail crash the target process unless you explicitly load the required module first. 

# Screenshots  
![Screenshot](example.png)  
![Screenshot](example2.png)  
