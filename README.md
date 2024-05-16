## Injection Technique: Loaded Module Reflection  
Evasion & Injection Technique: Copies the current process into a target process and begins execution. Same concept as PE Injection.

# What is this?  
This example shows how we can mirror a loaded module into another running process, which acts as a stager for payloads. The injected code is undetected by many usermode anti-cheat systems and won't show up from DLL walking, thus it can be used for delivery of some payload. The code example has been expanded to show how a working Win32 GUI can be spawned: the GUI can then be used to control read/writes on memory or do other actions and thus acts like a stager. This project displays similar concepts to MITRE technique T1620, which can be found at https://attack.mitre.org/techniques/T1620/.

# Prevention/Detection Methods 
1. A TLS callback can be used to prevent unknown threads being created in the target process.
2. Window Creation handles & registering window classes can be monitored for foreign GUIs, as we use `CreateWindow` to spawn a user-controllable interface in the target application.
3. Preventing foreign calls to `OpenProcess` from succeeding will make the entire technique fail

# Steps Taken:  
1. Open the target process and allocate space greater or equal to the payload's image size using `VirtualAllocEx`  
2. Take the address for our new allocated buffer and write over the NT Optional header's ImageBase member with this address  
3. Copy all bytes from payload image to a buffer, write it into the target process using `WriteProcessMemory` after calling `VirtualProtectEx`  
4. Calculate the offset to our image's `main` routine by subtracting the address of `main` from the payload's image base  
5. Use the `main` offset (added with step 1's address) with `CreateRemoteThread` to make a new thread in our target process and begin program flow  

In summary, this technique allocates some space in the target, writes the current process module bytes to it, finds the 'WinMain' or 'Main' or 'Dllmain' offset, then creates a remote thread at that offset to execute the payload.  

# Notice  
For this technique you will want to call WINAPI function pointers with their address calculated at runtime with GetProcAddress, otherwise crashes will occur as relocations needs to be fixed (we are spawning our code on a random base address in heap memory on a target application). We are 'living off the land' of the target process and must make use of the modules loaded inside the target process, otherwise the chance of detection grows if you start loading extra .dlls at runtime to get your own code to work properly. A code example has been added with Windows Forms as a GUI to better display this concept. Furthermore, the project optimization must be compiled with the option 'Using Link Time Code Generation', otherwise the injected code will crash the target.

# Screenshots  
![Screenshot](example.png)  
![Screenshot](example2.png)  
