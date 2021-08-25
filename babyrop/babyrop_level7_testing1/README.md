## Blocker:
* No address leak to defeat ASLR (the leak was limited to libc)
* Didn't know at what address our payload was stored
* Linking the binary with correct libc and ld that was used in server

## Solution: 
* Copied used binary and libc from the server.
* Used 'pwninit' to find a correct loader and to generate a patched binary to emulate a server side environment.
* PIE was not enabled in binary this means code and data section will not be randomised.
* PIE was enabled for the libc this means code and data section was randomised. system call libc's address leak comes in handy here.
* Called 'read' syscall and stored the name of the flag's filename in a particular address in binary's data section
* Because the 'data' address was not randomised we can hardcode the address in the exploit. Thus, making it similar (in a loose sense) to address leak. 

