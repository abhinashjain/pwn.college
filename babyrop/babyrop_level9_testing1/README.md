## Blocker:
* No address leak to defeat ASLR
* Didn't know at what address our payload was stored
* Linking the binary with correct libc and ld that was used in server
* printf was creating a problem because it expect one argument
* only 24B of the payload was stored in stack, rest was in data section

## Solution: 
* Copied used binary and libc from the server.
* Used 'pwninit' to find a correct loader and to generate a patched binary to emulate a server side environment.
* PIE was not enabled in binary this means code and data section will not be randomised. Hence, made it leak the address using puts(puts) method.
* puts(puts) method only work because PIE is not enabled in binary.
* Stack pivot technique was used by using the 'pop rsp' from the binary's address. 
* Thus making the rsp to point towards data section and use our full payload and not just restricted to 24B in stack.
* Had to increase the distance between our rsp and the GOT table. This we achieved using multiple 'ret' instruction.
* printf problem was resolved by pointing the first argument to already existing data in got table.
* PIE was enabled for the libc this means code and data section was randomised.
* Use puts(puts.got) to leak dynamic address of puts function in libc.
* Use this leaked address to calculate the base address of dynamically loaded libc.
* Then call any other libc's functions 
* Called 'read' syscall and stored the name of the flag's filename in a particular address in binary's data section
* Because the 'data' address was not randomised we can hardcode the address in the exploit. Thus, making it similar (in a loose sense) to address leak. 

