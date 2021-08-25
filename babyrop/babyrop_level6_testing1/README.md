## Blocker:
* No address leak to defeat ASLR
* Didn't know at what address our payload was stored
* No 'syscall' gadget/instruction in binary
* No 'pop rax' gadget/instruction in binary

## Solution: 
* PIE was not enabled in binary this means code and data section will not be randomised.
* Called read syscall and stored the name of the flag's filename in a particular address in data section
* Because the 'data' address was not randomised we can hardcode the address in the exploit. Thus, making it similar (in a loose sense) to address leak. 
* Instead of directly calling the syscall, call the equivalent function in libc.
* This removes the dependancy on the value in rax and syscall gadget/instruction.
* Call libc functions with proper arguments.
* Return to libc function address i.e. the function's pre-define address in .plt + 4.
* Returning to this address in .plt will automatically re-direct to .got.plt table which will then redirect to correct address of a function inside libc's .text section.
