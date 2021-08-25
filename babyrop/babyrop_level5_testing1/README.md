## Blocker:
* No address leak to defeat ASLR
* Didn't know at what address our payload was stored

## Solution: 
* PIE was not enabled in binary this means code and data section will not be randomised.
* Called 'read' syscall and stored the name of the flag's filename in a particular address in data section
* Because the 'data' address was not randomised we can hardcode the address in the exploit. Thus, making it similar (in a loose sense) to address leak. 

