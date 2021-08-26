## Blocker:
* PIE was enabled on tha binary hence we didn't know the address of win() (location where we wanted to jump)

## Solution: 
* After running the binary multiple times, I observed that out of the 16 bits (2 bytes), the last 12 bits were constant (i.e. 809 in hex) and only the first 4 bits were changing.
* Used partial overwrite technique to only overwrite last 2 bytes of previously stored address at rip (return address in stack)
* I ended up hardcoding all 16 bits and ran the binary multiple times hoping that at some point my hardcoded value will match the address of win() function.
* And, it worked!
