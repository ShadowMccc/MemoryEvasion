# MemoryEvasion
A Cobalt Strike memory evasion loader for redteamers,Support x86/x64 stager/stagerless payload with profile(tested on windows7/10,winserver 2012)
## How To Evasion?
* Hook Sleep,CreateProcessA,CreateHeap,GetProcessHeap functions before the shellcode is loaded.
* Create a new heap for beacon's profile. when beacon calls GetProcessHeap or CreateHeap functions,return the new heap's handle.
* When beacon calls sleep function we encrypt memorys where beacon and profile are located,and when the sleep has finished we decrypt them.

## Why Hook GetProcessheap and CreateHeap
* 64-bit beacon calls GetProcessHeap to get the memory to store beacon's profile.
* 32-bit beacon dose not call GetProcessHeap to get the memory to store beacon's profile.It uses CreateHeap to create new heap and get the memory to store beacon's profile from that heap.

## Demo
![DEMO](demo.gif)

## References
This project would not have been possible without the following:
- [LockdExeDemo](https://github.com/waldo-irc/LockdExeDemo)
- [ThreadStackSpoofer](https://github.com/mgeeky/ThreadStackSpoofer)
