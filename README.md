# 🛡️ HandleGuard: Universal Anti-Cheat & Anti-Crack Detector

![C#](https://img.shields.io/badge/Language-C%23-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)
![Compatibility](https://img.shields.io/badge/Compatibility-.NET%20Core%20%7C%20.NET%20Framework%20%7C%20Native%20AOT-success.svg)

**HandleGuard** is a super universal and powerful protection. It catches memory editors, debuggers, and malicious stuff trying to poke around in your app's memory.

## ✨ Why it's cool
* **Runs anywhere:** Works flawlessly on **.NET Core**, **.NET Framework**, and is 100% ready for **Native AOT**.
* **Catches almost everything:** It detects a ton of different threats out of the box:
  * Memory Scanners (Cheat Engine, ArtMoney, etc.)
  * Debuggers (x64dbg, OllyDbg, WinDbg)
  * Custom DLL Injectors
  * Process dumpers and memory readers

## ⚙️ How it works (the short version)
Instead of using basic anti-debug APIs that get bypassed in 5 seconds, HandleGuard digs deeper:
1. It uses `NtQuerySystemInformation` to grab **all** open handles across the entire Windows OS.
2. It finds the real Kernel Object address of its own process.
3. It constantly scans the system for any other process holding a handle to this Kernel Object.
4. If some random process has a handle with dangerous rights (like `PROCESS_VM_READ` or `PROCESS_VM_WRITE`), the detector flags it!

## 🛡️ Pro-Tips for real security
This handle detector is strong, but don't rely on just one trick. For maximum protection, I highly recommend combining this with:
* **Direct Syscalls:** Swap out standard WinAPI calls (like `NtQuerySystemInformation`) with Direct or Indirect Syscalls to bypass user-mode hooks from advanced cheats.
* **Anti-Memory Patching:** Add integrity checks for your `.text` section so you know if someone modifies your code in memory.
* **String Encryption:** Hide your strings and API names. Make them sweat.

## 🤝 Forks & PRs
This project is totally open-source. If you have any ideas on how to make the detection even better, or if you found a way to optimize the code — just fork the repo and hit me with a pull request! I'm really looking forward to seeing your forks.
