# IAT scanner
This is a simple IAT scanner, an anti cheat if I may, that scans for any changed imports inside of the exe.
# How it works, sorta
1. It loads in the original file bytes from the disk to the programs memory and proceeds to add its sections and headers(sorta like a manual mapper)
2. it automatically scans for any changes in the IAT. It does this by parsing throuh the original application's PE header, then explicitly assigning the `FirstThunk` to running applications address(`		auto fThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<uintptr_t>(currModule) + importsDesc->FirstThunk);`. Then it compares the addresses of the expected result, which is the address of the function within the appliction's untampered dll, to the actual one found through the first thunk.
3. Everything else is hooking related and not really why I made the scanner, figure it out yourself.
# HOW TO USE
->Read the source code and understand literally how the main function works

