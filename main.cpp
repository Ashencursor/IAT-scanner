#include <iostream>
#include <Windows.h>
#include <vector>
#include "utils.h"

bool IAT_Scanner(HMODULE currModule, HMODULE originalModule) {
	PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(originalModule);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
	PIMAGE_NT_HEADERS NT = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(dos) + dos->e_lfanew);
	if (NT->Signature != IMAGE_NT_SIGNATURE) return false;
	auto importsDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
		reinterpret_cast<uintptr_t>(originalModule) + NT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	//LOOP THROUGH DLLS
	while (importsDesc->Name) {
		const char* DLL_Name = reinterpret_cast<const char*>(reinterpret_cast<uintptr_t>(originalModule) + importsDesc->Name);
		HMODULE hModule = GetModuleHandleA(DLL_Name);// reference to current dll in this EXE
		if (!hModule) {
			importsDesc++;
			continue;
		}
		auto oThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<uintptr_t>(originalModule) + importsDesc->OriginalFirstThunk);
		auto fThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<uintptr_t>(currModule) + importsDesc->FirstThunk);//USES CURRENT DLL

		// LOOP THROUGH DLL FUNCTIONS
		while (oThunk->u1.AddressOfData) {
			//name of current dll in original file
			PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<uintptr_t>(originalModule) + oThunk->u1.AddressOfData);
			FARPROC expectedAddr = GetProcAddress(hModule, importByName->Name);// ADDRESS OF OG DLL FUNCTION address from DLL
			FARPROC actual = reinterpret_cast<FARPROC>(fThunk->u1.Function);// ADDRESS of current DLL

			if (expectedAddr != actual) {
				return false;
			}

			oThunk++;//name table 
			fThunk++;//addr table
		}
		importsDesc++;//process each descriptor
	}

	return true;
}


using MessageBoxFunc = int (WINAPI*)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
MessageBoxFunc originalMessageBoxFunc = nullptr;
int WINAPI HkMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType){
	return originalMessageBoxFunc(hWnd, "HOOKED", "SMD", uType);
}

void hookIAT(HMODULE currMod, std::string dllName, std::string funcName) {
	PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(currMod);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
	PIMAGE_NT_HEADERS NT = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(dos) + dos->e_lfanew);
	if (NT->Signature != IMAGE_NT_SIGNATURE) return;
	auto importsDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
		reinterpret_cast<uintptr_t>(currMod) + NT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	//LOOP THROUGH DLLS
	while (importsDesc->Name) {
		const char* DLL_Name = reinterpret_cast<const char*>(reinterpret_cast<uintptr_t>(currMod) + importsDesc->Name);
		HMODULE hModule = GetModuleHandleA(DLL_Name);// reference to current dll in this EXE
		if (!hModule) {
			importsDesc++;
			continue;
		}
		if (toLower(DLL_Name) != toLower(dllName)) {
			importsDesc++;
			continue;
		}
		auto oThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<uintptr_t>(currMod) + importsDesc->OriginalFirstThunk);
		auto fThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<uintptr_t>(currMod) + importsDesc->FirstThunk);//USES CURRENT DLL

		// LOOP THROUGH DLL FUNCTIONS
		while (oThunk->u1.AddressOfData) {
			//name of current dll in original file
			PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<uintptr_t>(currMod) + oThunk->u1.AddressOfData);
			
			if (toLower(importByName->Name) == toLower(funcName)) {
				static int count = 0;
				if (count == 0) {
					originalMessageBoxFunc = reinterpret_cast<MessageBoxFunc>(GetProcAddress(GetModuleHandleA(dllName.data()), funcName.data()));
					count++;
				}
				DWORD oldP;
				VirtualProtect(&fThunk->u1.Function, 32, PAGE_EXECUTE_READWRITE, &oldP);//&fThunk->u1.Function NOT reinterpret_cast<LPVOID>(fThunk-?&fThunk->u1.Function)
				fThunk->u1.Function = reinterpret_cast<uintptr_t>(HkMessageBoxA);// Without virtual prot theres a writing violation
				VirtualProtect(&fThunk->u1.Function, 32, oldP, &oldP);

				std::cout << "Found MessageBoxA\n";
			}

			oThunk++;//name table 
			fThunk++;//addr table
		}
		importsDesc++;//process each descriptor
	}

}




void copyFileBytesAndHeaders(std::vector<std::uint8_t> originalData, void* hLocal) {
	auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(originalData.data());
	auto NT = reinterpret_cast<PIMAGE_NT_HEADERS>(dos->e_lfanew + reinterpret_cast<uintptr_t>(originalData.data()));

	// Copy headers 
	memcpy(hLocal, originalData.data(), NT->OptionalHeader.SizeOfHeaders);
	// Copy Sections
	const auto* currentSection = IMAGE_FIRST_SECTION(NT);
	for (size_t i = 0; i < NT->FileHeader.NumberOfSections; i++, currentSection++) {
		memcpy(
			reinterpret_cast<void*>(reinterpret_cast<uint8_t*>(hLocal) + currentSection->VirtualAddress),
			originalData.data() + currentSection->PointerToRawData,
			currentSection->SizeOfRawData
		);
	}
}

static int count = 0;
int main() {
	//Current, "tampered" module. Prob run multiple scans so this main will have to repeat itself
	const HMODULE curr_Module = GetModuleHandleA(NULL);
	MessageBoxA(nullptr, "HEllo", "World", 0);
	//Allocated memory 
	std::vector<std::uint8_t> originalData = GetRawDllBytesFromFile("C:\\Users\\osawi\\source\\repos\\IAT scanner\\x64\\Debug\\IAT scanner.exe");
	auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(originalData.data());
    auto NT = reinterpret_cast<PIMAGE_NT_HEADERS>(dos->e_lfanew + reinterpret_cast<uintptr_t>(originalData.data()));

	//Allocate mem for a local exe in mem
	void* hLocal = VirtualAlloc(nullptr, NT->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!hLocal) {
		std::cout << "error allocating  mem for local origional data\n";
		return 0;
	}
	copyFileBytesAndHeaders(originalData, hLocal);//copy headers into local memory(originalData)

	while (true) {
		if (GetAsyncKeyState(VK_F9) && 1) {
			break;
		}
		if (GetAsyncKeyState(VK_F10) && 1) {
			if (count == 0) {// Only want to do this once
				hookIAT(curr_Module, "user32.dll", "MessageBoxA");
				count++;
			}
		}
		// Should convert rawdata to HMODULE(to then be turned into PE  stuff
		if (!IAT_Scanner(curr_Module, reinterpret_cast<HMODULE>(hLocal))) {
			std::cout << "[-] An import has been tampered with\n";
			return 0;
		}
		Sleep(3000);
		std::cout << "[+] IAT scan complete." << std::endl;
	}
	std::cout << "[+] IAT has NOT been tampered with" << std::endl;

	return 0;
}