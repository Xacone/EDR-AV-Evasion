#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <pchannel.h>
#include <winternl.h>
#include <synchapi.h>

using namespace std;

int main() {

	HANDLE process = GetCurrentProcess();
	MODULEINFO mi = {};
	HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");

	GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
	LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;

	// File Object Mapping Utilities
	HANDLE ntdllFile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	cout << hookedDosHeader->e_magic << endl;
	cout << "LFA: " << hookedDosHeader->e_lfanew << endl;

	PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

	for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER*i));  
		cout << hookedSectionHeader->Name << endl;

		if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {

		}
	}



	cout << "Module's entry point : "  << mi.EntryPoint << 
		"\n Load address of module : " << mi.lpBaseOfDll << 
		"\n Image space : " << mi.SizeOfImage << endl;

	while (true) {
		Sleep(500000);
	}

	return 0;
}
