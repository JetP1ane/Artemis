#include <windows.h>
#include <subauth.h>
#include <stdio.h>

typedef struct PEB {
    UINT64*  BaseAddr;
    BYTE    Reserved1[2];
    BYTE    BeingDebugged;
    UINT64    Ldr; // 2 bytes
} PEB, *PPEB;


typedef struct LDR_DATA {
    UINT64 InLoadOrderModuleList;
    UINT64 InMemoryOrderModuleList;    
} LDR, *PLDR;


typedef struct LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    UINT64* EntryPoint;
    ULONG SizeOfImage;
    std::wstring FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


// Portable Executable
typedef struct PE_Header {
    UINT64* MagicNumber;
    BYTE e_lfanew;
    UINT64 ImageBase;
} PE_HEADER, *PPE_HEADER;


typedef struct PE_EXPORT_DIRECTORY {
    UINT64 AddressOfFunctions;
    UINT64 AddressOfNames;
} PE_BODY, *PPE_BODY;