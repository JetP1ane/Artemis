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


class Artemis {

    public:
        DWORD read_control = 0x0400;
        ArtemisData artemisStruct;
        PEB pebStruct;
        LDR_DATA ldrStruct;
        LDR_DATA_TABLE_ENTRY ldrEntryStruct;
        PE_HEADER peHeaderStruct;
        PE_EXPORT_DIRECTORY exportDirectoryStruct;


    UINT64 walkPEB(std::wstring fileName) {

        UINT64 uiPeb = __readgsqword(0x60);
        UINT64* ptr = (UINT64*)uiPeb;
        pebStruct.BaseAddr = ptr;
        pebStruct.Ldr = *(ptr+0x3);
        artemisStruct.BaseAddr = *(ptr+0x2);
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
        
        return uiPeb;

    }

    void walkPE(std::string targetFunction) {

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
                    //TODO: Step through this Byte by Byte, so dereference with BYTE
                    printf("\nFunction Addr Ptr Data: %p", *((UINT64*)funcAddress));
                    syscallExtractor(funcAddress);  // Pass function Ptr to syscallExtractor to snag the Id

                    break;
                }

                functionNameArray.clear();
                functionName.clear();

                funcTick++;

                //break;
            }

            tick++;    // increment
            
            //break;

        }

    }

    int syscallExtractor(UINT64 functionPtr) {

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
                    int syscallID = *((BYTE*)(window+0x1)); // Go plus 0x1 from the end of the window to snag the syscall ID value
                    printf("\n[+] Syscall Id: %x", syscallID);  // print Hex value
                    break;
                 }
            }

            printf("\nAssembly: %p", *assembly);

            tick++;

        }
        
        return 0x0;
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

};


void main(int argc, char* argv[]) {

        Artemis artemis;

        std::wstring fileName = L"ntdll.dll";

        artemis.walkPEB(fileName);
        artemis.walkPE((std::string)argv[1]);

    }