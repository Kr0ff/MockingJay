#include <windows.h>
#include <psapi.h>
#include <stdio.h>

// pStartAddress - Start address of the RWX section
// dwSectionSize - Size of the RWX section
typedef struct _MOCKINGJAY_INFO {
	LPVOID	pStartAddress;
	DWORD	dwSizeSection;
} MOCKINGJAY_INFO;

LPVOID DiscoverRWXSection();
int ExecuteMockingJay(unsigned char shellcode[], SIZE_T shellcodeSize);