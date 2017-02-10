/*
 * listdrv.cpp - List loaded kernel modules.
 * Author : Marche147 [bitmarche@gmail.com]
 * Description : 
 */

#pragma warning(disable:4005)	// MACRO REDEFINITION

#include "../CommonLib/common.h"
#include <ntstatus.h>
#pragma comment(lib, "../x64/Release/syscall.lib")
#pragma comment(lib, "../x64/Release/CommonLib.lib")

extern pNtQuerySystemInformation NtQuerySystemInformation;
extern pRtlNtStatusToDosError RtlNtStatusToDosError;

void __declspec(noreturn) fatal(char* str)
{
	printf("[-] Fatal error : %s, GetLastError() = %u.\n", str, GetLastError());
	ExitProcess(-1);
}

void __declspec(noreturn) usage(char* str)
{
	printf("Usage : %s [options]\n", str);
	puts("Options :");
	puts("\t/h - show help information");
	puts("\t/f [by] - find module by name");
	ExitProcess(0);
}

int main(int argc, char* argv[])
{
	PSYSTEM_MODULE_INFORMATION psmi = NULL;
	ULONG retlen = 0;
	NTSTATUS s;
	static bool g_Find = false;
	static char* g_FindStr = NULL;

	for (int arg = 1;arg < argc;arg++) {
		if (strcmp(argv[arg], "/h") == 0) {
			usage(argv[0]);
		}
		else if (strcmp(argv[arg], "/f") == 0) {
			g_Find = true;
			if (arg == argc - 1) {
				puts("Missing target after option \"/f\"");
				usage(argv[0]);
			}
			g_FindStr = argv[++arg];
		}
		else {
			usage(argv[0]);
		}
	}

	if (!NtQuerySystemInformation) {
		HMODULE m = LoadLibraryA("ntdll.dll");
		if (!m) {
			fatal("Cannot load NTDLL.DLL");
		}
		NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(m, "NtQuerySystemInformation");
		if (!NtQuerySystemInformation) {
			fatal("Cannot find entry point of NtQuerySystemInformation");
		}
		RtlNtStatusToDosError = (pRtlNtStatusToDosError)GetProcAddress(m, "RtlNtStatusToDosError");
		if (!RtlNtStatusToDosError) {
			fatal("Cannot find entry point of RtlNtStatusToDosError");
		}
	}

	s = NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &retlen);
	if (s == STATUS_BUFFER_TOO_SMALL || s == STATUS_INFO_LENGTH_MISMATCH) {
		psmi = (PSYSTEM_MODULE_INFORMATION)halloc(retlen);
		s = NtQuerySystemInformation(SystemModuleInformation, psmi, retlen, &retlen);
		if (!NT_SUCCESS(s)) {
			SetLastError(RtlNtStatusToDosError(s));
			hfree(psmi);
			fatal("Query error");
		}
	}
	else {
		SetLastError(RtlNtStatusToDosError(s));
		fatal("Query error when asking for length");
	}

	printf("ImagaName\t\tBase\t\tSize\t\tFullPath\n");
	printf("--------------------------------------------------------------------\n");
	for (DWORD i = 0;i < psmi->Count;i++) {
		if(!g_Find)
			printf("%s\t\t%p\t\t0x%X\t\t%s\n", psmi->Module[i].ImageName + psmi->Module[i].PathLength, psmi->Module[i].Base, psmi->Module[i].Size, psmi->Module[i].ImageName);
		else {
			if (strstr(psmi->Module[i].ImageName + psmi->Module[i].PathLength, g_FindStr)) {
				printf("%s\t\t%p\t\t0x%X\t\t%s\n", psmi->Module[i].ImageName + psmi->Module[i].PathLength, psmi->Module[i].Base, psmi->Module[i].Size, psmi->Module[i].ImageName);
			}
		}
	}

	if (psmi) {
		hfree(psmi);
	}
	return 0;
}