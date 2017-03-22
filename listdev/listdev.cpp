/*
* listdev.cpp - list nt devices info
* Author : Marche147 [bitmarche@gmail.com]
* Description :
*/

#pragma warning(disable:4005)	// MACRO REDEFINITION

#include "../CommonLib/common.h"
#include <ntstatus.h>
#include <list>
#include "../kMisc/kMisc.h"

#pragma comment(lib, "../x64/Release/syscall.lib")
#pragma comment(lib, "../x64/Release/CommonLib.lib")

pNtOpenDirectoryObject NtOpenDirectoryObject = NULL;
pNtQueryDirectoryObject NtQueryDirectoryObject = NULL;
pNtOpenFile NtOpenFile = NULL;
BOOL g_DriverLoaded = FALSE;
HANDLE g_Device = INVALID_HANDLE_VALUE;
char* g_FindDevice = NULL;
BOOL g_Detail = FALSE;

char* g_MajorFunctions[] = {
 "IRP_MJ_CREATE",                   
 "IRP_MJ_CREATE_NAMED_PIPE",
 "IRP_MJ_CLOSE",                    
 "IRP_MJ_READ",                     
 "IRP_MJ_WRITE",
 "IRP_MJ_QUERY_INFORMATION",
 "IRP_MJ_SET_INFORMATION",
 "IRP_MJ_QUERY_EA",
 "IRP_MJ_SET_EA",
 "IRP_MJ_FLUSH_BUFFERS",
 "IRP_MJ_QUERY_VOLUME_INFORMATION",
 "IRP_MJ_SET_VOLUME_INFORMATION",
 "IRP_MJ_DIRECTORY_CONTROL",
 "IRP_MJ_FILE_SYSTEM_CONTROL",
 "IRP_MJ_DEVICE_CONTROL",
 "IRP_MJ_INTERNAL_DEVICE_CONTROL",
 "IRP_MJ_SHUTDOWN",
 "IRP_MJ_LOCK_CONTROL",
 "IRP_MJ_CLEANUP",
 "IRP_MJ_CREATE_MAILSLOT",
 "IRP_MJ_QUERY_SECURITY",           
 "IRP_MJ_SET_SECURITY",
 "IRP_MJ_POWER",
 "IRP_MJ_SYSTEM_CONTROL",
 "IRP_MJ_DEVICE_CHANGE",
 "IRP_MJ_QUERY_QUOTA",
 "IRP_MJ_SET_QUOTA",
 "IRP_MJ_PNP",
};

void __declspec(noreturn) fatal(char* str)
{
	dprintf("[FATAL] %s : GetLastError() = %d\n", str, GetLastError());
	ExitProcess(-1);
}

void error(char* str)
{
	dprintf("[ERROR] %s : GetLastError() = %d\n", str, GetLastError());
	return;
}

void PrintObjectInfo(PUNICODE_STRING ustrObjName, PUNICODE_STRING ustrTypeName)
{
	printf("Object : %ws, Type : %ws\n", ustrObjName->Buffer, ustrTypeName->Buffer);
	return;
}

void __declspec(noreturn) usage(char* path)
{
	printf("Usage : %s [options]\n", path);
	puts("Options - ");
	puts("\t/u - unload driver");
	puts("\t/s - safe mode (without driver loading)");
	puts("\t/f - detailed info");
	ExitProcess(0);
}

void PrintDeviceInfo(PWCHAR pDevPath)
{
	PWCHAR devPath = NULL;

	printf("Device : %ws\n", pDevPath);
	if (g_FindDevice) {
		size_t converted;
		devPath = (PWCHAR)MALLOC((strlen(g_FindDevice) + 1) * 2);
		mbstowcs_s(&converted, devPath, (strlen(g_FindDevice) + 1), g_FindDevice, _TRUNCATE);
		if (!wcsstr(pDevPath, devPath)) {
			FREE(devPath);
			return;
		}
		FREE(devPath);
	}

	if (g_Detail && g_DriverLoaded) {
		if (g_Device == INVALID_HANDLE_VALUE) {
			g_Device = CreateFile(USERSPACE_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
			if (g_Device == INVALID_HANDLE_VALUE) {
				fatal("CreateFile");
			}
		}
		DRIVER_BY_DEVICE_IO ioinfo;
		PWCHAR driverName;
		DWORD retlen;

		ZeroMemory(&ioinfo, sizeof(ioinfo));
		driverName = (PWCHAR)MALLOC(0x400);

		ioinfo.deviceName = pDevPath;
		ioinfo.deviceNameLen = wcslen(pDevPath) * 2 + 2;
		ioinfo.driverName = driverName;
		ioinfo.driverNameLen = 0x400;

		if (DeviceIoControl(g_Device, IOCTL_GET_DRIVER_INFO_BY_DEVICE, &ioinfo, sizeof(ioinfo), &ioinfo, sizeof(ioinfo), &retlen, NULL)) {
			printf("- Driver : %ws\n", ioinfo.driverName);
			printf("- DriverSection : %#p\n", ioinfo.driverSection);
			for (int i = 0;i < IRP_MJ_MAXIMUM_FUNCTION + 1;i++) {
				if(ioinfo.majorFunctions[i])
					printf("- MajorFunction[%s] : %#p\n", g_MajorFunctions[i], ioinfo.majorFunctions[i]);
			}
		}
		else {
			error("DeviceIoControl");
		}

		FREE(driverName);
	}
	return;
}

void EnumNTDirectory(HANDLE hDir, PCWSTR wRoot)
{
	ULONG retlen, context, r;
	POBJECT_DIRECTORY_INFORMATION odi = NULL;
	HANDLE hSubDir;
	NTSTATUS s;
	BOOL bRestart = TRUE;
	OBJECT_ATTRIBUTES oa;
	PWCHAR wSubDirName = NULL, wDevName;
	size_t clen;
	UNICODE_STRING ustrSubDirName;

	retlen = 1024 * sizeof(OBJECT_DIRECTORY_INFORMATION);
	odi = (POBJECT_DIRECTORY_INFORMATION)MALLOC(retlen);
	do
	{
		s = NtQueryDirectoryObject(hDir, odi, retlen, 0, bRestart, &context, &r);
		bRestart = FALSE;
		for (int i = 0;odi[i].Name.Buffer;i++) {
			if (wcscmp(odi[i].TypeName.Buffer, L"Directory") == 0) {
				// enum sub
				clen = wcslen(wRoot) * 2 + wcslen(odi[i].Name.Buffer) * 2 + 10;
				wSubDirName = (PWCHAR)MALLOC(clen);
				wcscpy_s(wSubDirName, clen, wRoot);
				wcscat_s(wSubDirName, clen, L"\\");
				wcscat_s(wSubDirName, clen, odi[i].Name.Buffer);
				RtlInitUnicodeString(&ustrSubDirName, wSubDirName);

				InitializeObjectAttributes(&oa, &ustrSubDirName, OBJ_CASE_INSENSITIVE, NULL, NULL);
				s = NtOpenDirectoryObject(&hSubDir, DIRECTORY_QUERY, &oa);
				if (NT_SUCCESS(s)) {
					EnumNTDirectory(hSubDir, wSubDirName);
					CloseHandle(hSubDir);
				}
				else {
					printf("[-] Error when enum directory %ws : %08x\n", wSubDirName, s);
				}
				FREE(wSubDirName);
			} else if (wcscmp(odi[i].TypeName.Buffer, L"Device") == 0) {
				//printf("Device : %ws\\%ws\n", wRoot, odi[i].Name.Buffer);
				wDevName = (PWCHAR)MALLOC(1024);
				wnsprintfW(wDevName, 1024, L"%ws\\%ws", wRoot, odi[i].Name.Buffer);
				PrintDeviceInfo(wDevName);
				FREE(wDevName);
			}
		}
	} while (s == STATUS_MORE_ENTRIES);
	FREE(odi);
	return;
}

int main(int argc, char* argv[])
{
	/* usage */

	HMODULE hNtDll = LoadLibrary(L"ntdll.dll");
	NTSTATUS s = STATUS_UNSUCCESSFUL;
	HANDLE hDir = NULL;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING ustrDirName;
	BOOL unload = FALSE;
	BOOL load = TRUE;

	for (int i = 1;i < argc;i++) {
		if (strcmp(argv[i], "/u") == 0) {
			unload = TRUE;
		}
		else if (strcmp(argv[i], "/s") == 0) {
			load = FALSE;
		}
		else if (strcmp(argv[i], "/f") == 0) {
			g_Detail = TRUE;
		}
		else if (strcmp(argv[i], "/n") == 0) {
			if (i == argc - 1) {
				puts("Missing name after /n");
				usage(argv[0]);
			}
			g_FindDevice = argv[++i];
		}
		else {
			usage(argv[0]);
		}
	}

	if (!CheckAndElevate()) {
		fatal("CheckAndElevate");
	}

	if (unload) {
		if (!UnloadDriver("kMisc")) {
			fatal("UnloadDriver");
		}
		printf("Driver successfully unloaded.\n");
		return 0;
	}

	if (load && !LoadDriver("kMisc", "kMisc.sys", FALSE)) {
		fatal("LoadDriver");
	}
	if(load)	g_DriverLoaded = TRUE;
	

	if(!hNtDll) {
		fatal("Cannot find ntdll");
	}
	NtQueryDirectoryObject = (pNtQueryDirectoryObject)GetProcAddress(hNtDll, "NtQueryDirectoryObject");
	NtOpenDirectoryObject = (pNtOpenDirectoryObject)GetProcAddress(hNtDll, "NtOpenDirectoryObject");
	NtOpenFile = (pNtOpenFile)GetProcAddress(hNtDll, "NtOpenFile");
	if (!NtQueryDirectoryObject || !NtOpenDirectoryObject || !NtOpenFile) {
		fatal("GetProcAddress");
	}

	UNICODE_STRING ustrFileName;
	HANDLE hFile;
	IO_STATUS_BLOCK iosb;
	RtlInitUnicodeString(&ustrFileName, L"\\UdfsCdrom");
	InitializeObjectAttributes(&oa, &ustrFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	s = NtOpenFile(&hFile, GENERIC_READ, &oa, &iosb, 0, FILE_OPEN);
	if (NT_SUCCESS(s)) {
		printf("success\n");
		CloseHandle(hFile);
	}
	else {
		printf("err : %08x\n", s);
	}

	RtlInitUnicodeString(&ustrDirName, L"\\");
	InitializeObjectAttributes(&oa, &ustrDirName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	s = NtOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &oa);
	if (!NT_SUCCESS(s)) {
		fatal("NtOpenDirectoryObject");
	}
	EnumNTDirectory(hDir, L"");

Finish:
	if (hDir) CloseHandle(hDir);
	return 0;
}