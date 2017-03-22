/*
* listdev.cpp - list nt devices info
* Author : Marche147 [bitmarche@gmail.com]
* Description :
*/

#pragma warning(disable:4005)	// MACRO REDEFINITION

#include "../CommonLib/common.h"
#include <ntstatus.h>
#include <list>
#pragma comment(lib, "../x64/Release/syscall.lib")
#pragma comment(lib, "../x64/Release/CommonLib.lib")

pNtOpenDirectoryObject NtOpenDirectoryObject = NULL;
pNtQueryDirectoryObject NtQueryDirectoryObject = NULL;
pNtOpenFile NtOpenFile = NULL;

void __declspec(noreturn) fatal(char* str)
{
	dprintf("[FATAL] %s : GetLastError() = %d\n", str, GetLastError());
	ExitProcess(-1);
}

void PrintObjectInfo(PUNICODE_STRING ustrObjName, PUNICODE_STRING ustrTypeName)
{
	printf("Object : %ws, Type : %ws\n", ustrObjName->Buffer, ustrTypeName->Buffer);
	return;
}

void PrintDeviceInfo(PUNICODE_STRING ustrDevPath)
{
	// TODO : Communicate with driver
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
	PWCHAR wSubDirName = NULL;
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
				printf("Device : %ws\\%ws\n", wRoot, odi[i].Name.Buffer);
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

	if (!CheckAndElevate()) {
		fatal("CheckAndElevate");
	}

	if(!hNtDll) {
		fatal("Cannot find ntdll");
	}
	NtQueryDirectoryObject = (pNtQueryDirectoryObject)GetProcAddress(hNtDll, "NtQueryDirectoryObject");
	NtOpenDirectoryObject = (pNtOpenDirectoryObject)GetProcAddress(hNtDll, "NtOpenDirectoryObject");
	NtOpenFile = (pNtOpenFile)GetProcAddress(hNtDll, "NtOpenFile");
	if (!NtQueryDirectoryObject || !NtOpenDirectoryObject || !NtOpenFile) {
		fatal("GetProcAddress");
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