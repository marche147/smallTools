/*
* floppy.cpp - floppy image read/write
* Author : Marche147 [bitmarche@gmail.com]
* Description : 
* TODO #1 : Add FAT-12 Support
*/

#pragma warning(disable:4005)	// MACRO REDEFINITION

#include "../CommonLib/common.h"
#include <ntstatus.h>
#pragma comment(lib, "../x64/Release/syscall.lib")
#pragma comment(lib, "../x64/Release/CommonLib.lib")

#define FLOPPY_SIZE 1440 * 1024

void __declspec(noreturn) usage(char* path)
{
	printf("Usage : %s command [options]\n", path);
	puts("Available commands :");
	puts("\tcreate [path] - creates a empty floppy image");
	puts("\tformat [path] [type] - formats the image");
	puts("\twrite_raw [pos] [bin] [path] [size] - write raw binary data to image");
	ExitProcess(0);
}

void __declspec(noreturn) fatal(char* err)
{
	printf("[FATAL] %s : GetLastError() = %d\n", err, GetLastError());
	ExitProcess(-1);
}

int main(int argc, char* argv[])
{
	char* command = argv[1];
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hMapping = NULL;
	PVOID pBase = NULL;
	if (argc <= 1)	usage(argv[0]);
	char* path = NULL;
	void* p;
	DWORD written, read;

	if (!strcmp(command, "create")) {
		path = argv[2];
		if (!path)	path = "floppy.img";
		hFile = CreateFileA(path, FILE_ALL_ACCESS, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			fatal("CreateFile");
		}
		void* m = MALLOC(FLOPPY_SIZE);
		if (!m) {
			fatal("HeapAlloc");
		}
		if (!WriteFile(hFile, m, FLOPPY_SIZE, &written, NULL)) {
			fatal("WriteFile");
		}
	}
	else if (!strcmp(command, "write_raw")) {
		if (argc <= 4) usage(argv[0]);
		path = argv[4];
		DWORD pos = atoi(argv[2]);
		char* bin_path = argv[3];
		DWORD size = 0, size_hi;
		HANDLE hBinFile = CreateFileA(bin_path, FILE_GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hBinFile == INVALID_HANDLE_VALUE) {
			fatal("CreateFile(BinPath)");
		}
		hFile = CreateFileA(path, FILE_READ_ACCESS | FILE_WRITE_ACCESS | FILE_GENERIC_EXECUTE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			fatal("CreateFile(Path)");
		}
		if (GetFileSize(hFile, &size_hi) != FLOPPY_SIZE) {
			printf("[-] Invalid floppy image.\n");
			CloseHandle(hBinFile);
			goto BailOut;
		}

		if (argc == 6)	size = atoi(argv[5]);
		else size = GetFileSize(hBinFile, &size_hi);
		if (size + pos >= FLOPPY_SIZE || size + pos < size) {
			printf("[-] Invalid file size\n");
			CloseHandle(hBinFile);
			goto BailOut;
		}
		p = MALLOC(size);
		if (!p)	fatal("HeapAlloc");
		if (!ReadFile(hBinFile, p, size, &read, NULL)) fatal("ReadFile");
		if (size != read)	fatal("ReadFile(Partial)");
		hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
		if (!hMapping) fatal("CreateFileMapping");
		pBase = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		if (!pBase) fatal("MapViewOfFile");

		memcpy((char*)(pBase)+pos, p, size);

		FREE(p);
		CloseHandle(hBinFile);
	}

BailOut:

	if (hFile != INVALID_HANDLE_VALUE)	CloseHandle(hFile);
	if (pBase) {
		FlushViewOfFile(pBase, 0);
		UnmapViewOfFile(pBase);
	}
	if (hMapping) CloseHandle(hMapping);

	printf("[+] Done!\n");
	return 0;
}