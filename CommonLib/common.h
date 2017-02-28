/*
 * common.h - Util functions
 * Author : Marche147 [bitmarche@gmail.com]
 * Description : 
 */

#ifndef _COMMON_H
#define _COMMON_H

#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <AclAPI.h>
#include <Psapi.h>
#include <UserEnv.h>
#include <Shlwapi.h>
#include <time.h>

#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

#define _COMMON_DEBUG
#define PAGE_SIZE	0x1000
#define _LOG_FILE

#ifdef _LOG_FILE
#define _LOG_PATH "C:\\"
#endif

typedef int int32_t;
typedef short int16_t;
typedef signed char int8_t;
typedef __int64 int64_t;
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
typedef unsigned __int64 uint64_t;

#define halloc(x)	(HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,x))
#define hfree(x)	(HeapFree(GetProcessHeap(),0,x))
#define MALLOC	halloc
#define FREE	hfree
#define ROUNDUP(x,align) (((x)+(align)-1)&(~((align)-1)))
#define dprintf(...)	fprintf(stderr,__VA_ARGS__)

typedef LONG NTSTATUS;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation
	// ...
} SYSTEM_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,          // Note: this is kernel mode only
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	ProcessWow64Information,
	ProcessImageFileName,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination,
	ProcessDebugObjectHandle,
	ProcessDebugFlags,
	ProcessHandleTracing,
	ProcessIoPriority,
	ProcessExecuteFlags,
	ProcessResourceManagement,
	ProcessCookie,
	ProcessImageInformation,
	MaxProcessInfoClass             // MaxProcessInfoClass should always be the last enum
} PROCESSINFOCLASS;

typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
);

typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID PebBaseAddress;
	ULONG_PTR AffinityMask;
	LONG BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION *PPROCESS_BASIC_INFORMATION;

typedef NTSTATUS (WINAPI *pNtQuerySystemInformation)(
	DWORD SystemInformationClass,
	PVOID SystemInformation,
	ULONG InformationLength,
	PULONG ReturnedLength
	);

typedef ULONG (WINAPI *pRtlNtStatusToDosError)(
	_In_ NTSTATUS Status
);

typedef NTSTATUS(WINAPI *pNtAllocateVirtualMemory)(
	_In_    HANDLE    ProcessHandle,
	_Inout_ PVOID     *BaseAddress,
	_In_    ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T   RegionSize,
	_In_    ULONG     AllocationType,
	_In_    ULONG     Protect
	);

typedef NTSTATUS
(WINAPI *pNtQueryIntervalProfile)(
	__in ULONG ProfileSource,
	__out PULONG Interval
	);

typedef VOID
(WINAPI *pDbgBreakPoint)();

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT PathLength;
	CHAR ImageName[256];
}SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG Count;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

#define NT_SUCCESS(s) (((LONG)(s))>=0)

/*
 * Function definitions
 */
#ifdef __x86__
uint32_t __stdcall  NtSyscall(uint32_t SyscallIndex,uint32_t ArgCount,void* ArgArray[]);
#else
uint64_t NtSyscall(uint64_t SyscallIndex,uint64_t ArgCount,void* ArgArray[]);
#endif 

PVOID GetProcFromModule(LPTSTR szModName,LPCSTR szFuncName);
BOOL EnablePrivilege(LPTSTR szPrivName);
void* GetKernelBaseEx(char* ImageName, size_t maxlen);
BOOL SetObjectSecurityDenyOne(HANDLE object, PSID sid, DWORD access);
DWORD FindProcessId(LPTSTR processName);
PVOID LoadExportedKernelSymAddress(LPTSTR SymName);
PVOID AllocateFixedPages(PVOID Address, ULONG PageCount);
VOID CallNtQueryIntervalProfile(void);
VOID Breakpoint(void);
HRESULT AddOrRemoveAceOnFileObjectAcl(BOOL IsRemoveOperation, LPCTSTR pszFilePath, PSID pSid, DWORD dwAccessMask);
DWORD RandRange32(DWORD min, DWORD max);
PVOID NtCurrentPeb(void);
VOID LogPrint(char* fmt, ...);
BOOL UTF8ToAnsi(WCHAR* wszUnicodeStr, CHAR* szAnsiStr, ULONG ulBufLen);
BOOL AnsiToUTF8(CHAR* szAnsiStr, WCHAR* wszUnicodeStr, ULONG ulBufLen);
BOOL GetTokenInformationEx(HANDLE token, TOKEN_INFORMATION_CLASS tlc, PVOID *info, DWORD* retlen);

/* AppContainer Related */
HRESULT FindOrCreateAppContainerProfileEx(LPCWSTR pszChildFilePath, LPCWSTR pszDescription, PSID_AND_ATTRIBUTES pCapabilities, DWORD dwCapabilityCount, PSID *ppSid);
HRESULT GetAppContainerSid(LPCWSTR pszChildFilePath, PSID *ppSid);
HRESULT DestroyAppContainerProfile(LPCWSTR pszChildFilePath);

/* Payloads */
#ifndef _WIN64
VOID TokenStealingPayloadWin7();
#endif

#endif