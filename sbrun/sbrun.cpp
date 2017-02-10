/*
* sbrun.cpp - Runs an executable with security settings
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

void __declspec(noreturn) fatal(char* str)
{
	printf("[-] Fatal error : %s, GetLastError() = %u.\n", str, GetLastError());
	ExitProcess(-1);
}

void __declspec(noreturn) usage(char* str)
{
	printf("Usage : %s [options] -- <appPath>\n", str);
	puts("Options :");

	// misc 
	puts("\tMisc :");
	puts("\t-h, --help - show help information");
	puts("\t-w, --wait - wait until child terminates and redirect stdin/out/err");
	puts("\t-c, --command - command line passed to the child");

	// token related
	puts("");
	puts("\tToken related :");
	puts("\t-a, --appcontainer - enables AppContainer (cannot be used with mitigation policy)");
	//puts("\t--cap <Name> - add capability SID");	// TODO
	puts("\t-l, --level <level> - integrity level");
	//puts("\t-r <SID> - add restrict SID");	// TODO

	// mitigations
	puts("");
	puts("\tMitigation Policy :");
	puts("\t--dep - enable DEP");
	puts("\t--sehop - enable SEHOP");
	puts("\t--nowin32k - disable win32k system calls");
	puts("\t--shandle - strict handle check");
	puts("\t--nochild - disable child process creation");
	puts("\t--noreloc - no force image relocation");
	puts("\t--noheapterm - disable heap terminate on corruption");
	puts("\t--nobuaslr - no bottom up aslr");
	puts("\t--noheaslr - no high entropy aslr");
	puts("\t--noep - disable extension points");
	puts("\t--nodyncode - disable dynamic code execution");
	puts("\t--nofont - disallow font loading");
	puts("\t--sil - strict image loading");

	// job related
	puts("");
	puts("\tJob related :");
	puts("\t--rui - enable basic-ui restriction");
	puts("\t-t, --time <timeout> - enable timeout");
	puts("\t-m, --memory <memlimit> - sets memory limit");
	
	ExitProcess(0);
}

void DumpSidInfo(PSID sid)
{
	char buffer[260];
	char refdom[260];
	DWORD cchName = 260;
	DWORD cchRefDom = 260;
	SID_NAME_USE snu;

	if (LookupAccountSidA(NULL, sid, buffer, &cchName, refdom, &cchRefDom, &snu))
	{
		printf("name : %s\n", buffer);
		printf("ref domain : %s\n", refdom);
	}
	else
	{
		printf("failed lookup account sid. %d\n", GetLastError());
	}

	return;
}

int main(int argc, char* argv[])
{
	/* Options */
	static bool bNoWin32k = false, \
		bAppContainer = false, \
		bNoChild = false, \
		bReloc = true, \
		bHeapTerm = true, \
		bBUASLR = true, \
		bHEASLR = true, \
		bStrictHandle = false, \
		bDEP = false, \
		bSEHOP = false, \
		bDisableEP = false, \
		bNoDyncode = false, \
		bDisableFontLoad = false, \
		bSIL = false, \
		bWait = false, \
		bRestricted = false, \
		bRestrictUI = false;
	static char* szAppName = NULL, * szCommandLine = NULL;
	static DWORD dwIntLevel = SECURITY_MANDATORY_LOW_RID;
	static DWORD dwCapabilityCount = 0;
	static DWORD dwTimeout = -1;
	static SIZE_T dwMemoryLimit = -1;


	int i;
	STARTUPINFOEXA si;
	PROCESS_INFORMATION pi;
	LPPROC_THREAD_ATTRIBUTE_LIST pptal = NULL;
	SIZE_T ulRetSize = 0;
	HANDLE hToken = NULL, hNewToken = NULL;
	BOOL bRet;
	SECURITY_CAPABILITIES sc = { 0 };
	DWORD dwAttribCount = 0;
	TOKEN_MANDATORY_LABEL tml;
	PSID pAppContainerSID = NULL;
	WCHAR wszAppName[0x200];
	HRESULT hr;
	PSID_AND_ATTRIBUTES pCapabilies = NULL;
	HANDLE hJob = NULL;

	for (i = 1;i < argc; i++) {
		char* szTemp;
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			usage(argv[0]);
		}
		else if (!strcmp(argv[i], "-a") || !strcmp(argv[i], "--appcontainer")) {
			bAppContainer = true;
		}
		else if (!strcmp(argv[i], "--nowin32k")) {
			bNoWin32k = true;
		}
		else if (!strcmp(argv[i], "--nochild")) {
			bNoChild = true;
		}
		else if (!strcmp(argv[i], "--noreloc")) {
			bReloc = false;
		}
		else if (!strcmp(argv[i], "--noheapterm")) {
			bHeapTerm = false;
		}
		else if (!strcmp(argv[i], "--nobuaslr")) {
			bBUASLR = false;
		}
		else if (!strcmp(argv[i], "--noheaslr")) {
			bHEASLR = false;
		}
		else if (!strcmp(argv[i], "--shandle")) {
			bStrictHandle = true;
		}
		else if (!strcmp(argv[i], "--sehop")) {
			bSEHOP = true;
		}
		else if (!strcmp(argv[i], "--dep")) {
			bDEP = true;
		}
		else if (!strcmp(argv[i], "--noep")) {
			bDisableEP = true;
		}
		else if (!strcmp(argv[i], "--nodyncode")) {
			bNoDyncode = true;
		}
		else if (!strcmp(argv[i], "--nofont")) {
			bDisableFontLoad = true;
		}
		else if (!strcmp(argv[i], "--sil")) {
			bSIL = true;
		}
		else if (!strcmp(argv[i], "-w") || !strcmp(argv[i], "--wait")) {
			bWait = true;
		}
		else if (!strcmp(argv[i], "--")) {
			szAppName = argv[++i];
			if (!szAppName) {
				fatal("Missing application path");
			}
			break;
		}
		else if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--command")) {
			szCommandLine = argv[++i];
			if (!szCommandLine) {
				fatal("Missing command line");
			}
		}
		else if (!strcmp(argv[i], "-l") || !strcmp(argv[i], "--level")) {
			szTemp = argv[++i];
			if (!szTemp) {
				fatal("Missing argument");
			}
			if (!_stricmp(szTemp, "untrusted")) {
				dwIntLevel = SECURITY_MANDATORY_UNTRUSTED_RID;
			}
			else if (!_stricmp(szTemp, "low")) {
				dwIntLevel = SECURITY_MANDATORY_LOW_RID;
			}
			else if (!_stricmp(szTemp, "medium")) {
				dwIntLevel = SECURITY_MANDATORY_MEDIUM_RID;
			}
			else if (!_stricmp(szTemp, "high")) {
				dwIntLevel = SECURITY_MANDATORY_HIGH_RID;
			}
			else if (!_stricmp(szTemp, "system")) {
				dwIntLevel = SECURITY_MANDATORY_SYSTEM_RID;
			}
			else {
				fatal("Unknown integrity level");
			}
		}
		else if (!strcmp(argv[i], "--rui")) {
			bRestrictUI = true;
		}
		else if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--time")) {
			szTemp = argv[++i];
			if (!szTemp) {
				fatal("Missing argument");
			}
			dwTimeout = atoi(szTemp);
		}
		else if (!strcmp(argv[i], "-m") || !strcmp(argv[i], "--memory")) {
			szTemp = argv[++i];
			if (!szTemp) {
				fatal("Missing argument");
			}
			size_t iTemp = strlen(szTemp) - 1;
			dwMemoryLimit = atoi(szTemp);
			switch (szTemp[iTemp]) {
			case 'k':
			case 'K':
				dwMemoryLimit *= 1024;
				break;
			case 'm':
			case 'M':
				dwMemoryLimit *= (1024 * 1024);
				break;
			case 'g':
			case 'G':
				dwMemoryLimit *= (1024 * 1024 * 1024);
				break;
			default:
				break;
			}
		}
		else {
			usage(argv[0]);
		}
	}

	if (szAppName == NULL)	usage(argv[0]);

	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&sc, sizeof(sc));
	dwAttribCount = 2;
	//if (bAppContainer)	dwAttribCount++;

	InitializeProcThreadAttributeList(NULL, dwAttribCount, 0, &ulRetSize);
	if (ulRetSize == 0) {
		fatal("Can't initialize pptal");
	}
	//printf("ulRetSize = %d\n", ulRetSize);
	pptal = (LPPROC_THREAD_ATTRIBUTE_LIST)halloc(ulRetSize);
	if (!pptal) {
		fatal("Memory allocation failure");
	}
	if (!InitializeProcThreadAttributeList(pptal, dwAttribCount, 0, &ulRetSize)) {
		fatal("Cannot init pptal");
	}

	/* Mitigation policy */
	if (!bAppContainer) {	// GetLastError() = 87 if Mitigation policy and Security capability is both used ???
		ULONG64 dwMitigation = 0;
		if (bNoWin32k) {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON;
		}
		else {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_OFF;
		}
		if (bDEP) {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE;
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE;
		}
		if (bSEHOP) {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE;
		}
		if (bReloc) {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON;
		}
		else {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_OFF;
		}
		if (bHeapTerm) {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON;
		}
		else {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_OFF;
		}
		if (bBUASLR) {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON;
		}
		else {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_OFF;
		}
		if (bHEASLR) {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON;
		}
		else {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_OFF;
		}
		if (bStrictHandle) {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON;
		}
		else {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_OFF;
		}
		if (bDisableEP) {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON;
		}
		else {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_OFF;
		}
		if (bNoDyncode) {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
		}
		else {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_OFF;
		}
		if (bDisableFontLoad) {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_ON;
		}
		else {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_OFF;
		}
		if (bSIL) {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON;
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON;
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON;
		}
		else {
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_OFF;
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_OFF;
			dwMitigation |= PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_OFF;
		}
		if (!UpdateProcThreadAttribute(pptal, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &dwMitigation, sizeof(dwMitigation), NULL, NULL)) {
			fatal("Can't set mitigation policy");
		}
	}

	/* Child process policy */
	DWORD dwChildPolicy = 0;
	if (bNoChild) {
		dwChildPolicy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
	}
	if (!UpdateProcThreadAttribute(pptal, 0, PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &dwChildPolicy, sizeof(dwChildPolicy), NULL, NULL)) {
		fatal("Can't set child process policy");
	}

	/* Restricted token */
	if (bRestricted) {
		// TODO
		fatal("TODO");
	}
	else {
		bRet = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
		if (!bRet) {
			fatal("Failed to init token");
		}
		if (!DuplicateTokenEx(hToken, 0, NULL, SecurityImpersonation, TokenPrimary, &hNewToken)) {
			fatal("Failed to duplicate handle");
		}
	}

	/* Integrity level */
	PSID pIntegrityLevelSid = NULL;
	SID_IDENTIFIER_AUTHORITY sia = SECURITY_MANDATORY_LABEL_AUTHORITY;
	if (!bAppContainer) {
		if (!AllocateAndInitializeSid(&sia, 1, dwIntLevel, 0, 0, 0, 0, 0, 0, 0, &pIntegrityLevelSid)) {
			fatal("Cannot allocate SID");
		}
		tml.Label.Attributes = SE_GROUP_INTEGRITY;
		tml.Label.Sid = pIntegrityLevelSid;
		if (!SetTokenInformation(hNewToken, TokenIntegrityLevel, &tml, sizeof(tml) + GetLengthSid(pIntegrityLevelSid))) {
			fatal("Cannot update new token information");
		}
	}

	/* AppContainer */
	if (bAppContainer) {
		AnsiToUTF8(szAppName, wszAppName, sizeof(wszAppName));
		hr = FindOrCreateAppContainerProfileEx(wszAppName, L"TempAppContainer", NULL, 0, &pAppContainerSID);
		if (hr != S_OK) {
			SetLastError(HRESULT_CODE(hr));
			fatal("Failed to create AppContainer profile");
		}
		//DumpSidInfo(pAppContainerSID);
		sc.AppContainerSid = pAppContainerSID;
		sc.CapabilityCount = 0;
		sc.Capabilities = NULL;
		sc.Reserved = 0;
		if (!UpdateProcThreadAttribute(pptal, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &sc, sizeof(sc), NULL, NULL)) {
			fatal("Can't set security capabilities");
		}
	}

	/* job object */
	hJob = CreateJobObject(NULL, NULL);
	if (!hJob) {
		fatal("Can't create anonymous job object");
	}
	if (bRestrictUI) {
		JOBOBJECT_BASIC_UI_RESTRICTIONS jbur;
		jbur.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP;
		jbur.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_DISPLAYSETTINGS;
		jbur.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_EXITWINDOWS;
		jbur.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_GLOBALATOMS;
		jbur.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_HANDLES;
		jbur.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_READCLIPBOARD;
		jbur.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;
		jbur.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
		if (!SetInformationJobObject(hJob, JobObjectBasicUIRestrictions, &jbur, sizeof(jbur))) {
			fatal("Can't set restrct UI information");
		}
	}
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
	if (dwTimeout != -1) {
		ZeroMemory(&jeli, sizeof(jeli));
		jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_TIME;
		jeli.BasicLimitInformation.PerProcessUserTimeLimit.LowPart = dwTimeout;
		if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli))) {
			fatal("Can't set timeout information");
		}
	}
	if (dwMemoryLimit != -1) {
		ZeroMemory(&jeli, sizeof(jeli));
		jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
		jeli.ProcessMemoryLimit = dwMemoryLimit;
		if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli))) {
			fatal("Can't set memory limit information");
		}
	}
	
	/* create process */
	si.StartupInfo.cb = sizeof(si);
	if (bWait) {
		si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
		si.StartupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
		si.StartupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
		si.StartupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
	}
	si.lpAttributeList = pptal;

	bRet = CreateProcessAsUserA(hNewToken, szAppName, szCommandLine, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, NULL, NULL, &si.StartupInfo, &pi);

	if (!bRet) {
		fatal("Failed to create process");
	}

	if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
		TerminateProcess(pi.hProcess, -1);
		fatal("Can't assign process to job object");
	}

	ResumeThread(pi.hThread);
	CloseHandle(pi.hThread);
	if (bWait) {
		WaitForSingleObject(pi.hProcess, INFINITE);
	}
	else {
		printf("[+] Process %d Started.\n", pi.dwProcessId);
	}

	if (hToken)	CloseHandle(hToken);
	if (hNewToken) CloseHandle(hNewToken);
	if (pptal)	hfree(pptal);
	if (pIntegrityLevelSid)	FreeSid(pIntegrityLevelSid);
	if (hJob)	CloseHandle(hJob);
	return 0;
}