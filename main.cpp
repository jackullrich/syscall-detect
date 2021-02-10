#include <Windows.h>
#include <DbgHelp.h>
#include <stdio.h>
#include <winternl.h>
#include <malloc.h>	
#include <tchar.h>
#include <Bits.h>

#if _DEBUG
#pragma comment(lib,"Dbghelp.lib")
#endif

extern "C" VOID InstrumentationCallbackThunk(VOID);
extern "C" VOID InstrumentationCallback(PCONTEXT ctx);

#define RIP_SANITY_CHECK(Rip,BaseAddress,ModuleSize) (Rip > BaseAddress) && (Rip < (BaseAddress + ModuleSize))

static ULONG_PTR g_NtdllBase;
static ULONG_PTR g_W32UBase;

static DWORD g_NtdllSize;
static DWORD g_W32USize;

VOID GetBaseAddresses() {

	PIMAGE_DOS_HEADER piDH;
	PIMAGE_NT_HEADERS piNH;

	g_NtdllBase = (ULONG_PTR)GetModuleHandle(TEXT("ntdll.dll"));
	piDH = (PIMAGE_DOS_HEADER)g_NtdllBase;
	piNH = (PIMAGE_NT_HEADERS)(g_NtdllBase + piDH->e_lfanew);

	g_NtdllSize = piNH->OptionalHeader.SizeOfImage;

	g_W32UBase = (ULONG_PTR)GetModuleHandle(TEXT("win32u.dll"));
	if (g_W32UBase) {
		piDH = (PIMAGE_DOS_HEADER)g_W32UBase;
		piNH = (PIMAGE_NT_HEADERS)(g_W32UBase + piDH->e_lfanew);
		g_W32USize = piNH->OptionalHeader.SizeOfImage;
	}
}

VOID InstrumentationCallback(PCONTEXT ctx)
{
	BOOLEAN bInstrumentationCallbackDisabled;
	ULONG_PTR NtdllBase;
	ULONG_PTR W32UBase;
	DWORD NtdllSize;
	DWORD W32USize;

#if _DEBUG
	BOOLEAN SymbolLookupResult;
	DWORD64 Displacement;
	PSYMBOL_INFO SymbolInfo;
	PCHAR SymbolBuffer[sizeof(SYMBOL_INFO) + 1024];
#endif

	ULONG_PTR pTEB = (ULONG_PTR)NtCurrentTeb();

	//
	// https://www.geoffchappell.com/studies/windows/win32/ntdll/structs/teb/index.htm
	//
	ctx->Rip = *((ULONG_PTR*)(pTEB + 0x02D8)); // TEB->InstrumentationCallbackPreviousPc
	ctx->Rsp = *((ULONG_PTR*)(pTEB + 0x02E0)); // TEB->InstrumentationCallbackPreviousSp
	ctx->Rcx = ctx->R10;

	//
	// Prevent recursion. TEB->InstrumentationCallbackDisabled
	//
	bInstrumentationCallbackDisabled = *((BOOLEAN*)pTEB + 0x1b8);

	if (!bInstrumentationCallbackDisabled) {

		//
		// Disabling for no recursion
		// 
		*((BOOLEAN*)pTEB + 0x1b8) = TRUE;

#if _DEBUG
		SymbolInfo = (PSYMBOL_INFO)SymbolBuffer;
		RtlSecureZeroMemory(SymbolInfo, sizeof(SYMBOL_INFO) + 1024);

		SymbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
		SymbolInfo->MaxNameLen = 1024;

		SymbolLookupResult = SymFromAddr(
			GetCurrentProcess(),
			ctx->Rip,
			&Displacement,
			SymbolInfo
		);
#endif

#if _DEBUG
		if (SymbolLookupResult) {
#endif
			NtdllBase = (ULONG_PTR)InterlockedCompareExchangePointer(
				(PVOID*)&g_NtdllBase,
				NULL,
				NULL
			);

			W32UBase = (ULONG_PTR)InterlockedCompareExchangePointer(
				(PVOID*)&g_W32UBase,
				NULL,
				NULL
			);

			NtdllSize = InterlockedCompareExchange(
				(DWORD*)&g_NtdllSize,
				NULL,
				NULL
			);

			W32USize = InterlockedCompareExchange(
				(DWORD*)&g_W32USize,
				NULL,
				NULL
			);

			if (RIP_SANITY_CHECK(ctx->Rip, NtdllBase, NtdllSize)) {

				if (NtdllBase) {

#if _DEBUG
					//
					// See if we can look up by name
					//
					PVOID pFunction = GetProcAddress((HMODULE)NtdllBase, SymbolInfo->Name);

					if (!pFunction) {
						printf("[-] Reverse lookup failed for function: %s.\n", SymbolInfo->Name);
					}
					else {
						printf("[+] Reverse lookup successful for function %s.\n", SymbolInfo->Name);
					}
#endif
				}
				else {
					printf("[-] ntdll.dll not found.\n");
				}
			}
			else if (RIP_SANITY_CHECK(ctx->Rip, W32UBase, W32USize)) {

				if (W32UBase) {

#if _DEBUG
					//
					// See if we can look up by name
					//
					PVOID pFunction = GetProcAddress((HMODULE)W32UBase, SymbolInfo->Name);

					if (!pFunction) {
						printf("[-] Reverse lookup failed for function: %s.\n", SymbolInfo->Name);
					}
					else {
						printf("[+] Reverse lookup successful for function %s.\n", SymbolInfo->Name);
					}
#endif
				}
				else {
					printf("[-] win32u.dll not found.\n");
				}
			}
			else {

				printf("[SYSCALL-DETECT] Kernel returns to unverified module, preventing further execution!\n");
#if _DEBUG
				printf("[SYSCALL-DETECT] Function: %s\n", SymbolInfo->Name);
#endif
				DebugBreak();
			}

#if _DEBUG
		}
		else {

			//
			// SymFromAddr failed
			//
			printf("SymFromAddr failed.\n");
			// DebugBreak();
		}
#endif
		//
		// Enabling so we can catch next callback.
		//
		* ((BOOLEAN*)pTEB + 0x1b8) = FALSE;
	}

	RtlRestoreContext(ctx, NULL);
}

typedef NTSTATUS(NTAPI* pNtSetInformationProcess)(
	HANDLE ProcessHandle,
	PROCESS_INFORMATION_CLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength
	);

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
	ULONG Version;
	ULONG Reserved;
	PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, * PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll"),
	"NtSetInformationProcess");

BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,
	DWORD fdwReason,
	LPVOID lpReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
	{

		
		//
		// Obtain ntdll and optionally w32u.dll's base address 
		//
		GetBaseAddresses();

#if _DEBUG
		LoadLibraryA("dbghelp.dll");
		SymSetOptions(SYMOPT_UNDNAME);
		SymInitialize(GetCurrentProcess(), NULL, TRUE);
#endif

		AllocConsole();
		freopen("CONOUT$", "w", stdout);

		printf("[SYSCALL-DETECT] Console logging started...\n");
		printf("[SYSCALL-DETECT] ntdll BaseAddress: 0x%lu\n", g_NtdllBase);
		printf("[SYSCALL-DETECT] win32u BaseAddress: 0x%lu\n", g_W32UBase);


		PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION nirvana;
		nirvana.Callback = (PVOID)(ULONG_PTR)InstrumentationCallbackThunk;
		nirvana.Reserved = 0;
		nirvana.Version = 0;

		NtSetInformationProcess(
			GetCurrentProcess(),
			(PROCESS_INFORMATION_CLASS)40,
			&nirvana,
			sizeof(nirvana));
	}
	break;
	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;

	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}