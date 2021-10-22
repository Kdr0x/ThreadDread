#pragma once

#include <cstdlib>
#include <cstdio>
#include "ws2tcpip.h"
#include "winsock2.h"
#include "windows.h"
#include "tlhelp32.h"
#include "psapi.h"
#include "yara.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "kernel32.lib")

struct MODESARGS
{
	// Pointer to the Thread ID and Process ID strings in the command line arguments once found
	char* tidstr;
	char* pidstr;
	char* reportServerAddress;
	char* reportServerPort;
	char* dumpAddress;
	char* queryAddress;
	char* zeroAddress;
	char* regionSize;
	char* yaraSource;

	// Mode switches
	bool targetListMode;
	bool fullListMode;
	bool yaraMode;
	bool yaraSourceMode;
	bool dumpMode;
	bool modListMode;
	bool modHuntMode;
	bool procListMode;
	bool queryMode;
	bool zeroMode;
	bool legendMode;
	bool networkMode;
	bool helpMode;
	bool threadResumeMode;
	bool threadSuspendMode;
	bool threadKillMode;
	bool threadListMode;

	// Hold a Process ID and Thread ID
	DWORD pid;
	DWORD tid;
	DWORD timer;
};



// Type definition for NtQueryInformationThread() inside ntdll.dll
typedef NTSTATUS(WINAPI* PNQIT)(HANDLE, DWORD, PVOID, ULONG, PULONG);

