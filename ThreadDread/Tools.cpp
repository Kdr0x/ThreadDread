#include "Tools.h"

GCMEMORY::GCMEMORY()
{
	remoteAddress = 0;
	remoteSize = 0;
	localAddress = 0;
	localSize = 0;
	localHeap = 0;
	heapSize = 0;
	zeroMemory(&mbi, sizeof(MEMORY_BASIC_INFORMATION));
	heapHandle = 0;
}

bool GCMEMORY::allocateLocal(SIZE_T length, DWORD protect, DWORD type)
{
	// Allocate memory and zero it out
	localAddress = (char*)VirtualAlloc(0, length, type, protect);
	if (localAddress == 0) return false;

	for (SIZE_T i = 0; i < length; i++) localAddress[i] = (char)0x00;

	localSize = length;

	return true;
}

bool GCMEMORY::freeLocal()
{
	for (SIZE_T i = 0; i < localSize; i++) localAddress[i] = (char)0x00;
	if (VirtualFree(localAddress, 0, MEM_RELEASE) != 0)
	{
		localSize = 0;
		localAddress = 0;
		return true;
	}
	else return false;
}

bool GCMEMORY::allocateHeap(DWORD sz = 512)
{
	if (heapHandle == 0) heapHandle = GetProcessHeap();
	localHeap = (char*)HeapAlloc(heapHandle, HEAP_ZERO_MEMORY, sz);

	if (localHeap != 0)
	{
		heapSize = sz;
		return true;
	}
	else return false;
}

bool GCMEMORY::freeHeap()
{
	if (heapHandle == 0) heapHandle = GetProcessHeap();
	if (localHeap != 0) HeapFree(heapHandle, 0, localHeap);
	return true;
}

char* GCMEMORY::getLocalHeap() { return localHeap; }

SIZE_T GCMEMORY::getLocalHeapSize() { return heapSize; }

void GCMEMORY::setLocalHeapAddress(void* addr) { localHeap = (char*)addr; }

void GCMEMORY::setLocalHeapSize(SIZE_T size) { heapSize = size; }

bool GCMEMORY::remoteQuery(HANDLE hp)
{
	SIZE_T sResult = 0;

	zeroMBI();
	sResult = VirtualQueryEx(hp, remoteAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	if (sResult == 0) return false;
	else
	{
		remoteSize = mbi.RegionSize;
		return true;
	}
}

bool GCMEMORY::remoteCopy(HANDLE hp)
{
	BOOL bResult = 0;
	SIZE_T bRead = 0;

	if (localSize == remoteSize)
	{
		bResult = ReadProcessMemory(hp, remoteAddress, localAddress, localSize, &bRead);
	}

	if (bRead == localSize) return true;
	else return false;
}

MEMORY_BASIC_INFORMATION* GCMEMORY::getMemoryInfo() { return &mbi; }

void GCMEMORY::setMemoryInfo(MEMORY_BASIC_INFORMATION* mbiAddr) { copyMemory(&mbi, mbiAddr, sizeof(MEMORY_BASIC_INFORMATION)); }

char* GCMEMORY::getRemoteAddress() { return remoteAddress; }

SIZE_T GCMEMORY::getRemoteSize() { return remoteSize; }

char* GCMEMORY::getLocalAddress() { return localAddress; }

SIZE_T GCMEMORY::getLocalSize() { return localSize; }

void GCMEMORY::setRemoteAddress(char* addr) { remoteAddress = addr; }

void GCMEMORY::setRemoteBufferSize(SIZE_T size) { remoteSize = size; }

void GCMEMORY::setLocalBufferAddress(char* addr) { localAddress = addr; }

void GCMEMORY::setLocalBufferSize(SIZE_T size) { localSize = size; }

void GCMEMORY::zeroLocal() { zeroMemory(localAddress, localSize); }

void GCMEMORY::zeroMBI() { zeroMemory(&mbi, sizeof(MEMORY_BASIC_INFORMATION)); }

void GCMEMORY::setNewProtect(DWORD np) { nProt = np; }

void GCMEMORY::setOldProtect(DWORD op) { oProt = op; }

DWORD* GCMEMORY::getNewProtect() { return &nProt; }

DWORD* GCMEMORY::getOldProtect() { return &oProt; }

void GCOUTPUT::logOutput(char* b, unsigned long long s)
{
	buffer = b;
	bufferSize = s;

	switch (mode)
	{
	case 1:			// Socket mode
		rsocket->nsconnect();
		rsocket->nssend(buffer, strlen((char*)buffer));
		rsocket->nsclose();
		break;
	case 2:			// File mode
		break;
	default:		// Console mode
		printf((char*)buffer);
		break;
	}
}

void GCOUTPUT::logOutput(wchar_t* b, unsigned long long s)
{
	buffer = b;
	bufferSize = s;

	switch (mode)
	{
	case 1:			// Socket mode
		rsocket->nsconnect();
		rsocket->nssend(buffer, wcslen((wchar_t*)buffer));
		rsocket->nsclose();
		break;
	case 2:			// File mode
		break;
	default:		// Console mode
		wprintf((wchar_t*)buffer);
		break;
	}
}

bool GCOUTPUT::allocateBuffer(DWORD size)
{
	bufferSize = size;
	buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
	if (buffer != 0) return true;
	else return false;
}

void GCOUTPUT::freeBuffer() { HeapFree(GetProcessHeap(), 0, buffer); }

void* GCOUTPUT::getBuffer() { return buffer; }

SIZE_T GCOUTPUT::getBufferSize() { return bufferSize; }

bool GCOUTPUT::resolveHostNames()
{
	DWORD aSize = 20;
	DWORD wSize = 20;
	zeroMemory(cNameA, 20);
	zeroMemory(cNameW, 40);
	GetComputerNameA(cNameA, &aSize);
	GetComputerNameW(cNameW, &wSize);
	return true;
}

char* GCOUTPUT::getHostNameA() { return cNameA; }

wchar_t* GCOUTPUT::getHostNameW() { return cNameW; }

void GCOUTPUT::clear()
{
	HeapFree(GetProcessHeap(), 0, buffer);
	bufferSize = 0;
	zeroMemory(cNameA, 20);
	zeroMemory(cNameW, 40);
}

void GCOUTPUT::setMode(BYTE m) { mode = m; }

void GCOUTPUT::setSocket(CLISOCK* s) { rsocket = s; }

GCSNAPS::GCSNAPS()
{
	processSnapshot = 0;
	moduleSnapshot = 0;
	threadSnapshot = 0;
	zeroMemory(&te, sizeof(THREADENTRY32));
	zeroMemory(&me, sizeof(MODULEENTRY32));
	zeroMemory(&pe, sizeof(PROCESSENTRY32));
	targeted = false;
	pid = 0;
	tid = 0;
	firstProcess = true;
	firstThread = true;
	firstModule = true;
}

bool GCSNAPS::logModules(GCOUTPUT * o)
{
	zeroMemory(&me, sizeof(MODULEENTRY32));
	me.dwSize = sizeof(MODULEENTRY32);

	DWORD nlen = 20;
	char cn[20];
	zeroMemory(cn, nlen);
	GetComputerNameA(cn, &nlen);

	char outmsg[1024];
	zeroMemory(outmsg, 1024);

	Module32First(moduleSnapshot, &me);
	DWORD lpid = me.th32ProcessID;

	do
	{
		_snprintf(outmsg, 1024, "ModuleList %s,%u,%s,%p,0x%X,%s\n", cn, lpid, me.szModule, me.modBaseAddr, me.modBaseSize, me.szExePath);
		o->logOutput(outmsg, 1024);
		zeroMemory(outmsg, 1024);
		zeroMemory(&me, sizeof(MODULEENTRY32));
		me.dwSize = sizeof(MODULEENTRY32);
	} while (Module32Next(moduleSnapshot, &me) != 0);
	return true;
}

bool GCSNAPS::logProcesses(GCOUTPUT * o, void* P)
{
	zeroMemory(&pe, sizeof(PROCESSENTRY32));
	pe.dwSize = sizeof(PROCESSENTRY32);

	GCPROCESS* p = (GCPROCESS*)P;
	SYSTEMTIME* ps = 0;

	DWORD nlen = 20;
	char cn[20];
	zeroMemory(cn, nlen);
	GetComputerNameA(cn, &nlen);

	char outmsg[1024];
	zeroMemory(outmsg, 1024);

	Process32First(processSnapshot, &pe);

	do
	{
		p->setProcessID(pe.th32ProcessID);
		p->setProcessHandle(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, p->getProcessID()));
		p->resolveProcessTimes();
		ps = p->getProcessStartTime();
		_snprintf(outmsg, 1024, "ProcessList %s,%u,%u,%u,%hu-%02hu-%02hu %02hu:%02hu:%02hu Z,%s\n", cn, pe.th32ProcessID, pe.th32ParentProcessID, pe.cntThreads, 
			ps->wYear, ps->wMonth, ps->wDay, ps->wHour, ps->wMinute, ps->wSecond, pe.szExeFile);
		o->logOutput(outmsg, 1024);
		p->clearTimes();
		p->closeProcessHandle();
		zeroMemory(outmsg, 1024);
		zeroMemory(&pe, sizeof(PROCESSENTRY32));
		pe.dwSize = sizeof(PROCESSENTRY32);
	} while (Process32Next(processSnapshot, &pe) != 0);

	return true;
}

bool GCSNAPS::logThreads(GCOUTPUT * o, void * M, void* T, void* P)
{
	zeroMemory(&te, sizeof(THREADENTRY32));
	te.dwSize = sizeof(THREADENTRY32);

	HMODULE nt = LoadLibraryA("ntdll.dll");
	void* sa = 0;
	MEMORY_BASIC_INFORMATION* i = 0;

	GCMEMORY* m = (GCMEMORY*)M;
	GCTHREAD* t = (GCTHREAD*)T;
	GCPROCESS* p = (GCPROCESS*)P;

	DWORD nlen = 20;
	char cn[20];
	zeroMemory(cn, nlen);
	GetComputerNameA(cn, &nlen);

	char outmsg[1024];
	zeroMemory(outmsg, 1024);

	Thread32First(threadSnapshot, &te);

	do
	{
		if (t != 0)
		{
			t->setThreadID(te.th32ThreadID);
			t->setThreadHandle(OpenThread(THREAD_QUERY_INFORMATION, FALSE, t->getThreadID()));
			sa = t->resolveThreadStartAddress(nt);
			t->closeThreadHandle();
		}
		if (p != 0 && m != 0)
		{
			p->setProcessID(te.th32OwnerProcessID);
			p->setProcessHandle(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, p->getProcessID()));
			m->setRemoteAddress((char*)sa);
			m->remoteQuery(p->getProcessHandle());
			p->closeProcessHandle();
			i = m->getMemoryInfo();
		}
		_snprintf(outmsg, 1024, "ThreadList %s,%u,%u,%p,%p,0x%llX,0x%X\n", cn, te.th32ThreadID, te.th32OwnerProcessID, sa, i->BaseAddress, i->RegionSize, i->Protect);

		if (pid != 0 && (pid == te.th32OwnerProcessID)) o->logOutput((char*)outmsg, 1024);
		if (pid == 0 && te.th32OwnerProcessID != 0 && te.th32OwnerProcessID != 4) o->logOutput((char*)outmsg, 1024);
		zeroMemory(outmsg, 1024);
		zeroMemory(&te, sizeof(THREADENTRY32));
		te.dwSize = sizeof(THREADENTRY32);
	} while (Thread32Next(threadSnapshot, &te) != 0);
	return true;
}

bool GCSNAPS::takeProcessSnapshot()
{
	processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (processSnapshot == INVALID_HANDLE_VALUE) return false;
	else return true;
}

bool GCSNAPS::takeModuleSnapshot(DWORD pid)
{
	moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (moduleSnapshot == INVALID_HANDLE_VALUE) return false;
	else return true;
}

bool GCSNAPS::takeThreadSnapshot()
{
	threadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (threadSnapshot == INVALID_HANDLE_VALUE) return false;
	else return true;
}

bool GCSNAPS::findThreadEntry()
{
	BOOL bResult = 0;

	if (firstThread)
	{
		zeroMemory(&te, sizeof(THREADENTRY32));
		te.dwSize = sizeof(THREADENTRY32);
		bResult = Thread32First(threadSnapshot, &te);
		firstThread = false;
	}
	else
	{
		zeroMemory(&te, sizeof(THREADENTRY32));
		te.dwSize = sizeof(THREADENTRY32);
		bResult = Thread32Next(threadSnapshot, &te);
	}

	if (bResult != FALSE) return true;
	else return false;
}

bool GCSNAPS::findProcessEntry()
{
	BOOL bResult = 0;

	if (firstProcess)
	{
		zeroMemory(&pe, sizeof(PROCESSENTRY32));
		pe.dwSize = sizeof(PROCESSENTRY32);
		bResult = Process32First(processSnapshot, &pe);
		firstProcess = false;
	}
	else
	{
		zeroMemory(&pe, sizeof(PROCESSENTRY32));
		pe.dwSize = sizeof(PROCESSENTRY32);
		bResult = Process32Next(processSnapshot, &pe);
	}

	if (bResult != FALSE) return true;
	else return false;
}

bool GCSNAPS::findModuleEntry()
{
	BOOL bResult = 0;

	if (firstModule)
	{
		zeroMemory(&me, sizeof(MODULEENTRY32));
		me.dwSize = sizeof(MODULEENTRY32);
		bResult = Module32First(moduleSnapshot, &me);
		firstModule = false;
	}
	else
	{
		zeroMemory(&me, sizeof(MODULEENTRY32));
		me.dwSize = sizeof(MODULEENTRY32);
		bResult = Module32Next(moduleSnapshot, &me);
	}

	if (bResult != FALSE) return true;
	else return false;
}

THREADENTRY32* GCSNAPS::getThreadEntry() { return &te; }

PROCESSENTRY32* GCSNAPS::getProcessEntry() { return &pe; }

MODULEENTRY32* GCSNAPS::getModuleEntry() { return &me; }

void GCSNAPS::setTargeted(bool tf, DWORD p = 0)
{
	targeted = tf;
	pid = p;
}

void GCSNAPS::setThreadID(DWORD t) { tid = t; }

void GCSNAPS::setProcessID(DWORD p) { pid = p; }

void GCSNAPS::releaseThreadHandle()
{
	CloseHandle(threadSnapshot);
	threadSnapshot = 0;
}

void GCSNAPS::releaseProcessHandle()
{
	CloseHandle(processSnapshot);
	processSnapshot = 0;
}

void GCSNAPS::releaseModuleHandle()
{
	CloseHandle(moduleSnapshot);
	moduleSnapshot = 0;
}

GCPROCESS::GCPROCESS()
{
	processid = 0;
	processHandle = 0;
}

DWORD GCPROCESS::getProcessID() { return processid; }

HANDLE GCPROCESS::getProcessHandle() { return processHandle; }

void GCPROCESS::setProcessID(DWORD p) { processid = p; }

void GCPROCESS::setProcessHandle(HANDLE h) { processHandle = h; }

void GCPROCESS::closeProcessHandle() { CloseHandle(processHandle); processHandle = 0; }

bool GCPROCESS::resolveProcessTimes()
{
	procFileTimes = (FILETIME*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FILETIME) * 4);
	if (procFileTimes != 0)
	{
		GetProcessTimes(processHandle, &(procFileTimes[0]), &(procFileTimes[1]), &(procFileTimes[2]), &(procFileTimes[3]));
		FileTimeToSystemTime(&(procFileTimes[0]), &procSysTime);
		return true;
	}
	else return false;
}

void GCPROCESS::clearTimes()
{
	zeroMemory(procFileTimes, sizeof(FILETIME) * 4);
	HeapFree(GetProcessHeap(), 0, procFileTimes);
	zeroMemory(&procSysTime, sizeof(SYSTEMTIME));
}

SYSTEMTIME* GCPROCESS::getProcessStartTime() { return &procSysTime; }

bool GCPROCESS::allocateProcessName()
{
	processName = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 250);
	if (processName != 0) return true;
	else return false;
}

void GCPROCESS::freeProcessName()
{
	if (processName != 0)
	{
		zeroMemory(processName, 250);
		HeapFree(GetProcessHeap(), 0, processName);
		processName = 0;
	}
}

char* GCPROCESS::getProcessName() { return processName; }

bool GCPROCESS::resolveExePath()
{
	DWORD dResult = GetModuleFileNameExA(processHandle, 0, processName, 250);
	if (dResult == 0) return false;
	else return true;
}

GCTHREAD::GCTHREAD()
{
	threadid = 0;
	threadHandle = 0;
	startAddress = 0;
	process = 0;
}

bool GCTHREAD::resumeThread()
{
	DWORD dResult = 0;

	threadHandle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadid);
	if (threadHandle != INVALID_HANDLE_VALUE)
	{
		dResult = ResumeThread(threadHandle);
		CloseHandle(threadHandle);
		threadHandle = 0;
	}

	// A "true" return is successful; a "false" is unsuccessful
	if (dResult != -1) return true;
	else return false;
}

bool GCTHREAD::suspendThread()
{
	DWORD dResult = 0;

	threadHandle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadid);
	if (threadHandle != INVALID_HANDLE_VALUE)
	{
		dResult = SuspendThread(threadHandle);
		CloseHandle(threadHandle);
		threadHandle = 0;
	}

	// A "true" return is successful; a "false" is unsuccessful
	if (dResult != -1) return true;
	else return false;
}

bool GCTHREAD::killThread()
{
	DWORD dResult = 0;

	threadHandle = OpenThread(THREAD_TERMINATE, FALSE, threadid);
	if (threadHandle != INVALID_HANDLE_VALUE)
	{
		dResult = TerminateThread(threadHandle, 0);
		CloseHandle(threadHandle);
		threadHandle = 0;
	}

	// A "true" return is successful; a "false" is unsuccessful
	if (dResult != -1) return true;
	else return false;
}

DWORD GCTHREAD::getThreadID() { return threadid; }

HANDLE GCTHREAD::getThreadHandle() { return threadHandle; }

void* GCTHREAD::resolveThreadStartAddress(HMODULE ntdll)
{
	ULONG dataReturnSize = 0;

	// Find the function "NtQueryInformationThread"
	PNQIT pNQIT = (PNQIT)GetProcAddress(ntdll, "NtQueryInformationThread");

	// Get thread start address by calling NtQueryInformationThread() within ntdll
	pNQIT(threadHandle, 9, &startAddress, sizeof(void*), &dataReturnSize);

	return startAddress;
}

void* GCTHREAD::getThreadStartAddress() { return startAddress; }

void GCTHREAD::setThreadID(DWORD t) { threadid = t; }

void GCTHREAD::setThreadHandle(HANDLE h) { threadHandle = h; }

bool GCTHREAD::resolveThreadTimes()
{
	threadFileTimes = (FILETIME*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FILETIME) * 4);
	if (threadFileTimes != 0)
	{
		GetThreadTimes(threadHandle, &(threadFileTimes[0]), &(threadFileTimes[1]), &(threadFileTimes[2]), &(threadFileTimes[3]));
		FileTimeToSystemTime(&(threadFileTimes[0]), &threadSysTime);
		return true;
	}
	else return false;
}

void GCTHREAD::clearTimes()
{
	zeroMemory(threadFileTimes, sizeof(FILETIME) * 4);
	HeapFree(GetProcessHeap(), 0, threadFileTimes);
	zeroMemory(&threadSysTime, sizeof(SYSTEMTIME));
}

SYSTEMTIME* GCTHREAD::getThreadStartTime() { return &threadSysTime; }

void GCTHREAD::closeThreadHandle() { CloseHandle(threadHandle); threadHandle = 0; }

GCYARA::GCYARA()
{
	memory = 0;
	yrs = 0;
	rulesStringArray = 0;
	numRules = 0;
}

bool GCYARA::initialize()
{
	numRules = 0;

	int yResult = yr_initialize();
	if (yResult != ERROR_SUCCESS)
	{
		yError = 1;
		return false;
	}

	yc = (YR_COMPILER*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(YR_COMPILER));

	yResult = yr_compiler_create(&yc);
	if (yResult != ERROR_SUCCESS)
	{
		yError = 2;
		return false;
	}

	return true;
}

bool GCYARA::addRule(char* r)
{
	int yResult = 0;
	yResult = yr_compiler_add_string(yc, r, 0);
	if (yResult != ERROR_SUCCESS)
	{
		yError = 4;
		return false;
	}

	numRules++;
}

bool GCYARA::allocRules()
{
	yrs = (YR_RULES*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(YR_RULES));
	if (yrs == 0)
	{
		yError = 8;
		return false;
	}

	return true;
}

bool GCYARA::finalizeRules()
{
	int yResult = 0;

	yResult = yr_compiler_get_rules(yc, &yrs);
	if (yResult != ERROR_SUCCESS)
	{
		yError = 16;
		return false;
	}

	return true;
}

bool GCYARA::scanMemoryBuffer(void* location, SIZE_T length, SCANDATA* sd)
{
	int yResult = yr_rules_scan_mem((YR_RULES*)yrs, (uint8_t*)location, length, SCAN_FLAGS_FAST_MODE, yara_scan_cb, sd, 5);
	if (yResult == ERROR_SUCCESS) return true;
	else return false;
}

bool GCYARA::finalize()
{
	int yResult = yr_finalize();
	if (yResult == ERROR_SUCCESS) return true;
	else return false;
}

DWORD CLISOCK::nsinit()
{
	WSADATA wsd;

	// Return 0 (success if winsock is already initialized)
	if (initialized) return 0;

	// Attempt to initialize Winsock and set the flag if successful
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsd);
	if (iResult == 0) initialized = true;

	return (DWORD)iResult;
}

DWORD CLISOCK::nsterm()
{
	int iResult = WSACleanup();

	return (DWORD)iResult;
}

DWORD CLISOCK::nsconnect()
{
	int iResult = 0;
	clientSock = INVALID_SOCKET;

	// Create and initialize the addrinfo hints structure and associated pointers
	struct addrinfo hints, * result = 0, * ptr = 0;
	zeroMemory(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the remote hostname and get results if possible
	iResult = getaddrinfo(addr, port, &hints, &result);
	if (iResult != 0) return 1;

	ptr = result;

	// Create the socket
	clientSock = WSASocketA(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol, 0, 0, 0);
	if (clientSock == INVALID_SOCKET) return 2;

	// Connect the socket
	iResult = connect(clientSock, ptr->ai_addr, ptr->ai_addrlen);

	return (DWORD)iResult;
}

unsigned long long CLISOCK::nssend(void* data, unsigned long long length)
{
	// Create variables to hold the result of the send() function as well as the remaining number of bytes to be sent
	unsigned long long remaining = length;
	int sentBytes = 0;

	do
	{
		// Send only the remaining bytes if the remaining byte count is less than 1024, otherwise, send chunks of 1024 bytes
		if (remaining < 1024) { sentBytes = send(clientSock, (char*)data, remaining, 0); }
		else { sentBytes = send(clientSock, (char*)data, 1024, 0); }

		// Break if the send function returns an error
		if (sentBytes == SOCKET_ERROR) break;

		// Adjust the remaining byte found based on what was actually sent
		remaining -= sentBytes;
	} while (remaining > 0);

	// Return the number of total bytes sent
	return (length - remaining);
}

DWORD CLISOCK::nsclose() { return (DWORD)(closesocket(clientSock)); }

void CLISOCK::setInitStatus(bool* s) { initialized = *s; }

void CLISOCK::setRemoteHost(char* a, char* p)
{
	addr = a;
	port = p;
}

void zeroMemory(void* loc, unsigned long long size) { for (unsigned long long i = 0; i < size; i++) ((char*)loc)[i] = (char)0x00; }

void copyMemory(void* dst, void* src, unsigned long long size) { for (unsigned long long i = 0; i < size; i++) ((char*)dst)[i] = ((char*)src)[i]; }

void yara_error_cb(int error_level, const char* file_name, int line_number, const char* message, void* user_data)
{

}

// Yara scan callback function
int yara_scan_cb(int message, void* message_data, void* user_data)
{
	int iResult = 0;

	SCANDATA* ud = (SCANDATA*)user_data;
	YR_RULE* md = (YR_RULE*)message_data;
	CLISOCK* cs = ud->clientSocket;

	switch (message)
	{
	case CALLBACK_MSG_RULE_MATCHING:
		if (ud->netmode)
		{
			snprintf((char*)(ud->output->getBuffer()), ud->output->getBufferSize(), "YaraScan %s,%s,%u,%p,%s\n", ud->output->getHostNameA(), md->identifier, ud->process->getProcessID(), ud->memory->getRemoteAddress(), ud->process->getProcessName());
			ud->output->logOutput((char*)(ud->output->getBuffer()), strlen((char*)(ud->output->getBuffer())));
		}
		else
		{
			snprintf((char*)(ud->output->getBuffer()), ud->output->getBufferSize(), "[*] Yara rule \"%s\" matched on region %p inside PID %u (%s)\n",
				md->identifier, ud->memory->getRemoteAddress(), ud->process->getProcessID(), ud->process->getProcessName());
			ud->output->logOutput((char*)(ud->output->getBuffer()), ud->output->getBufferSize());
		}
		iResult = CALLBACK_CONTINUE;
		break;
	case CALLBACK_MSG_RULE_NOT_MATCHING:
		iResult = CALLBACK_CONTINUE;
		break;
	case CALLBACK_MSG_SCAN_FINISHED:
		iResult = CALLBACK_CONTINUE;
		break;
	default:
		iResult = CALLBACK_CONTINUE;
		break;
	}

	return iResult;
}

void parseArguments(int argc, char** argv, MODESARGS* settings)
{
	settings->dumpMode = false;
	settings->fullListMode = false;
	settings->legendMode = false;
	settings->networkMode = false;
	settings->queryMode = false;
	settings->targetListMode = false;
	settings->yaraMode = false;
	settings->zeroMode = false;
	settings->helpMode = false;
	settings->threadResumeMode = false;
	settings->threadSuspendMode = false;
	settings->threadKillMode = false;
	settings->modListMode = false;
	settings->modHuntMode = false;
	settings->procListMode = false;
	settings->threadListMode = false;
	settings->dumpAddress = 0;
	settings->pidstr = 0;
	settings->queryAddress = 0;
	settings->regionSize = 0;
	settings->reportServerAddress = 0;
	settings->reportServerPort = 0;
	settings->tidstr = 0;
	settings->zeroAddress = 0;
	settings->pid = 0;

	// Look for more than one argument to process
	if (argc > 1)
	{
		// Start a loop to iterate through the arguments
		for (int i = 0; i < argc; i++)
		{
			// Look for arguments with switches
			if (argv[i][0] == '-' || argv[i][0] == '/')
			{
				int j = 0;
				DWORD offsetCounter = 0;
				// If an argument contains a switch character '-' look for all of the switches
				while (argv[i][j] != (char)0x00)
				{

					// Look for the help argument and print the proper usage information
					if (argv[i][j] == 'h')
					{
						offsetCounter++;
						settings->helpMode = true;
					}

					// Look for the argument to resume a specific thread ID and do so, if possible
					if (argv[i][j] == 'r') {
						offsetCounter++;
						settings->tidstr = argv[i + offsetCounter];
						settings->tid = (DWORD)atoi(settings->tidstr);
						settings->threadResumeMode = true;
					}

					// Look for the argument to suspend a specific thread ID and do so, if possible
					if (argv[i][j] == 's') {
						offsetCounter++;
						settings->tidstr = argv[i + offsetCounter];
						settings->tid = (DWORD)atoi(settings->tidstr);
						settings->threadSuspendMode = true;
					}

					// Look for the argument to kill a specific thread ID and do so, if possible
					if (argv[i][j] == 'k') {
						offsetCounter++;
						settings->tidstr = argv[i + offsetCounter];
						settings->tid = (DWORD)atoi(settings->tidstr);
						settings->threadKillMode = true;
					}

					// Look for the argument to list threads
					if (argv[i][j] == 'l') {
						offsetCounter++;
						settings->threadListMode = true;
					}

					// Look for the argument to list processes
					if (argv[i][j] == 'L') {
						offsetCounter++;
						settings->procListMode = true;
					}

					// Look for the argument to hunt injected modules
					if (argv[i][j] == 'B') {
						offsetCounter++;
						settings->modHuntMode = true;
					}

					// Look for the argument to list all system threads
					if (argv[i][j] == 'q') {
						offsetCounter++;
						settings->queryMode = true;
						settings->queryAddress = (char*)strtoull(argv[i + offsetCounter], 0, 16);
					}

					// Look for the argument to enable yara scanning
					if (argv[i][j] == 'y') {
						offsetCounter++;
						settings->yaraMode = true;
					}

					// Look for the argument to specify a Process ID
					if (argv[i][j] == 'p') {
						offsetCounter++;
						settings->pid = (DWORD)atoi(argv[i + offsetCounter]);
						settings->pidstr = argv[i + offsetCounter];
					}

					// Look for the argument to dump memory starting at a specific virtual address
					if (argv[i][j] == 'd') {
						offsetCounter++;
						settings->dumpMode = true;
						settings->dumpAddress = argv[i + offsetCounter];
					}

					// Look for the argument to destroy a memory region starting at a specific virtual address
					if (argv[i][j] == 'z') {
						offsetCounter++;
						settings->zeroMode = true;
						settings->zeroAddress = argv[i + offsetCounter];
					}

					// Look for the verbose argument to print the legend, where necessary
					if (argv[i][j] == 'v') {
						offsetCounter++;
						settings->legendMode = true;
					}

					// Look for the remote address argument, where necessary
					if (argv[i][j] == 'A') {
						offsetCounter++;
						settings->reportServerAddress = argv[i + offsetCounter];
						settings->networkMode = true;
					}

					// Look for the remote port argument, where necessary
					if (argv[i][j] == 'P') {
						offsetCounter++;
						settings->reportServerPort = argv[i + offsetCounter];
						settings->networkMode = true;
					}

					// Look for the module listing argument, where necessary
					if (argv[i][j] == 'm') {
						offsetCounter++;
						settings->modListMode = argv[i + offsetCounter];
					}

					// Increment the counter to look for switches
					j++;
				}
			}
		}
	}

	if (settings->pid == 0) settings->fullListMode = true;
}

void printLegend()
{
	// Print the legend
	printf("\n==== MEMORY ALLOCATION TYPE LEGEND ====\n\n");
	printf("MEM_IMAGE - 0x1000000 (MIGHT BE NORMAL)\nMEM_PRIVATE - 0x20000 (VERY SUSPICIOUS)\nMEM_MAPPED - 0x40000 (ABNORMAL FOR THREADS)\n\n");
	printf("==== MEMORY PROTECTION LEGEND ====\n\n");
	printf("PAGE_NOACCESS - 0x1\nPAGE_READONLY - 0x2\nPAGE_READWRITE - 0x4 (VERY SUSPICIOUS)\nPAGE_WRITECOPY - 0x8\nPAGE_EXECUTE - 0x10\nPAGE_EXECUTE_READ - 0x20 (SUSPICIOUS)\nPAGE_EXECUTE_READWRITE - 0x40\t(VERY SUSPICIOUS)\nPAGE_EXECUTE_WRITECOPY - 0x80\t(NORMAL)\n\n");
	printf("==== MEMORY STATE LEGEND ====\n\n");
	printf("MEM_COMMIT - 0x1000\tMemory region is \"committed\" and therefore usable\nMEM_RESERVE - 0x2000\tMemory region is \"reserved\" but not usable\nMEM_FREE - 0x10000\tMemory region has been \"freed\" and is no longer in use\n\n");
}

void printHelp()
{
	printf("Usage:\n\tThreadDread.exe [ optional arguments ]\n\n");
	printf("Example:\n\n");
	printf("\tThreadDread.exe -q 0x1122334455667788 -p 1234 -d -v\n\n");
	printf("\tThe above command queries the memory address of a specific process, dumps the region automatically, and enables printing of the legend!\n\n");

	printf("Options:\n\n");

	// Networking
	printf("\t-A <address> Allows you to specify the collection server IP/Hostname for output\n");
	printf("\t-P <port> Allows you to specify the collection server port for output (required with -A)\n\n");

	// Module listing
	printf("\t-m Enables module listing mode; specify a process with -p (required)\n\n");

	// Thread listing
	printf("\t-l Enables thread listing mode; specify a process with -p (optional)\n\n");

	// Process listing
	printf("\t-L Enables process listing mode\n\n");

	// Thread suspend/resume/kill
	printf("\t-r <TID> Resumes a specific Thread ID\n");
	printf("\t-s <TID> Suspends a specific Thread ID\n");
	printf("\t-k <TID> Kills a specific Thread ID\n\n");

	// Memory manipulation
	printf("\t-d Enables automatic \"dump\" mode when querying memory addresses/regions\n");
	printf("\t-p <PID> Targets a specific process for an operation such as querying or Yara scanning memory addresses/regions\n");
	printf("\t-y Enables Yara scanning with built-in rules\n");
	//printf("\t-z Enables \"zero\"/\"clean\" mode which will write 0x00 bytes to a memory region and deallocate it\n\n");

	// Enable verbosity
	printf("\t-v Enables printing the legend of memory constants for increased \"verbosity\" (it helps!)\n\n");
	printf("\tWithout any arguments, this program attempts to find interesting threads!\n");
}