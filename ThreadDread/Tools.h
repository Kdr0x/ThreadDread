#pragma once

#include "Main.h"

// Just a quick way to zero out a memory range
void zeroMemory(void*, unsigned long long);

// Copy memory between buffers
void copyMemory(void*, void*, unsigned long long);

// Parse the program arguments
void parseArguments(int, char**, MODESARGS*);

// Print usage documentation
void printHelp();

// Print the legend
void printLegend();

// Process self-termination
void terminateSelf(LPVOID);		// Default self-kill timer of 15 minutes

class CLISOCK
{
	bool initialized;
	SOCKET clientSock;
	char* addr;
	char* port;

public:

	DWORD nsinit();
	DWORD nsterm();
	DWORD nsconnect();
	unsigned long long nssend(void*, unsigned long long);
	DWORD nsclose();
	void setInitStatus(bool*);
	void setRemoteHost(char*, char*);
};

class GCMEMORY
{
	char* remoteAddress;
	SIZE_T remoteSize;
	char* localAddress;
	SIZE_T localSize;
	char* localHeap;
	SIZE_T heapSize;
	MEMORY_BASIC_INFORMATION mbi;
	HANDLE heapHandle;
	DWORD oProt;
	DWORD nProt;

public:

	GCMEMORY();
	
	// Allocate local buffer
	bool allocateLocal(SIZE_T length = 4096, DWORD protect = PAGE_READWRITE, DWORD type = MEM_RESERVE | MEM_COMMIT);
	// Free local buffer
	bool freeLocal();

	// Allocate buffer from heap
	bool allocateHeap(DWORD);
	// Free buffer from heap
	bool freeHeap();

	// Query remote memory buffer
	bool remoteQuery(HANDLE);
	// Copy remote memory buffer
	bool remoteCopy(HANDLE);
	
	// Get a pointer to the memory information structure
	MEMORY_BASIC_INFORMATION* getMemoryInfo();
	// Set the pointer to the memory information structure
	void setMemoryInfo(MEMORY_BASIC_INFORMATION*);

	// Get remote buffer address
	char* getRemoteAddress();
	// Get remote buffer size
	unsigned long long getRemoteSize();
	// Get local buffer address
	char* getLocalAddress();
	// Get local buffer size
	SIZE_T getLocalSize();
	// Get local heap address
	char* getLocalHeap();
	// Get local heap size
	SIZE_T getLocalHeapSize();

	// Set remote buffer address
	void setRemoteAddress(char*);
	// Set remote buffer size
	void setRemoteBufferSize(SIZE_T);
	// Set local buffer address
	void setLocalBufferAddress(char*);
	// Set local buffer size
	void setLocalBufferSize(SIZE_T);
	// Set local heap address
	void setLocalHeapAddress(void*);
	// Set the size of the local heap allocation
	void setLocalHeapSize(SIZE_T);

	// Zero local memory buffer
	void zeroLocal();
	// Zero MBI
	void zeroMBI();

	// Set new protection
	void setNewProtect(DWORD);
	// Set old protection
	void setOldProtect(DWORD);
	// Get new protection
	DWORD* getNewProtect();
	// Get old protection
	DWORD* getOldProtect();
};


/*
class GCFILE
{
	HANDLE hFile;
	char* fileName;
	char* fullPath;
	GCMEMORY* buffers;

public:
	bool createOutputFile();			// Create a file for writing output
	HANDLE getfileHandle();				// Get the file handle
	void setFileName();					// Set the filename
};*/

class GCOUTPUT
{
	BYTE mode;
	void* buffer;
	SIZE_T bufferSize;
	CLISOCK* rsocket;
	char cNameA[20];
	wchar_t cNameW[20];

public:
	void logOutput(char*, unsigned long long);
	void logOutput(wchar_t*, unsigned long long);
	bool allocateBuffer(DWORD size = 1024);
	void freeBuffer();
	void* getBuffer();
	SIZE_T getBufferSize();
	bool resolveHostNames();
	char* getHostNameA();
	wchar_t* getHostNameW();
	void clear();
	void setMode(BYTE);
	void setSocket(CLISOCK*);
};

class GCSNAPS
{
	HANDLE processSnapshot;
	HANDLE moduleSnapshot;
	HANDLE threadSnapshot;
	THREADENTRY32 te;
	MODULEENTRY32 me;
	PROCESSENTRY32 pe;
	bool targeted;
	DWORD pid;
	DWORD tid;
	bool firstProcess;
	bool firstThread;
	bool firstModule;

public:
	GCSNAPS();															// Initialize the variables
	bool logModules(GCOUTPUT *);										// Print the list of modules
	bool logProcesses(GCOUTPUT *, void*);								// Print the list of processes
	bool logThreads(GCOUTPUT*, void*, void*, void*);					// Print the list of threads
	bool takeProcessSnapshot();											// Snapshots all processes on the system
	bool takeModuleSnapshot(DWORD);										// Requires a PID parameter
	bool takeThreadSnapshot();											// Snapshots all threads on the system
	bool findThreadEntry();												// Find the next thread entry
	bool findProcessEntry();											// Find the next process entry
	bool findModuleEntry();												// Find the next module entry
	THREADENTRY32* getThreadEntry();									// Get a pointer to the thread entry structure
	PROCESSENTRY32* getProcessEntry();									// Get a pointer to the process entry structure
	MODULEENTRY32* getModuleEntry();									// Get a pointer to the module entry structure
	void setTargeted(bool, DWORD);										// Set the targeting feature
	void setThreadID(DWORD);											// Set the target thread ID
	void setProcessID(DWORD);											// Set the target process ID
	void releaseThreadHandle();											// Release the thread snapshot handle
	void releaseProcessHandle();										// Release the process snapshot handle
	void releaseModuleHandle();											// Release the module snapshot handle
};

class GCPROCESS
{
	DWORD processid;
	HANDLE processHandle;
	char* processName;
	FILETIME* procFileTimes;
	SYSTEMTIME procSysTime;

public:
	GCPROCESS();								// Initialize the variables
	DWORD getProcessID();						// Get the process ID
	HANDLE getProcessHandle();					// Get the process handle
	void setProcessID(DWORD);					// Set the process ID
	void setProcessHandle(HANDLE);				// Set the process handle
	void closeProcessHandle();					// Close the process handle
	bool resolveProcessTimes();					// Get the process' times
	void clearTimes();							// Clear the process file and system times
	SYSTEMTIME* getProcessStartTime();			// Get the process' start time
	bool allocateProcessName();					// Allocate space for process name
	void freeProcessName();						// Deallocate space for process name
	char* getProcessName();						// Get a pointer to the process name
	bool resolveExePath();						// Resolve the process' executable path
};

class GCTHREAD
{
	DWORD threadid;
	HANDLE threadHandle;
	void* startAddress;
	FILETIME* threadFileTimes;
	SYSTEMTIME threadSysTime;
	GCPROCESS* process;

public:
	GCTHREAD();									// Initialize the variables
	bool resumeThread();						// Resume the thread
	bool suspendThread();						// Suspend the thread
	bool killThread();							// Kill the thread
	DWORD getThreadID();						// Get the thread ID
	HANDLE getThreadHandle();					// Get the thread handle
	void* resolveThreadStartAddress(HMODULE);	// Resolve the thread start address
	void clearTimes();							// Clear the thread file and system times
	void* getThreadStartAddress();				// Get the thread start address
	GCPROCESS* getThreadProcess();				// Get the thread process object
	void setThreadID(DWORD);					// Set the thread ID
	void setThreadHandle(HANDLE);				// Set the thread handle
	bool resolveThreadTimes();					// Get the thread's times
	SYSTEMTIME* getThreadStartTime();			// Get the thread's start time
	void closeThreadHandle();					// Close the thread's handle
};

struct SCANDATA
{
	CLISOCK* clientSocket;
	GCMEMORY* memory;
	GCPROCESS* process;
	GCOUTPUT* output;
	bool netmode;
	bool* wsInit;
	char* remoteAddress;
	char* remotePort;
};

class GCYARA
{
	char source;
	YR_COMPILER* yc;
	GCMEMORY* memory;
	YR_RULES* yrs;
	char** rulesStringArray;
	DWORD numRules;
	DWORD yError;

public:
	GCYARA();
	bool initialize();
	bool scanMemoryBuffer(void*, SIZE_T, SCANDATA*);
	bool allocRules();
	bool addRule(char* r);
	bool finalizeRules();
	bool finalize();
	void setSource(char);
	DWORD getError() { return yError; }
};

// Yara error callback function
void yara_error_cb(int, const char*, int, const char*, void*);

// Yara scan callback function
int yara_scan_cb(int, void*, void*);