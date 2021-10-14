#include "Tools.h"

// Global variables
bool winsockInit;
char* yaraRules[5] =
{
	(char*)"rule PEFileHeader\n{\n\tstrings:\n\t\t$mz = \"MZ\" nocase\n\t\t$pe = { 50 45 00 00 }\n\t\t$dosstr = \"This program cannot be run in DOS mode\" nocase\n\n\tcondition:\n\t\t$mz at 400 or $pe at 512 or $dosstr at 1024\n}",
	(char*)"rule CSMeterpreter\n{\n\tstrings:\n\t\t$metcs = \"MZARUH\"\n\n\tcondition:\n\t\t$metcs at 0\n}",
	0,
	0,
	0
};

// All the magic happens here
int main(int argc, char** argv)
{
	// Parse the program arguments
	MODESARGS modarg;
	zeroMemory(&modarg, sizeof(MODESARGS));
	parseArguments(argc, argv, &modarg);

	GCMEMORY gcm;							// This object handles local and remote process memory
	GCPROCESS gcp;							// This object handles processes
	GCTHREAD gct;							// This object handles threads
	GCOUTPUT gco;							// This object handles output
	GCSNAPS gcs;							// This object handles snapshots
	GCYARA gcy;								// This object handles Yara
	CLISOCK clisend;						// This object handles the client socket to send report data
	CLISOCK clireceive;						// This object handles the client socket to receive Yara rules, if necessary

	// Set the global Winsock initialization flag to false
	winsockInit = false;

	// Find ntdll.dll
	HMODULE ntdll = LoadLibraryA("ntdll.dll");

	// Find the function "NtQueryInformationThread"
	PNQIT pNQIT = (PNQIT)GetProcAddress(ntdll, "NtQueryInformationThread");

	/*
	modarg.pid = 2008;
	modarg.modListMode = true;
	modarg.networkMode = true;
	modarg.reportServerAddress = (char*)"127.0.0.1";
	modarg.reportServerPort = (char*)"8080";
	modarg.pid = 2008;
	modarg.threadListMode = true;
	*/

	if (modarg.networkMode)
	{
		clisend.setInitStatus(&winsockInit);
		clisend.nsinit();
		clisend.setRemoteHost(modarg.reportServerAddress, modarg.reportServerPort);
		gco.setMode(1);
		gco.setSocket(&clisend);
	}

	if (modarg.helpMode)
	{
		printHelp();
		if (modarg.legendMode) printLegend();
		ExitProcess(0);
	}

	if (modarg.threadResumeMode)
	{
		gct.setThreadID(modarg.tid);
		gct.resumeThread();
		ExitProcess(0);
	}
	if (modarg.threadSuspendMode)
	{
		gct.setThreadID(modarg.tid);
		gct.suspendThread();
		ExitProcess(0);
	}

	if (modarg.threadKillMode)
	{
		gct.setThreadID(modarg.tid);
		gct.killThread();
		ExitProcess(0);
	}

	if (modarg.modListMode)
	{
		if (modarg.pid == 0) ExitProcess(0);

		gcs.takeModuleSnapshot(modarg.pid);
		gcs.logModules(&gco);
		gcs.releaseModuleHandle();
		ExitProcess(0);
	}

	if (modarg.threadListMode)
	{
		gcs.takeThreadSnapshot();
		gcs.setProcessID(modarg.pid);
		gcs.logThreads(&gco, &gcm, &gct, &gcp);
		gcs.releaseThreadHandle();
		ExitProcess(0);
	}

	if (modarg.procListMode)
	{
		gcs.takeProcessSnapshot();
		gcs.setProcessID(modarg.pid);
		gcs.logProcesses(&gco, &gcp);
		gcs.releaseProcessHandle();
		ExitProcess(0);
	}

	if (modarg.modHuntMode)
	{
		gcs.takeProcessSnapshot();

		PROCESSENTRY32* pe = 0;

		void* startaddr = 0;
		void* endaddr = 0;
		SIZE_T allocationSize = 0;

		MEMORY_BASIC_INFORMATION mbiCopy, *cmbi;

		while (gcs.findProcessEntry() != false)
		{
			char* memptr = 0;
			pe = gcs.getProcessEntry();

			MEMORY_BASIC_INFORMATION* mi;

			gcp.setProcessID(pe->th32ProcessID);

			// Try to open the handle to the process
			gcp.setProcessHandle(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, gcp.getProcessID()));
			if (gcp.getProcessHandle() == NULL) continue;

			// Allocate memory for the executable path of the process
			gcp.allocateProcessName();
			gcp.resolveExePath();

			if (strstr(gcp.getProcessName(), "SearchApp") != 0 || strstr(gcp.getProcessName(),"powershell") != 0 || strstr(gcp.getProcessName(), "Visual Studio") != 0 || strstr(gcp.getProcessName(), "OneDrive") != 0)
			{
				gcp.freeProcessName();
				gcp.closeProcessHandle();
				continue;
			}

			// Tell the user what we are about to do
			//printf("\n[*] Initiating binary inject scan of process %u (%s)\n", gcp.getProcessID(), gcp.getProcessName());

			// Scan memory here
			while ((void*)memptr <= ntdll)
			{
				// Clean out the memory basic information structure
				gcm.zeroMBI();

				// Query the memory region of the target process
				gcm.setRemoteAddress(memptr);
				gcm.remoteQuery(gcp.getProcessHandle());
				mi = gcm.getMemoryInfo();

				// Skip the region if we encounter a guard page (this causes problems)
				if ((mi->Protect & PAGE_GUARD) != 0) goto skipRegion1;
				if (mi->Protect != PAGE_EXECUTE_READWRITE && mi->Protect != PAGE_EXECUTE_READ) goto skipRegion1;
				else
				{
					// Find committed pages that have execute permission and are not mapped to images
					if (mi->State == MEM_COMMIT && mi->Type != MEM_IMAGE)
					{
						startaddr = mi->AllocationBase;														// Set the start address equal to the base of the allocation
						gcm.setRemoteAddress((char*)startaddr);												// Set the remote address to query to the allocation base; where we start scanning
						copyMemory(&mbiCopy, gcm.getMemoryInfo(), sizeof(MEMORY_BASIC_INFORMATION));		// Copy the current MBI so we don't lose it

						// Run this loop as long as contiguous regions are committed to make sure we get all the data
						do
						{
							gcm.remoteQuery(gcp.getProcessHandle());										// Query the region
							cmbi = gcm.getMemoryInfo();														// Get the MBI information
							if (cmbi->State == MEM_COMMIT)													// Check if the region is committed
							{
								endaddr = (char*)(cmbi->BaseAddress) + cmbi->RegionSize;	// Set the endaddr equal to the current region address + the region size; we will scan this next!
								allocationSize += cmbi->RegionSize;							// Increase the allocation size by the current region size
							}
							gcm.setRemoteAddress((char*)endaddr);							// Set the next address to query
						} while (cmbi->State == MEM_COMMIT);								// Run while contiguous region states are still "committed"

						// Output some data
						gco.allocateBuffer();
						gco.resolveHostNames();
						if (allocationSize > 0x8000)
						{
							snprintf((char*)(gco.getBuffer()), gco.getBufferSize(), "BinaryInject %s,%u,%p,0x%llX,%s\n",
								gco.getHostNameA(), gcp.getProcessID(), startaddr, allocationSize, gcp.getProcessName());
							gco.logOutput((char*)gco.getBuffer(), gco.getBufferSize());
						}

						// Get ready for the next iteration
						startaddr = 0;
						endaddr = 0;
						allocationSize = 0;
						gco.clear();
						copyMemory(gcm.getMemoryInfo(), &mbiCopy, sizeof(MEMORY_BASIC_INFORMATION));		// Restore the saved MBI now that we are done scanning
					}
				}

			skipRegion1:

				// Increase the memory pointer so we know where to scan next
				if (mi->RegionSize >= 4096) memptr += mi->RegionSize;
				else memptr += 4096;
			}

			// Get ready for the next iteration
			gcp.freeProcessName();
			gcp.closeProcessHandle();
		}

		ExitProcess(0);
	}

	if (modarg.queryMode)
	{
		DWORD totalSize = 0;

		MEMORY_BASIC_INFORMATION* mp;

		gcp.setProcessID(modarg.pid);
		gcp.setProcessHandle(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, gcp.getProcessID()));

		// Tell the user what we are about to do
		printf("[*] Querying address %p in remote process %u\n\n", modarg.queryAddress, modarg.pid);

		// Query the memory region
		gcm.setRemoteAddress(modarg.queryAddress);
		gcm.remoteQuery(gcp.getProcessHandle());
		mp = gcm.getMemoryInfo();
		gcm.setRemoteBufferSize(mp->RegionSize);
		gcm.allocateLocal(mp->RegionSize);

		// Allocate memory to store the string
		gco.allocateBuffer();
		snprintf((char*)(gco.getBuffer()), gco.getBufferSize(), "MemQuery Address: %p,RegBase: %p,AllBase: %p,RegSize: 0x%llX,IniProt: 0x%X,CurProt: 0x%X,RegType: 0x%X,ReState: 0x%X\n",
			modarg.queryAddress, mp->BaseAddress, mp->AllocationBase, mp->RegionSize, mp->AllocationProtect, mp->Protect, mp->Type, mp->State);

		// Output the results
		if (modarg.networkMode) gco.logOutput((char*)gco.getBuffer(), gco.getBufferSize());
		else gco.logOutput((char*)gco.getBuffer(), gco.getBufferSize());

		// Print the legend
		if (modarg.legendMode) printLegend();

		if (modarg.dumpMode && modarg.pid != 0)
		{
			char fileName[48];
			zeroMemory(fileName, 48);

			snprintf(fileName, 48, "%u_%p.dmp", gcp.getProcessID(), mp->AllocationBase);

			// Dump the region to disk if possible
			DWORD bytesWritten = 0;
			HANDLE dumpFile = CreateFileA(fileName, GENERIC_ALL, 1 | 2 | 4, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
			
			// Start with the allocation base
			gcm.setRemoteAddress((char*)mp->AllocationBase);
			
			// Start a loop to keep dumping content while contiguous regions are committed
			do
			{
				// Zero the MBI and query the remote address
				gcm.zeroMBI();
				gcm.remoteQuery(gcp.getProcessHandle());
				mp = gcm.getMemoryInfo();

				// Break out of the loop if the next region is not committed
				if (mp->State != MEM_COMMIT) break;

				printf("[*] Copying region starting at base address %p with size 0x%llX\n", mp->BaseAddress, mp->RegionSize);

				// Allocate space for the region
				gcm.allocateLocal(mp->RegionSize);
				gcm.setLocalBufferSize(mp->RegionSize);
				gcm.setRemoteBufferSize(mp->RegionSize);
				
				// Set the remote region to RWX, copy it, then set it back the way it was
				gcm.setNewProtect(PAGE_EXECUTE_READWRITE);
				VirtualProtectEx(gcp.getProcessHandle(), gcm.getRemoteAddress(), gcm.getRemoteSize(), *(gcm.getNewProtect()), gcm.getOldProtect());
				gcm.remoteCopy(gcp.getProcessHandle());
				VirtualProtectEx(gcp.getProcessHandle(), gcm.getRemoteAddress(), gcm.getRemoteSize(), *(gcm.getOldProtect()), gcm.getNewProtect());

				// Write the resulting buffer to disk
				if (dumpFile != INVALID_HANDLE_VALUE) WriteFile(dumpFile, gcm.getLocalAddress(), mp->RegionSize, &bytesWritten, 0);
				totalSize += bytesWritten;
				bytesWritten = 0;

				// Update the remote query address for the next iteration
				gcm.setRemoteAddress((char*)mp->BaseAddress + mp->RegionSize);
				
				// Deallocate the memory
				gcm.freeLocal();
			} while (mp->State == MEM_COMMIT);

			// Close the handle
			CloseHandle(dumpFile);
			printf("\n[*] Successfully wrote %u (0x%X) bytes to file %s in the current directory!\n", totalSize, totalSize, fileName);

			printf("\n[*] If you dumped a PE file, you may need to fix up the section alignment before you read it statically!\n");
		}

		ExitProcess(0);
	}

	// Check for yaraMode being enabled
	if (modarg.yaraMode)
	{
		// Determine whether a process is being targeted or not
		bool targetedScan = false;
		if (modarg.pid != 0) targetedScan = true;

		// Tell the user we are compiling the rules
		printf("[*] Yara scanning mode enabled; initializing Yara and compiling rules...\n");

		// Create a SCANDATA structure to pass user data to the Yara scan callback function
		SCANDATA sd;
		zeroMemory(&sd, sizeof(SCANDATA));

		// Initialize Yara
		gcy.initialize();
		gcy.allocRules();
		for (unsigned char i = 0; i < 2; i++) gcy.addRule(yaraRules[i]);
		gcy.finalizeRules();
		
		// Snapshot all processes on the system
		gcs.takeProcessSnapshot();

		// Tell the user we are scanning all processes if targetedScan is false
		if (!targetedScan) printf("[*] Scanning all system processes...\n");

		PROCESSENTRY32* pe = 0;

		while (gcs.findProcessEntry() != false)
		{
			char* memptr = 0;
			pe = gcs.getProcessEntry();

			MEMORY_BASIC_INFORMATION* mi;

			// Adjust scan according to targeted or not
			if ((targetedScan && pe->th32ProcessID != modarg.pid) || pe->th32ProcessID == GetCurrentProcessId()) continue;

			// Make the pid variable equal to the tpid variable
			if (targetedScan) gcp.setProcessID(modarg.pid);
			else gcp.setProcessID(pe->th32ProcessID);

			// Try to open the handle to the process
			gcp.setProcessHandle(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, gcp.getProcessID()));
			if (gcp.getProcessHandle() == NULL) continue;

			// Allocate memory for the executable path of the process
			gcp.allocateProcessName();
			gcp.resolveExePath();
			
			// Tell the user we are running a targeted scan if targetedScan is true
			printf("\n[*] Initiating Yara scan of process %u 0x%llX (%s)\n", gcp.getProcessID(), gcp.getProcessHandle(), gcp.getProcessName());

			// Keep scanning while the memptr variable has a less than or equal to value with the address of this process' ntdll.dll module
			// The reason we do this is because ntdll.dll is usually the last thing loaded (in the highest memory address range)
			while ((void*)memptr <= ntdll)
			{
				// Clean out the memory basic information structure
				gcm.zeroMBI();

				// Query the memory region of the target process
				gcm.setRemoteAddress(memptr);
				gcm.remoteQuery(gcp.getProcessHandle());
				mi = gcm.getMemoryInfo();

				// Skip the region if we encounter a guard page (this causes problems)
				if ((mi->Protect & PAGE_GUARD) != 0) goto skipRegion2;

				// Get committed pages only
				if (mi->State == MEM_COMMIT)
				{
					// Allocate memory to copy the remote buffer and then copy it
					gcm.allocateLocal(mi->RegionSize);
					gcm.setRemoteBufferSize(mi->RegionSize);
					gcm.remoteCopy(gcp.getProcessHandle());					// ERROR FIX THIS, remote copy failed
					gco.allocateBuffer();
					gco.resolveHostNames();

					// Initialize the SCANDATA structure to pass to the yara scanner
					sd.memory = &gcm;
					sd.process = &gcp;
					sd.output = &gco;
					if (modarg.networkMode)
					{
						sd.netmode = true;
						sd.clientSocket = &clisend;
						sd.wsInit = &winsockInit;
						sd.remoteAddress = modarg.reportServerAddress;
						sd.remotePort = modarg.reportServerPort;
					}
					else
					{
						sd.netmode = false;
						sd.clientSocket = 0;
					}

					// Scan the memory region
					gcy.scanMemoryBuffer(gcm.getLocalAddress(), gcm.getLocalSize(), &sd);

					// Get ready for the next iteration
					zeroMemory(&sd, sizeof(SCANDATA));
					gcm.freeLocal();
					gcm.setRemoteBufferSize(0);
					gco.clear();
				}

			skipRegion2:

				// Increase the memory pointer so we know where to scan next
				if (mi->RegionSize >= 4096) memptr += mi->RegionSize;
				else memptr += 4096;
			}

			// Get ready for the next iteration
			gcp.freeProcessName();
			gcp.closeProcessHandle();
		}

		// Close the handle to the process snapshot
		gcs.releaseProcessHandle();

		gcy.finalize();
		ExitProcess(0);
	}

	if (modarg.zeroMode)
	{
		ExitProcess(0);
	}

	// Set a BOOL variable
	BOOL bResult = FALSE;

	// Maintain counters for all system threads and reported threads
	DWORD printCount = 0;
	DWORD threadCount = 0;

	// Get the thread snapshot and create a pointer for the thread entry
	gcs.takeThreadSnapshot();
	MEMORY_BASIC_INFORMATION* mp = 0;

	while (gcs.findThreadEntry())
	{	
		// Collect thread information
		gct.setThreadID(gcs.getThreadEntry()->th32ThreadID);
		gct.setThreadHandle(OpenThread(THREAD_QUERY_INFORMATION, FALSE, gct.getThreadID()));
		gct.resolveThreadTimes();
		

		// Collect process information
		gcp.setProcessID(gcs.getThreadEntry()->th32OwnerProcessID);
		gcp.setProcessHandle(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, gcp.getProcessID()));
		gcp.allocateProcessName();
		gcp.resolveExePath();
		gcp.resolveProcessTimes();

		// Collect the memory allocation information
		gcm.setRemoteAddress((char*)gct.resolveThreadStartAddress(ntdll));
		gcm.remoteQuery(gcp.getProcessHandle());

		// Set pointer equal to the memory basic information and allocate an output buffer
		mp = gcm.getMemoryInfo();
		gco.allocateBuffer();

		// Get the computer's host name ready for output
		gco.resolveHostNames();

		// Start the process of generating output, if necessary
		// Looking for thread start memory region that is not PAGE_EXECUTE_WRITECOPY to detect an injected thread
		// Also look for allocations that are both executable and private, which will detect process hollowing
		if ((mp->AllocationProtect != PAGE_EXECUTE_WRITECOPY && mp->Type != 0) || ((mp->Protect == PAGE_EXECUTE_READ || mp->Protect == PAGE_EXECUTE_READWRITE) && mp->Type == MEM_PRIVATE))
		{
			// Next, look for full thread listing or targeted process thread listing
			if (modarg.fullListMode || (modarg.targetListMode && gcp.getProcessID() == modarg.pid))
			{
				// Output according to mode
				if (modarg.networkMode)
				{
					// Fill the output buffer with relevant information
					snprintf((char*)gco.getBuffer(), gco.getBufferSize(), "ThreadScan %s,%u,%hu-%02hu-%02hu %02hu:%02hu:%02hu Zulu,%p,0x%X,0x%X,%u,%hu-%02hu-%02hu %02hu:%02hu:%02hu Zulu,%s\n",
						gco.getHostNameA(), gct.getThreadID(),
						gct.getThreadStartTime()->wYear, gct.getThreadStartTime()->wMonth, gct.getThreadStartTime()->wDay,
						gct.getThreadStartTime()->wHour, gct.getThreadStartTime()->wMinute, gct.getThreadStartTime()->wSecond,
						gct.getThreadStartAddress(), mp->Type, mp->Protect,
						gcp.getProcessID(), gcp.getProcessStartTime()->wYear, gcp.getProcessStartTime()->wMonth, gcp.getProcessStartTime()->wDay,
						gcp.getProcessStartTime()->wHour, gcp.getProcessStartTime()->wMinute, gcp.getProcessStartTime()->wSecond,
						gcp.getProcessName());

					// Sent the output
					gco.logOutput((char*)gco.getBuffer(), gco.getBufferSize());
					zeroMemory(gco.getBuffer(), gco.getBufferSize());
				}
				else
				{
					snprintf((char*)gco.getBuffer(), gco.getBufferSize(), "[*] Thread %u:\n\t*Process Info*\tPID: %u\t\t\t\t\tPath: %s\t\tProcess Creation: %hu-%02hu-%02hu %02hu:%02hu:%02hu Z\n\t*Thread Info*\tThread Creation: %hu-%02hu-%02hu %02hu:%02hu:%02hu Z\t\tStart Address: 0x%llX\n\t*Memory Info*\tMemory Allocation Type: 0x%X\t\t\tMemory Protection: 0x%X\n",
						gct.getThreadID(), gcp.getProcessID(), gcp.getProcessName(),
						gcp.getProcessStartTime()->wYear, gcp.getProcessStartTime()->wMonth, gcp.getProcessStartTime()->wDay,
						gcp.getProcessStartTime()->wHour, gcp.getProcessStartTime()->wMinute, gcp.getProcessStartTime()->wSecond,
						gct.getThreadStartTime()->wYear, gct.getThreadStartTime()->wMonth, gct.getThreadStartTime()->wDay,
						gct.getThreadStartTime()->wHour, gct.getThreadStartTime()->wMinute, gct.getThreadStartTime()->wSecond,
						gct.getThreadStartAddress(), mp->Type, mp->Protect);

					// Send the output
					gco.logOutput((char*)gco.getBuffer(), gco.getBufferSize());
					zeroMemory(gco.getBuffer(), gco.getBufferSize());
				}
				printCount++;
			}
		}

		// Clean up before the next iteration
		gcm.setRemoteAddress(0);
		gcm.setRemoteBufferSize(0);
		gcm.zeroMBI();
		gco.clear();
		gcp.setProcessID(0);
		gcp.clearTimes();
		gcp.freeProcessName();
		gct.clearTimes();

		// Close the process and thread handles
		gct.closeThreadHandle();
		gcp.closeProcessHandle();

		threadCount++;
	}

	// Close the thread snapshot handle and terminate the connection
	gcs.releaseThreadHandle();
	clisend.nsterm();

	// Print the thread reporting statistics
	printf("\n[*] Reported %u of %u total system threads\n\n", printCount, threadCount);

	// Print the legend
	if (modarg.legendMode) printLegend();

	return 0;
}