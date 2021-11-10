#include "Tools.h"

// Global variables
bool winsockInit;

// All the magic happens here
int main(int argc, char** argv)
{
	// Start a new thread on the "safety" self-kill timer
	DWORD safetyThreadID = 0;
	HANDLE safetyThread = 0;

	// Parse the program arguments
	MODESARGS modarg;
	zeroMemory(&modarg, sizeof(MODESARGS));
	parseArguments(argc, argv, &modarg);

	// Create the safety kill thread
	if (modarg.timer <= 0) modarg.timer = 15;
	safetyThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)terminateSelf, (LPVOID)&(modarg.timer), 0, &safetyThreadID);

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
		if (gct.resumeThread()) printf("[*] Successfully resumed thread %u\n", modarg.tid);
		else printf("[!] Error: Could not resume thread %u\n", modarg.tid);
		ExitProcess(0);
	}
	if (modarg.threadSuspendMode)
	{
		gct.setThreadID(modarg.tid);
		if (gct.suspendThread()) printf("[*] Successfully suspended thread %u\n", modarg.tid);
		else printf("[!] Error: Could not suspend thread %u\n", modarg.tid);
		ExitProcess(0);
	}

	if (modarg.threadKillMode)
	{
		gct.setThreadID(modarg.tid);
		if (gct.killThread()) printf("[*] Successfully killed thread %u\n", modarg.tid);
		else printf("[!] Error: Could not kill thread %u\n", modarg.tid);
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
		gcs.logThreads(&gco, &gcm, &gct, &gcp, &gcs);
		gcs.releaseThreadHandle();
		if (modarg.legendMode) printLegend();
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
		void* targetAlloc = 0;

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
				// Page with execute permissions was found
				else
				{
					// Look for a committed RWX region whose region base and allocation base are the same
					if ((mi->State == MEM_COMMIT) && (mi->Protect == PAGE_EXECUTE_READWRITE) && (mi->AllocationBase == mi->BaseAddress))
					{
						// Copy the region
						gcm.setRemoteAddress((char*)mi->AllocationBase);
						gcm.allocateLocal(mi->RegionSize);
						gcm.remoteCopy(gcp.getProcessHandle());

						// Overlay the DOS and NT headers on top of this memory region to check for signs of PE signatures
						PIMAGE_DOS_HEADER pDH = (PIMAGE_DOS_HEADER)gcm.getLocalAddress();
						PIMAGE_NT_HEADERS64 pNH = (PIMAGE_NT_HEADERS64)(gcm.getLocalAddress() + pDH->e_lfanew);
						PIMAGE_FILE_HEADER pFH = (PIMAGE_FILE_HEADER)&(pNH->FileHeader);
						PIMAGE_OPTIONAL_HEADER64 pOH = (PIMAGE_OPTIONAL_HEADER64)&(pNH->OptionalHeader);

						// Check to make sure pNH is still pointing within the region
						if (((SIZE_T)pNH - (SIZE_T)pDH) <= mi->RegionSize)
						{
							/* Inspect the potential PE's headers for evidence that it IS indeed a PE file; look for the following
							1. "MZ" signature
							2. PE" signature
							3. Target machine architecture constant
							4. Section alignment is 0x1000 (4096)
							5. The "magic" number of a PE32+ binary
							*/
							if (pDH->e_magic == (WORD)0x5a4d || pNH->Signature == (DWORD)0x00004550 || pFH->Machine == IMAGE_FILE_MACHINE_AMD64 ||
								pOH->SectionAlignment == 0x1000 || pOH->Magic == 0x20b)
							{
								// Start preparing buffers for output
								gco.allocateBuffer();
								gco.resolveHostNames();

								// Log the injected PE file that was found
								snprintf((char*)gco.getBuffer(), gco.getBufferSize(), "PEScan %s,%u,%p,0x%zX,0x%X,0x%X\n", gco.getHostNameA(), gcp.getProcessID(), mi->AllocationBase, mi->RegionSize, mi->AllocationProtect, mi->Protect);
								gco.logOutput((char*)gco.getBuffer(), strlen((char*)gco.getBuffer()));

								// Clear the buffers that were used
								gco.clear();
							}
						}
						
						gcm.freeLocal();
					}
					/*/ Find committed pages that have execute permission and are not mapped to images
					if (mi->State == MEM_COMMIT && mi->Type != MEM_IMAGE && mi->AllocationProtect != PAGE_EXECUTE_WRITECOPY)
					{
						// Set the initial allocation base if it was not already set
						if (targetAlloc == 0) targetAlloc = mi->AllocationBase;

						startaddr = targetAlloc;															// Set the start address equal to the base of the target allocation
						gcm.setRemoteAddress((char*)startaddr);												// Set the remote address to query to the allocation base; where we start scanning
						copyMemory(&mbiCopy, gcm.getMemoryInfo(), sizeof(MEMORY_BASIC_INFORMATION));		// Copy the current MBI so we don't lose it

						// Run this loop as long as contiguous regions are part of the same allocation
						do
						{
							gcm.remoteQuery(gcp.getProcessHandle());										// Query the region
							cmbi = gcm.getMemoryInfo();														// Get the MBI information
							if (cmbi->AllocationBase != targetAlloc) break;									// Break if a new allocation is being read
							endaddr = (char*)(cmbi->BaseAddress) + cmbi->RegionSize;	// Set the endaddr equal to the current region address + the region size; we will scan this next!
							allocationSize += cmbi->RegionSize;												// Increase the allocation size by the current region size
							gcm.setRemoteAddress((char*)endaddr);											// Set the next address to query
						} while (cmbi->AllocationBase == targetAlloc);										// Run while the contiguous regions are part of the same allocation

						// Output some data
						gco.allocateBuffer();
						gco.resolveHostNames();
						if (allocationSize > 0x8000)
						{
							snprintf((char*)(gco.getBuffer()), gco.getBufferSize(), "BinaryInject %s,%u,%p,0x%llX,%s,0x%X\n",
								gco.getHostNameA(), gcp.getProcessID(), startaddr, allocationSize, gcp.getProcessName(), gcm.getMemoryInfo()->AllocationProtect);
							gco.logOutput((char*)gco.getBuffer(), gco.getBufferSize());
						}

						// Get ready for the next iteration
						startaddr = 0;
						endaddr = 0;
						allocationSize = 0;
						gco.clear();
						copyMemory(gcm.getMemoryInfo(), &mbiCopy, sizeof(MEMORY_BASIC_INFORMATION));		// Restore the saved MBI now that we are done scanning
					}*/
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

		if (modarg.legendMode) printLegend();

		ExitProcess(0);
	}

	if (modarg.queryMode)
	{
		// Pointer to target allocation
		void* targetAlloc = 0;

		// Total dumped bytes and total allocation size
		SIZE_T dfBW = 0;
		SIZE_T allocSize = 0;
		SIZE_T commitSize = 0;
		SIZE_T reserveSize = 0;

		// Memory information pointer
		MEMORY_BASIC_INFORMATION* mp;

		// Set the process ID to query and open a handle to the process
		gcp.setProcessID(modarg.pid);
		gcp.setProcessHandle(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, gcp.getProcessID()));

		// Tell the user what we are about to do
		printf("[*] Querying address %p in remote process %u\n\n", modarg.queryAddress, modarg.pid);

		// Query the memory address initially given to get the target allocation
		gcm.setRemoteAddress(modarg.queryAddress);
		gcm.remoteQuery(gcp.getProcessHandle());
		mp = gcm.getMemoryInfo();
		if (targetAlloc == 0) targetAlloc = mp->AllocationBase;

		// Set the remote address to the target allocation base
		gcm.setRemoteAddress((char*)targetAlloc);

		// Run this loop for each region that is a part of the same allocation
		do
		{
			// Query the remote region and update the mp pointer
			gcm.zeroMBI();
			gcm.remoteQuery(gcp.getProcessHandle());
			mp = gcm.getMemoryInfo();

			// Break the loop id the region that was just queried is outside of the target allocation
			if (mp->AllocationBase != targetAlloc) break;

			// Allocate a buffer to hold the output data
			gco.allocateBuffer();

			// Update the size counters
			allocSize += mp->RegionSize;
			if (mp->State == MEM_COMMIT) commitSize += mp->RegionSize;
			if (mp->State == MEM_RESERVE) reserveSize += mp->RegionSize;

			// Load the buffer with relevant data
			snprintf((char*)(gco.getBuffer()), gco.getBufferSize(), "MemQuery %p,%p,0x%zX,0x%X,0x%X,0x%X,%p,0x%X\n",
				modarg.queryAddress, mp->BaseAddress, mp->RegionSize, mp->Protect, mp->Type, mp->State, mp->AllocationBase, mp->AllocationProtect);

			// Log the output
			gco.logOutput((char*)gco.getBuffer(), strlen((char*)gco.getBuffer()));

			// Free the output buffer
			gco.clear();

			// If dump mode is enabled, the region is committed, and the process ID is not 0, dump the region and record the mapping
			if (modarg.dumpMode && mp->State == MEM_COMMIT && modarg.pid != 0)
			{
				// Create a variable to store bytes written
				SIZE_T bw = 0;

				// Create a dump file name buffer
				char dumpFileName[48];
				zeroMemory(dumpFileName, 48);

				// Create a dump mapping file name buffer
				char dumpFileMapping[48];
				zeroMemory(dumpFileMapping, 48);

				// Create a buffer to hold the map data
				char mapData[96];
				zeroMemory(mapData, 96);

				// Write to the file name buffers
				snprintf(dumpFileName, 48, "%u_%p.dmp", gcp.getProcessID(), mp->AllocationBase);
				snprintf(dumpFileMapping, 48, "%u_%p.txt", gcp.getProcessID(), mp->AllocationBase);

				// Open the files for appending
				HANDLE dumpFile = CreateFileA(dumpFileName, GENERIC_ALL, 1 | 2 | 4, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
				HANDLE mapFile = CreateFileA(dumpFileMapping, GENERIC_ALL, 1 | 2 | 4, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
				if (dumpFile == INVALID_HANDLE_VALUE || mapFile == INVALID_HANDLE_VALUE)
				{
					zeroMemory(dumpFileName, 48);
					zeroMemory(dumpFileMapping, 48);
				}
				else
				{
					// Set the file pointers to the end of the files and write the data to them
					SetFilePointer(dumpFile, 0, 0, FILE_END);
					SetFilePointer(mapFile, 0, 0, FILE_END);

					// Allocate memory to copy the remote buffer and then copy it
					gcm.allocateLocal(mp->RegionSize);
					gcm.setRemoteBufferSize(mp->RegionSize);

					// Set the remote region to RWX, copy it, then set it back the way it was
					gcm.setNewProtect(PAGE_EXECUTE_READWRITE);
					VirtualProtectEx(gcp.getProcessHandle(), gcm.getRemoteAddress(), gcm.getRemoteSize(), *(gcm.getNewProtect()), gcm.getOldProtect());
					gcm.remoteCopy(gcp.getProcessHandle());
					VirtualProtectEx(gcp.getProcessHandle(), gcm.getRemoteAddress(), gcm.getRemoteSize(), *(gcm.getOldProtect()), gcm.getNewProtect());

					// Write the data to the dump file
					WriteFile(dumpFile, gcm.getLocalAddress(), gcm.getLocalSize(), (LPDWORD)&bw, 0);

					// Increment the dump file bytes written counter with however many bytes were just written
					dfBW += bw;
					bw = 0;

					// Get the mapping data; address, region size, memory protection, file offset
					snprintf(mapData, 96, "%p,0x%zX,0x%X,0x%X,0x%zX\n", mp->BaseAddress, mp->RegionSize, mp->Protect, mp->Type, (dfBW - mp->RegionSize));

					// Write the contents to the map file
					WriteFile(mapFile, mapData, (DWORD)strlen(mapData), (LPDWORD)&bw, 0);

					// Close both file handles
					CloseHandle(dumpFile);
					CloseHandle(mapFile);
				}
			}

			// Reset memory structure
			gcm.freeLocal();
			gcm.setRemoteAddress((char*)(mp->BaseAddress) + mp->RegionSize);
			gcm.setLocalBufferSize(0);
			gcm.setRemoteBufferSize(0);

		} while (mp->AllocationBase == targetAlloc);

		gcp.closeProcessHandle();

		printf("\n[*] Total allocation size: %zu (0x%zX) bytes\n", allocSize, allocSize);
		printf("[*] Total size of all reserved regions: %zu (0x%zX) bytes\n", reserveSize, reserveSize);
		printf("[*] Total size of all committed regions: %zu (0x%zX) bytes\n", commitSize, commitSize);

		if (modarg.dumpMode)
		{
			printf("\n[*] Successfully wrote %zu (0x%zX) bytes to file %u_%p.dmp\n", dfBW, dfBW, modarg.pid, targetAlloc);
			printf("[*] Check file %u_%p.txt for memory mappings!\n", modarg.pid, targetAlloc);
		}
		
		if (modarg.legendMode) printLegend();

		ExitProcess(0);
	}

	// Check for yaraMode being enabled
	if (modarg.yaraMode)
	{
		bool ruleTest = false;

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
		if (modarg.yaraSourceMode) gcy.setSource(1);
		ruleTest = gcy.addRule(modarg.yaraSource);
		if (!ruleTest)
		{
			printf("[!] Error: Yara rules failed to compile; exiting!\n");
			ExitProcess(0);
		}
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
				//if ((mi->Protect & PAGE_GUARD) != 0) goto skipRegion2;

				// Get committed pages only
				if (mi->State == MEM_COMMIT)
				{
					// Allocate memory to copy the remote buffer and then copy it
					gcm.allocateLocal(mi->RegionSize);
					gcm.setRemoteBufferSize(mi->RegionSize);
					// Set the remote region to RWX, copy it, then set it back the way it was
					gcm.setNewProtect(PAGE_EXECUTE_READWRITE);
					VirtualProtectEx(gcp.getProcessHandle(), gcm.getRemoteAddress(), gcm.getRemoteSize(), *(gcm.getNewProtect()), gcm.getOldProtect());
					gcm.remoteCopy(gcp.getProcessHandle());
					VirtualProtectEx(gcp.getProcessHandle(), gcm.getRemoteAddress(), gcm.getRemoteSize(), *(gcm.getOldProtect()), gcm.getNewProtect());
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

		if (modarg.legendMode) printLegend();

		ExitProcess(0);
	}

	if (modarg.dumpMode && modarg.pid != 0)
	{
		// Create some file handles
		HANDLE dfHandle = 0;
		HANDLE mfHandle = 0;

		// MBI Pointer, memory pointer, error flag, and dump file bytes written
		MEMORY_BASIC_INFORMATION* mi = 0;
		char* memptr = 0;
		DWORD dfBW = 0;
		bool errorFlag = false;

		// Create some space to hold the file names for the dump file and map file
		char* procDumpFile = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 32);
		char* procMapFile = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 32);
		char* mapString = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 80);
		if (procDumpFile == 0 || procMapFile == 0 || mapString == 0)
		{
			errorFlag = true;
			goto errorDumpProcess;
		}

		// Set the dump file and map file names
		snprintf(procDumpFile, 32, "%u_dump.bin", modarg.pid);
		snprintf(procMapFile, 32, "%u_map.txt", modarg.pid);

		// Create some file handles; one for the process dump and one for the mapping information
		dfHandle = CreateFileA(procDumpFile, GENERIC_ALL, 1 | 2 | 4, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		mfHandle = CreateFileA(procMapFile, GENERIC_ALL, 1 | 2 | 4, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		if (dfHandle == INVALID_HANDLE_VALUE || mfHandle == INVALID_HANDLE_VALUE)
		{
			errorFlag = true;
			goto errorDumpProcess;
		}

		// Try to open a process handle to start dumping process memory
		gcp.setProcessID(modarg.pid);
		gcp.setProcessHandle(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, gcp.getProcessID()));
		if (gcp.getProcessHandle() == NULL)
		{
			errorFlag = true;
			goto errorDumpProcess;
		}

		// Print the process that is currently being dumped
		printf("[*] Dumping process %u...\n", modarg.pid);

		// Run through the process memory space and dump each mapped region to the dump file
		// Record each dumped memory region's base address, size, type, current protection, and dump file offset into the map file
		while ((void*)memptr <= ntdll)
		{
			// Clean out the memory basic information structure
			gcm.zeroMBI();

			// Query the memory region of the target process
			gcm.setRemoteAddress(memptr);
			gcm.remoteQuery(gcp.getProcessHandle());
			mi = gcm.getMemoryInfo();

			// Zero the map string
			zeroMemory(mapString, 80);

			// Get committed pages only
			if (mi->State == MEM_COMMIT)
			{
				// Bytes Written
				DWORD bw = 0;

				// Allocate memory to copy the remote buffer and then copy it
				gcm.allocateLocal(mi->RegionSize);
				gcm.setRemoteBufferSize(mi->RegionSize);

				// Set the remote region to RWX, copy it, then set it back the way it was
				gcm.setNewProtect(PAGE_EXECUTE_READWRITE);
				VirtualProtectEx(gcp.getProcessHandle(), gcm.getRemoteAddress(), gcm.getRemoteSize(), *(gcm.getNewProtect()), gcm.getOldProtect());
				gcm.remoteCopy(gcp.getProcessHandle());
				VirtualProtectEx(gcp.getProcessHandle(), gcm.getRemoteAddress(), gcm.getRemoteSize(), *(gcm.getOldProtect()), gcm.getNewProtect());
				gco.allocateBuffer();
				gco.resolveHostNames();

				// Write the region to the dump file; muahahahahaha
				WriteFile(dfHandle, gcm.getLocalAddress(), gcm.getLocalSize(), &bw, 0);
				dfBW += bw;

				// Get the attributes into a string and write them to the map file
				snprintf(mapString, 80, "%p,0x%zX,0x%X,0x%X,0x%zX\n", mi->BaseAddress, mi->RegionSize, mi->Protect, mi->Type, (dfBW - mi->RegionSize));
				bw = 0;
				WriteFile(mfHandle, mapString, (DWORD)strlen(mapString), &bw, 0);

				// Get ready for the next iteration
				gcm.freeLocal();
				gcm.setRemoteBufferSize(0);
			}
			
			// Increate the memory pointer for the next iteration
			if (mi->RegionSize == 0) memptr += 4096;
			else memptr += mi->RegionSize;
		}

		// Print how many bytes were dumped from the process
		printf("[*] Successfully dumped %u (0x%X) bytes from process %u to file %s\n", dfBW, dfBW, modarg.pid, procDumpFile);
		printf("[*] Check file %s for memory mappings\n", procMapFile);

		// Clean up after dumping the process, releasing handles and freeing heap memory
		gcp.closeProcessHandle();
		CloseHandle(dfHandle);
		CloseHandle(mfHandle);
		HeapFree(GetProcessHeap(), 0, mapString);
		HeapFree(GetProcessHeap(), 0, procDumpFile);
		HeapFree(GetProcessHeap(), 0, procMapFile);

	errorDumpProcess:
		if (errorFlag)
		{
			printf("[!] Error: Could not dump process, likely due to invalid process handle, insufficient heap space, or inability to open a file for writing; exiting!\n");
			ExitProcess(1);
		}

		if (modarg.legendMode) printLegend();

		else ExitProcess(0);
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