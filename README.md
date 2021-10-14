# ThreadDread

Author: Gary "kd" Contreras

Latest: 2021-10-14

Version: 1.0

:::::Usage:::::

View usage information by specifying the "-h" option on the command line, like so: "ThreadDread.exe -h".

:::::Description:::::

ThreadDread is a program I designed to be able to do memory analysis and deep process injection analysis workflows on a running system. It can be used as both a live response and hunting tool. As a live response tool, the incident responder may wich to perform the following actions:

1. List running processes on the system
2. List running threads on the system (or from a specific process)
3. List loaded modules (mapped PE files) within a process
4. Scan all running processes for possibly injected binaries (PE files)
5. Scan all running threads for interesting start addresses
6. Scan all running processes (or a specific process) with Yara rules
7. Dump interesting regions of memory within a process
8. Suspend/Resume/Kill a running thread
9. Send scanner output to a remote listening server; used for hunting purposes (tested with a persistent Netcat listener)

All of this functionality is currently featured in version 1.0. If the analyst suspects process injection, ThreadDread should be able to find it using the 3 different scanners available. If they can identify a malicious thread, the tool allows the analyst to suspend, resume, or kill it from the command line without affecting the rest of the, otherwise benign, running process. This functionality was meant to allow the analyst to remove a malicious presence from a legitimate running service without necessarily rebooting the machine.

:::::Future Plans/Features:::::

1. Ingesting Yara rules from the remote server
2. APC stealth injection detection (Gargoyle stager)
