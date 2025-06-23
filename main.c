#include <stdio.h>
#include "main.h"
#include <windows.h>
#include <winternl.h>
#include <winnt.h>
#include <intrin.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#define g(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define e(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)
#define i(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__)




int main(void) {


    printf("Hello, World!\n");

    STARTUPINFO si;

    HANDLE hProcess;
    LPROCESS_INFORMATION pi;
    LPCSTR path = "C:\\Windows\\System32\\svchost.exe";




    BOOL c = NtCreateProcess(hProcess, NULL, NULL, CREATE_SUSPENDED, 0, NULL, NULL, NULL);

    if (c) {



        NtAllocateVirtualMemory();

        NtWriteVirtualMemory();

        NtSetContextThread();

        NtResumeThread();



    }

    return 0;
}