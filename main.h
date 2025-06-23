//
// Created by fallon on 6/22/25.
//

#ifndef MAIN_H
#define MAIN_H

#endif //MAIN_H



typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef NTSTATUS (NTAPI *PUSER_THREAD_START_ROUTINE)(
    _In_ PVOID ThreadParameter
    );

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;


typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

//define the different functions


typedef NTSTATUS(NTAPI *NtCreateProcess)(

    _Out_ PHANDLE ProcessHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
  _In_ HANDLE ParentProcess,
  _In_ BOOLEAN InheritObjectTable,
  _In_opt_ HANDLE SectionHandle,
  _In_opt_ HANDLE DebugPort,
  _In_opt_ HANDLE TokenHandle

);


typedef NTSTATUS(NTAPI *NtUnmmapViewOfSection)(
_In_ HANDLE ProcessHandle,
  _In_opt_ PVOID BaseAddress
);

typedef NTSTATUS(NTAPI *NtAllocateVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection
);


typedef NTSTATUS(NTAPI *NtGetContextThread)(
    _In_ HANDLE ThreadHandle,
    _Inout_ PCONTEXT ThreadContext
);

typedef NTSTATUS(NTAPI *NtResumeThread)(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
);

typedef NTSTATUS(NTAPI *NtCreateFile)(


    _Out_ PHANDLE FileHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_opt_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes,
    _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition,
    _In_ ULONG CreateOptions,
    _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
    _In_ ULONG EaLength


);
typedef NTSTATUS(NTAPI *NtOpenProcess)(
_Out_ PHANDLE ProcessHandle,
_In_ ACCESS_MASK DesiredAccess,
_In_ POBJECT_ATTRIBUTES ObjectAttributes,
_In_opt_ PCLIENT_ID ClientId
);


typedef NTSTATUS(NTAPI *NtWriteVirtualMemory)(
_In_ HANDLE ProcessHandle,
_In_opt_ PVOID BaseAddress,
_In_reads_bytes_(BufferSize) PVOID Buffer,
_In_ SIZE_T BufferSize,
_Out_opt_ PSIZE_T NumberOfBytesWritten
    );