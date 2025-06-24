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

typedef struct _PS_CREATE_INFO
{
    SIZE_T Size;
    PS_CREATE_STATE State;
    union
    {
        // PsCreateInitialState
        struct
        {
            union
            {
                ULONG InitFlags;
                struct
                {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR IFEOSkipDebugger : 1;
                    UCHAR IFEODoNotPropagateKeyState : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
        } InitState;

        // PsCreateFailOnSectionCreate
        struct
        {
            HANDLE FileHandle;
        } FailSection;

        // PsCreateFailExeFormat
        struct
        {
            USHORT DllCharacteristics;
        } ExeFormat;

        // PsCreateFailExeName
        struct
        {
            HANDLE IFEOKey;
        } ExeName;

        // PsCreateSuccess
        struct
        {
            union
            {
                ULONG OutputFlags;
                struct
                {
                    UCHAR ProtectedProcess : 1;
                    UCHAR AddressSpaceOverride : 1;
                    UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
                    UCHAR ManifestDetected : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1 : 3;
                    UCHAR SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                };
            };
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, *PPS_CREATE_INFO;


typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;

    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;

    UNICODE_STRING RedirectionDllName; // REDSTONE4
    UNICODE_STRING HeapPartitionName; // 19H1
    ULONG_PTR DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;



typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef const OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

typedef DWORD ACCESS_MASK;
typedef ACCESS_MASK* PACCESS_MASK;

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
#define InitializeObjectAttributes(p, n, a, r, s) { \
(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
(p)->RootDirectory = r; \
(p)->Attributes = a; \
(p)->ObjectName = n; \
(p)->SecurityDescriptor = s; \
(p)->SecurityQualityOfService = NULL; \
}

typedef NTSTATUS(NTAPI *NtCreateUserProcess)(

_Out_ PHANDLE ProcessHandle,
_Out_ PHANDLE ThreadHandle,
_In_ ACCESS_MASK ProcessDesiredAccess,
_In_ ACCESS_MASK ThreadDesiredAccess,
_In_opt_ PCOBJECT_ATTRIBUTES ProcessObjectAttributes,
_In_opt_ PCOBJECT_ATTRIBUTES ThreadObjectAttributes,
_In_ ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
_In_ ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
_In_opt_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
_Inout_ PPS_CREATE_INFO CreateInfo,
_In_opt_ PPS_ATTRIBUTE_LIST AttributeList


);




typedef NTSTATUS(NTAPI *NtGetNextProcess)(
_In_opt_ HANDLE ProcessHandle,
_In_ ACCESS_MASK DesiredAccess,
_In_ ULONG HandleAttributes,
_In_ ULONG Flags,
_Out_ PHANDLE NewProcessHandle

);

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


typedef NTSTATUS (NTAPI *NtReadFile)(

_In_ HANDLE FileHandle,
 _In_opt_ HANDLE Event,
 _In_opt_ PIO_APC_ROUTINE ApcRoutine,
 _In_opt_ PVOID ApcContext,
 _Out_ PIO_STATUS_BLOCK IoStatusBlock,
 _Out_writes_bytes_(Length) PVOID Buffer,
 _In_ ULONG Length,
 _In_opt_ PLARGE_INTEGER ByteOffset,
 _In_opt_ PULONG Key
);

typedef NTSTATUS(NTAPI * NtAllocateLocallyUniqueId)(

    _Out_ PLUID Luid

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



typedef NTSTATUS(NTAPI *RtlCreateProcessParametersEx) (
    _Out_ PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
     _In_ PUNICODE_STRING ImagePathName,
     _In_opt_ PUNICODE_STRING DllPath,
     _In_opt_ PUNICODE_STRING CurrentDirectory,
     _In_opt_ PUNICODE_STRING CommandLine,
     _In_opt_ PVOID Environment,
     _In_opt_ PUNICODE_STRING WindowTitle,
     _In_opt_ PUNICODE_STRING DesktopInfo,
     _In_opt_ PUNICODE_STRING ShellInfo,
     _In_opt_ PUNICODE_STRING RuntimeData,
     _In_ ULONG Flags

);

VOID NTAPIRtlInitUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_ PWSTR SourceString
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