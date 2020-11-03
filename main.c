#define _WIN32_WINNT 0x0500
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>

typedef struct _STRING {
  WORD Length;
  WORD MaximumLength;
  CHAR *Buffer;
} STRING, *PSTRING;

typedef struct _UNICODE_STRING {
  WORD Length;
  WORD MaximumLength;
  WCHAR *Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _CURDIR {
  UNICODE_STRING DosPath;
  LONG Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
  USHORT Flags;
  USHORT Length;
  ULONG TimeStamp;
  STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _PEB_FREE_BLOCK {
  struct _PEB_FREE_BLOCK *Next;
  ULONG Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef struct _ACTIVATION_CONTEXT_DATA {
} ACTIVATION_CONTEXT_DATA, *PACTIVATION_CONTEXT_DATA;

typedef struct _ASSEMBLY_STORAGE_MAP {
} ASSEMBLY_STORAGE_MAP, *PASSEMBLY_STORAGE_MAP;

typedef struct _FLS_CALLBACK_INFO {
} FLS_CALLBACK_INFO, *PFLS_CALLBACK_INFO;

typedef struct _PEB_LDR_DATA {
  ULONG Length;
  UCHAR Initialized;
  PVOID SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  ULONG MaximumLength;
  ULONG Length;

  ULONG Flags;
  ULONG DebugFlags;

  HANDLE ConsoleHandle;
  ULONG ConsoleFlags;
  HANDLE StandardInput;
  HANDLE StandardOutput;
  HANDLE StandardError;

  CURDIR CurrentDirectory;        // ProcessParameters
  UNICODE_STRING DllPath;         // ProcessParameters
  UNICODE_STRING ImagePathName;   // ProcessParameters
  UNICODE_STRING CommandLine;     // ProcessParameters
  ULONG Environment;              // NtAllocateVirtualMemory

  ULONG StartingX;
  ULONG StartingY;
  ULONG CountX;
  ULONG CountY;
  ULONG CountCharsX;
  ULONG CountCharsY;
  ULONG FillAttribute;

  ULONG WindowFlags;
  ULONG ShowWindowFlags;
  UNICODE_STRING WindowTitle;     // ProcessParameters
  UNICODE_STRING DesktopInfo;     // ProcessParameters
  UNICODE_STRING ShellInfo;       // ProcessParameters
  UNICODE_STRING RuntimeData;     // ProcessParameters
  RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef NTSTATUS (NTAPI *_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    DWORD ProcessInformationLength,
    PDWORD ReturnLength);

typedef struct _PROCESS_BASIC_INFORMATION {
  PVOID Reserved1;
  PVOID PebBaseAddress;
  PVOID Reserved2[2];
  ULONG_PTR UniqueProcessId;
  PVOID Reserved3;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

PVOID
GetPebAddress(HANDLE ProcessHandle) {
  _NtQueryInformationProcess NtQueryInformationProcess =
    (_NtQueryInformationProcess)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
  PROCESS_BASIC_INFORMATION pbi;

  NtQueryInformationProcess(ProcessHandle, 0, &pbi, sizeof(pbi), NULL);
  return pbi.PebBaseAddress;
}

#ifdef _WIN64
# define peb_offset (0x20)
#else
# define peb_offset (0x10)
#endif

static void
error_message(DWORD err) {
  static char buf[256] = {0};
  char *p = buf + sizeof(buf);
  if (err == 0) return;
  FormatMessage(
    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL,
    err,
    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
    buf,
    sizeof buf,
    NULL);
  while (--p > buf) {
    if (*p == '\r' || *p == '\n') {
      *p = 0;
      break;
    }
  }
  fprintf(stderr, "%s\n", buf);
}

int
main(int argc, char *argv[]) {
  DWORD pid = atoi(argv[1]);
  HANDLE hProcess;
  PVOID pebAddress;
  PRTL_USER_PROCESS_PARAMETERS rtlUserProcParams;
  CURDIR currentDirectory;
  WCHAR *currentDirectoryContents;

  hProcess = OpenProcess(
      PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  if (hProcess == NULL) {
    error_message(GetLastError());
    return 1;
  }

  pebAddress = GetPebAddress(hProcess);
  if (!pebAddress) {
    error_message(GetLastError());
    return 1;
  }
  if (!ReadProcessMemory(hProcess, (PCHAR)pebAddress + peb_offset,
        &rtlUserProcParams, sizeof(rtlUserProcParams), NULL)) {
    error_message(GetLastError());
    return 1;
  }

  if (!ReadProcessMemory(hProcess, &rtlUserProcParams->CurrentDirectory,
        &currentDirectory, sizeof(currentDirectory), NULL)) {
    error_message(GetLastError());
    return 1;
  }
  currentDirectoryContents = (WCHAR *)malloc(currentDirectory.DosPath.Length+1);
  if (!ReadProcessMemory(hProcess, currentDirectory.DosPath.Buffer,
        currentDirectoryContents, currentDirectory.DosPath.Length, NULL)) {
    error_message(GetLastError());
    free(currentDirectoryContents);
    return 1;
  }
  CloseHandle(hProcess);

  printf("%.*S\n", currentDirectory.DosPath.Length / 2, currentDirectoryContents);
  free(currentDirectoryContents);
}

/* vim:set et sw=2 ts=2: */
