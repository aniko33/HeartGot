![New Project(2)](https://github.com/user-attachments/assets/98201835-7370-4592-8d5f-8728bd8994c3)

HeartGot is a tool for obtaining syscall numbers (SSNs) using *Capstone Framework* for disassembling and *PeFile* for search functions and getting opcodes.

# Installation

## [NTDLL download](https://www.dll-files.com/ntdll.dll.html)

## Dependencies
- `stone-color`: https://stone-color.readthedocs.io/en/latest/
- `pefile`: https://github.com/erocarrera/pefile?tab=readme-ov-file#installation
- `capstone`: https://www.capstone-engine.org/download.html

## The repository

```
git clone https://github.com/aniko33/HeartGot.git
cd HeartGot
python heartgot.py --help
```

# Usage

```
usage: HeartGot [-h] [-f FUNCTIONS [FUNCTIONS ...]] [-g] [-v] dllPath

Extract SSNs from NTDLL functions

positional arguments:
  dllPath

options:
  -h, --help            show this help message and exit
  -f FUNCTIONS [FUNCTIONS ...], --functions FUNCTIONS [FUNCTIONS ...]
  -g, --generate-header
  -v, --verbose
```

## Get SSNs

`python heartgot.py path/to/ntdll.dll -f NtOpenProcess NtWriteVirtualMemory`

```
[+] NtQueryInformationWorkerFactory SSN: 0x14f
[+] NtOpenProcess SSN: 0x26
[+] NtWriteVirtualMemory SSN: 0x3a
```

## Generate a header

`python heartgot.py path/to/ntdll.dll --generate-header -f NtOpenProcess NtWriteVirtualMemory > heartdirect.h`

### `heartdirect.h`
```
#include "unwin.h"
#ifndef HEARTDIRECT_H_
#define HEARTDIRECT_H_

#define GEN_SYSCALL64(SSN) __asm volatile (   \
    "mov r10, rcx\n"                        \
    "mov eax, " SSN "\n"                    \
    "syscall\n"                             \
)


__stdcall NTSTATUS syscall_NtQueryInformationWorkerFactory(
			_In_ HANDLE WorkerFactoryHandle,
			_In_ WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
			_Out_ PVOID WorkerFactoryInformation,
			_In_ ULONG WorkerFactoryInformationLength,
			_Out_opt_ PULONG ReturnLength
		) {
	GEN_SYSCALL64("0x14f");
}
__stdcall NTSTATUS syscall_NtOpenProcess(
			_Out_ PHANDLE ProcessHandle,
			_In_ ACCESS_MASK DesiredAccess,
			_In_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_opt_ PCLIENT_ID ClientId
		) {
	GEN_SYSCALL64("0x26");
}
__stdcall NTSTATUS syscall_NtWriteVirtualMemory(
			_In_ HANDLE ProcessHandle,
			_In_opt_ PVOID BaseAddress,
			_In_ CONST VOID* Buffer,
			_In_ SIZE_T BufferSize,
			_Out_opt_ PSIZE_T NumberOfBytesWritten
		) {
	GEN_SYSCALL64("0x3a");
}

#endif
```

## How to compile header?

`<compiler> heartgot.h -masm=intel -lntdll -fomit-frame-pointer`

for example `x86_64-w64-mingw32-gcc heartgot.h -masm=intel -lntdll`

# Showcase

![out](https://github.com/user-attachments/assets/984ac433-590c-4819-a386-07eda063c869)
