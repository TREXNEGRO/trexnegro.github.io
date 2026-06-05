---
title: "Two Lenovo Power Manager kernel drivers, one Everyone:RW DACL — a class-pattern in TPPWR64V and ibmpmdrv"
date: 2026-06-05T18:00:00-05:00
draft: false
categories: [Research, BYOVD, Vulnerability Disclosure]
tags: [lenovo, byovd, lpe, dacl, smapi, embedded-controller, ibmpmsvc, tppwr64v, ibmpmdrv, win11, kernel-driver, ioctl]
description: "Two Lenovo Power Manager kernel drivers ship with their device DACL granting Everyone (S-1-1-0) read+write. Any local user — including restricted-token sandboxes — can open the device and reach the IOCTL dispatcher. On `TPPWR64V.SYS` the dispatcher is a gateway to SMAPI Embedded Controller port I/O; on `ibmpmdrv.sys` it returns 18+ kernel-side state values. The identical SDDL on two unrelated devices points at a shared driver-creation template that's worth a class-level audit. Disclosed to Lenovo PSIRT 2026-06-05; this post is the full technical writeup."
ShowToc: true
TocOpen: false
ShowReadingTime: true
ShowCodeCopyButtons: true
---
> **TL;DR** — `TPPWR64V.SYS` and `ibmpmdrv.sys` both create their `\Device\…`
> object with the SDDL `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1201bf;;;WD)(A;;0x1200a9;;;RC)`,
> giving Everyone (`WD`) effectively `FILE_GENERIC_READ | FILE_GENERIC_WRITE`.
> The IOCTL dispatchers expose:
>
> - **TPPWR64V**: 8 IOCTLs routing user-controlled bytes to the IBM/Lenovo SMAPI
>   Embedded Controller index/data window (ports `0x1604`, `0x1610`, `0x1611`,
>   `0x161f`). Full `OUT dx, AL` chain with attacker-controlled `AL` on chassis
>   where the SMAPI EC fires back.
> - **ibmpmdrv**: 18 IOCTLs that return 4-byte kernel-side power-management
>   state values to a non-elevated caller. Driven in production by `ibmpmsvc.exe`
>   running as `SYSTEM` (service `IBMPMSVC`).
>
> Both drivers are WHCP-signed on behalf of Lenovo. Neither is in Microsoft's
> recommended driver block rules. Neither is in LOLDrivers. Coordinated
> disclosure batch sent to `psirt@lenovo.com` 2026-06-05; ack received the
> same day. CVE IDs pending.

---

## How I got here

The setup wasn't supposed to be about Lenovo. I was wiring up infrastructure
for a black-box EDR rule enumeration sprint — Cortex XDR plus a few others,
needed a clean Windows host to baseline against. The host happened to be a
Lenovo ThinkPad-class device (Intel Core Ultra 7 155U, Windows 11 24H2 build
26200, Cortex agent live). Standard corporate-style build.

Cortex API credentials weren't ready, so while I waited I did what you do on
a fresh host: enumerated the driver inventory. `driverquery /v /fo csv` plus
`Get-AuthenticodeSignature` and `Get-FileHash -Algorithm SHA256` across
`C:\Windows\System32\drivers\` and `C:\Windows\System32\DriverStore\FileRepository\`.
1,022 drivers. 136 unique by SHA256 signed under the Microsoft Windows
Hardware Compatibility Publisher (WHCP) cert on behalf of various OEMs.

The WHCP corpus is the interesting one. Anything with a `Microsoft Windows`
signer is part of the OS baseline. Anything WHCP-signed is third-party
attested through Microsoft's process — for our purposes, signed by the OEM
but living in the same trust universe as the kernel itself.

I cross-referenced the 136 WHCP drivers against:

1. Microsoft's recommended driver block rules (the HVCI list, updated
   2026-05-01).
2. The LOLDrivers community database.
3. A keyword tier system over `CompanyName` / `ProductName` / `FileDescription`:
   - **Tier 1**: keywords {`power`, `msr`, `smbus`, `port io`, `physical
     memory`, `dram`, `ec`} → MSR/port-I/O/physmem candidates.
   - **Tier 2**: `acpi`, `bios`, `uefi`, `firmware`, `wmi`, `thermal`.
   - **Tier 3-5**: lower priority.

Three drivers came out top tier from Lenovo:

| File | Tier | Rationale |
|---|---|---|
| `TPPWR64V.SYS` | T1 | Power Manager Vendor Interface; imports `MmMapIoSpace` |
| `ibmpmdrv.sys` | T1 | Lenovo Power Management Driver; imports `IoBuildSynchronousFsdRequest` (proxy pattern) |
| `pmdrvs.sys` | T1 | Lenovo Power Management Driver (pair of `ibmpmdrv`); imports `ZwSetSecurityObject`, `ZwSetValueKey` |

None of the three appeared in the HVCI block list or LOLDrivers. Treat as
fresh.

## TPPWR64V.SYS — the first DACL hit

The device-object name string in `TPPWR64V.SYS` is `\Device\TPPWRIF`, with
the user-mode symlink `\DosDevices\TPPWRIF`. Opening the device:

```c
HANDLE h = CreateFileA("\\\\.\\TPPWRIF",
                       GENERIC_READ | GENERIC_WRITE,
                       0, NULL, OPEN_EXISTING, 0, NULL);
```

succeeds with `GetLastError() = 0` even from an admin-token process running
without elevation. So far standard for a power-management driver designed
to be addressable by a user-mode helper.

The interesting bit is the security descriptor. `GetSecurityInfo` followed
by `ConvertSecurityDescriptorToStringSecurityDescriptor` returns:

```
D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1201bf;;;WD)(A;;0x1200a9;;;RC)
```

Decoding the third ACE — `(A;;0x1201bf;;;WD)`:

- `A` — Allow ACE
- `0x1201bf` — access mask
- `WD` — well-known SID `S-1-1-0`, **Everyone**

Expanded:

```
0x1201bf = SYNCHRONIZE          (0x100000)
         | READ_CONTROL         (0x020000)
         | FILE_WRITE_ATTRIBUTES (0x000100)
         | FILE_READ_ATTRIBUTES (0x000080)
         | FILE_DELETE_CHILD    (0x000040)
         | FILE_EXECUTE         (0x000020)
         | FILE_WRITE_EA        (0x000010)
         | FILE_READ_EA         (0x000008)
         | FILE_APPEND_DATA     (0x000004)
         | FILE_WRITE_DATA      (0x000002)
         | FILE_READ_DATA       (0x000001)
```

That's `FILE_GENERIC_READ | FILE_GENERIC_WRITE`. Any process — even one
holding an LUA-restricted token with `DISABLE_MAX_PRIVILEGE`,
`SANDBOX_INERT`, `LUA_TOKEN` and zero `Administrator` SIDs — can `CreateFile`
this device and pass the handle to `DeviceIoControl`.

I verified this by writing a small reproducer that uses
`CreateRestrictedToken`, confirms via `GetTokenInformation(TokenElevation)`
that the resulting thread token has `TokenIsElevated = 0`, and then opens
the device. It opens.

```
[+] Restricted token created (LUA_TOKEN + DISABLE_MAX_PRIVILEGE)
[+] Now impersonating restricted (non-admin) token
    Thread token TokenIsElevated: 0  (NON-ELEVATED)

[VULNERABILITY CONFIRMED]
    \\.\TPPWRIF opened by RESTRICTED (non-admin) token
```

OK. So we have an unauthenticated entry point. What does the IOCTL surface
look like?

### Reconstructing the dispatcher

The `IRP_MJ_DEVICE_CONTROL` handler in `TPPWR64V_v2_BA6901BC.sys` starts at
file offset `0x11008`. Loading `IoControlCode` and doing the classic
compiler-emitted `sub eax, imm32 ; je <branch>` chain:

```asm
0x000112a7  mov  rbp, qword [rdx + 0xb8]   ; rbp = IrpStack
0x000112ae  mov  r12, qword [rcx + 0x40]   ; r12 = DeviceExtension
0x000112b2  mov  eax, dword [rbp + 0x18]   ; eax = IoControlCode
0x000112b8  sub  eax, 0x9cc0   ; je 0x11494   -> IOCTL 0x9cc0
0x000112c3  sub  eax, 0x1d0    ; je 0x11459   -> IOCTL 0x9e90
0x000112ce  sub  eax, 4        ; je 0x11447   -> IOCTL 0x9e94
0x000112d7  sub  eax, 0x218170 ; je 0x1143a   -> IOCTL 0x222004
0x000112e2  sub  eax, 4        ; je 0x1142d   -> IOCTL 0x222008
0x000112eb  sub  eax, 4        ; je 0x11400   -> IOCTL 0x22200c
0x000112f4  sub  eax, 4        ; je 0x1136f   -> IOCTL 0x222010
0x000112f9  cmp  eax, 0x30     ; je 0x11308   -> IOCTL 0x222040
```

Eight handlers. Reverse-summarising:

| IOCTL | Branch | Behaviour |
|---|---|---|
| `0x9cc0` | `0x11494` | GetInfo. Returns 28 bytes containing driver-internal constant `0x5380`, a DeviceExtension word, and a status byte. |
| `0x9e90` | `0x11459` | EC status check via shared handler `fcn.0x117c0`. Ports `0x1604` and `0x161f`. |
| `0x9e94` | `0x11447` | EC command via shared handler; input goes through converter `fcn.0x119c4`. |
| `0x222004` | `0x1143a` | EC command via shared handler; input goes through converter `fcn.0x11aa8`. |
| `0x222008` | `0x1142d` | EC command via shared handler. |
| `0x22200c` | `0x11400` | EC command (chassis-specific availability). |
| `0x222010` | `0x1136f` | EC command (chassis-specific availability). |
| `0x222040` | `0x11308` | **EC index/data window via `fcn.0x118c0`** — ports `0x1610` and `0x1611`. |

`fcn.0x118c0` is the meaty one. It implements the IBM/Lenovo SMAPI BIOS
index/data window protocol with attacker-controlled bytes.

### The SMAPI port-I/O sequence (with annotations)

```asm
; setup
0x000118dc  mov  r14d, 0x1610          ; index port
0x000118e7  mov  bpl,  dl              ; bpl  = byte 1 of user input
0x000118ea  mov  r12b, cl              ; r12b = byte 0 of user input
0x000118f3  lea  r15d, [r14 + 1]       ; r15d = 0x1611 (data port)

; phase 1 — wait for EC idle
0x000118f9  mov  edx, r14d
0x000118fc  xor  eax, eax
0x000118fe  out  dx, al                ; OUT 0x1610, 0
0x000118ff  mov  edx, r15d
0x00011902  in   al, dx                ; IN  AL, 0x1611
0x00011903  cmp  al, bl                ; bl = 0
0x00011905  je   0x1191b               ; EC idle -> handshake
0x00011907  call KeStallExecutionProcessor  ; 10us
0x00011917  jb   0x118f9               ; loop up to 2000 iterations

; phase 2 — handshake. THESE OUT INSTRUCTIONS WRITE THE ATTACKER'S BYTES.
0x0001191b  mov  edx, r14d
0x0001191e  mov  al, 1
0x00011920  out  dx, al                ; OUT 0x1610, 0x01
0x00011921  mov  edx, r15d
0x00011924  mov  al, 0xff
0x00011926  out  dx, al                ; OUT 0x1611, 0xff
0x00011927  mov  edx, r14d
0x0001192a  mov  al, 0x10
0x0001192c  out  dx, al                ; OUT 0x1610, 0x10
0x0001192d  mov  edx, r15d
0x00011930  mov  al, r12b              ; r12b = user input byte 0
0x00011933  out  dx, al                ; OUT 0x1611, USER_BYTE_0
0x00011934  mov  edx, r14d
0x00011937  xor  eax, eax
0x00011939  out  dx, al                ; OUT 0x1610, 0
0x0001193a  mov  edx, r15d
0x0001193d  mov  al, bpl               ; bpl = user input byte 1
0x00011940  out  dx, al                ; OUT 0x1611, USER_BYTE_1

; phase 3 — read 32 bytes back from EC into user output buffer
0x00011971  lea  eax, [rbx + 0x10]
0x00011974  mov  edx, r14d
0x00011977  out  dx, al                ; OUT 0x1610, idx
0x00011978  mov  edx, r15d
0x0001197b  in   al, dx                ; IN  AL, 0x1611
0x0001197e  mov  byte [rsi], al        ; user_out[i] = EC byte
```

There is no `PreviousMode == UserMode` filter. No caller-token check. No
allow-list of EC sub-commands. The handler dereferences the user buffer
pointer obtained from the IRP at `[rbp+0x18]`, takes byte 0 and byte 1
verbatim, and feeds them to `OUT 0x1611, AL` after the SMAPI command
prefix.

The shared handler `fcn.0x117c0`, reached by the other six EC IOCTLs,
follows the same pattern at ports `0x1604` (ACPI EC compatibility status
window) and `0x161f` (control), again sourcing operand bytes from the
caller's input buffer.

### Runtime — what happens on this chassis

From my non-elevated reproducer the `0x9cc0` GetInfo IOCTL succeeds and
returns the expected 28-byte struct:

```
INPUT  (28 bytes): aabb000000000000000000000000000000000000000000000000
OUTPUT (28 bytes): 8053000000000000000000000000b200000000000000000000000
                   ^^^^
                   driver-internal constant 0x5380
                   (matches static `mov eax, 0x5380` at fcn.114d7)
```

The `0x222040` SMAPI IOCTL returns `Win32err 170` —
`STATUS_DEVICE_BUSY`. That status only originates at
`fcn.0x118c0:0x11946`, reachable after `KeWaitForSingleObject` acquires the
device mutex, the size validation passes, and `fcn.0x118c0` is entered.
The handler's status-poll phase (phase 1 above) executes — every IOCTL
call from our non-elevated caller emits up to 2,000 iterations of
`OUT 0x1610, 0` + `IN AL, 0x1611` in ring 0.

On this Meteor Lake chassis the EC at the SMAPI window never returns the
"idle" signal during the 20 ms polling budget, so the handshake phase that
would emit `OUT 0x1611, USER_BYTE_0` and `OUT 0x1611, USER_BYTE_1` never
runs on this hardware in my testing. On the broader population of
ThinkPads where the SMAPI EC is the primary power-management interface
(roughly anything pre-Meteor Lake), the handshake fires and the attacker
bytes hit the data port. Lenovo PSIRT have the relevant chassis matrix
and can verify trivially.

The vulnerability is the **exposure** — an Everyone-RW DACL on a kernel
device that hosts attacker-controlled port-I/O dispatch. The chassis-by-
chassis EC firmware response is a downstream question.

### Lenovo PS500037 — not the same bug

The historic Lenovo advisory `PS500037` (2016) named the same driver
file but covered a separate primitive — a memory-leakage + DoS path. No
CVE ID was assigned to that advisory; the IOCTL surface and the
Everyone-RW DACL described here are not part of PS500037's scope. The
driver vintage shipped today (`1, 1, 2, 0 built by: WinDDK`) is the same
as the one signed pre-2017 and still propagated through DriverStore
packages on current Lenovo systems.

## ibmpmdrv.sys — same DACL, different exposure

While reading TPPWR64V I noticed `ibmpmdrv.sys` shares the DriverStore
package family. The companion driver `pmdrvs.sys` ships in the same INF.
Quick DACL dump on the three associated devices:

```
\\.\IBMPmDrv:  D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1201bf;;;WD)(A;;0x1200a9;;;RC)
\\.\PMDRVS:    D:P(A;;FA;;;SY)(A;;FA;;;BA)
\\.\PmDrvS:    D:P(A;;FA;;;SY)(A;;FA;;;BA)
```

`\\.\IBMPmDrv` has the **identical** SDDL as `\\.\TPPWRIF`. Same ACE,
same access mask, same well-known SID. Two unrelated drivers, same
template. That's the class-pattern.

The companion `pmdrvs.sys` device — `\\.\PMDRVS` and the alias
`\\.\PmDrvS` — uses the tighter, correct DACL: only `SYSTEM` and
`Administrators`. So someone on the Lenovo PM team knows how to write
the right SDDL; the question is why the template was copy-pasted in a
weakened form across multiple PM drivers.

### Ground-truth IOCTL set from ibmpmsvc.exe

`ibmpmdrv.sys` is not a sleeping driver like TPPWR64V on Meteor Lake —
it's actively driven by `ibmpmsvc.exe`, the SYSTEM-running service
`IBMPMSVC` that owns the Lenovo Power Manager user-mode pipeline.

Instead of guessing the IOCTL surface, I extracted it from
`ibmpmsvc.exe` directly. A few Python lines scanning for
`mov reg32, imm32` / `41 BX imm32` patterns where the immediate matches
the IOCTL device-type-0x22 family (`0x0022xxxx`) yielded a clean set of
20 codes in the range `0x00222400`–`0x002227d8`. These are the IOCTLs the
SYSTEM service issues to `\\.\IBMPmDrv` to drive power management.

A sweep of each code from non-elevated context (LUA token, restricted),
with input sizes 0 / 4 / 8 / 16 / 32 / 64 / 128 / 256 / 1024 and output
buffer 1024, returned `STATUS_SUCCESS` with 4 bytes for 10 of the
ground-truth codes. Adjacency probing around the success set found 8
more reachable codes for a total of 18 IOCTLs returning 4-byte
kernel-side state:

| IOCTL | Returned 4 bytes | Likely meaning |
|---|---|---|
| `0x0022242c` | `07 00 00 00` | feature flag / count |
| `0x00222430` | `10 00 00 00` | size / count = 16 |
| `0x00222434` | `00 02 00 00` | value `0x200` |
| `0x00222438` | `03 00 00 00` | enum value |
| `0x0022243c` | `03 00 00 00` | enum value |
| `0x00222444` | `00 00 00 00` | flag |
| `0x00222580` | `00 08 00 01` | composite `0x01000800` |
| `0x00222584` | `03 00 00 00` | enum value |
| `0x00222590` | `02 00 00 00` | value |
| `0x00222594` | `01 00 00 00` | value |
| `0x002225a4` | `00 00 0a 00` | composite `0x000a0000` |
| `0x00222640` | `00 00 00 80` | flag value `0x80000000` (bit 31 set) |
| `0x0022264c` | `01 00 00 00` | value |
| `0x00222650` | `00 21 00 00` | composite `0x00002100` |
| `0x00222654` | `00 00 00 00` | flag |
| `0x0022270c` | `01 01 00 80` | composite `0x80000101` (bit 31 set) |
| `0x002227d0` | `00 00 00 00` | flag |
| `0x00222400` | (0 bytes) | side-effect-only handler |

Each handler is reached without a token check or `PreviousMode` filter.
A 100-call stability sweep on `0x00222650` confirmed the value is stable
across consecutive calls (one distinct value over 100 iterations), so
these are deterministic reads of driver-side state rather than
race-window noise.

### Proxy paths to other drivers

`ibmpmdrv.sys` imports the IRP-forwarding APIs:

```
IoBuildSynchronousFsdRequest
IoBuildDeviceIoControlRequest
IofCallDriver
IoGetDeviceObjectPointer
IoAttachDeviceToDeviceStack
```

and references downstream device names in its `.rdata`:

```
\DosDevices\ETD          (Elan touchpad)
\DosDevices\SYNTP        (Synaptics touchpad)
\DosDevices\ApFiltr      (Alps pointing-device filter)
\DosDevices\ShockMgr     (Lenovo Active Protection System)
```

So the driver is structured as a multi-device proxy: a handful of IOCTLs
on `\Device\PMDRV` are forwarded as IRPs to whichever of those drivers
is attached on the host. On this Lenovo, four IOCTLs return
`ERROR_FILE_NOT_FOUND` — consistent with the proxy target not being
present. On a chassis with Synaptics, Elan or APS present, those IOCTLs
will succeed, and the downstream driver will see an IRP that *appears*
to come from a trusted Lenovo PM caller — even if the original `\\.\IBMPmDrv`
opener was a non-elevated user-mode process. That's the confused-deputy
surface; I haven't weaponised it (it needs a chassis with the right
target driver attached) but the import surface plus the device-name
references are publicly visible in the binary.

I tested whether the downstream device name comes from user input on
the FILE_NOT_FOUND IOCTLs by sending ASCII and UTF-16 device names
(`\Device\KeyboardClass0`, `\Device\Beep`, `\??\TPPWRIF`, the raw
strings `ETD`, `SYNTP`, `ShockMgr`) at multiple buffer offsets. The
status remained FILE_NOT_FOUND — so on these four IOCTLs the proxy
target is hardcoded, not attacker-supplied. That removes one specific
escalation vector but doesn't remove the underlying class-pattern.

## The class-pattern

The same SDDL string, on two unrelated devices, in two drivers in the
same INF family. The sibling driver `pmdrvs.sys` in that same family
uses the correct, restrictive DACL. This indicates that somewhere in
the Lenovo Power Manager driver code template there is a path that
calls `IoCreateDevice` followed by a security-descriptor application
that opens the device to Everyone — and that path was applied to
`TPPWR64V.SYS` and to `ibmpmdrv.sys` but not to `pmdrvs.sys`.

That template is what should be audited. Not just the two drivers in
this disclosure, but every device-creation site across the Lenovo PM
family, ThinkPad Settings Dependency, Lenovo Vantage power components,
and any successor or spin-off driver that may have inherited the same
helper.

If you ship a kernel driver — OEM or otherwise — and you're calling
`IoCreateDeviceSecure` or building an `SDDL` for the device, the
canonical safe pattern is:

```c
// SDDL_DEVOBJ_SYS_ALL_ADM_ALL — system + admins, everyone else denied
WCHAR* sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
```

The `D:P(A;;FA;;;SY)(A;;FA;;;BA)` we see on `\\.\PMDRVS` is equivalent.
What you do **not** want is an `A;;0x1201bf;;;WD` ACE pinned onto the
end of that DACL, because that's just bolted-on world-write — almost
certainly leftover diagnostic code or a copy-paste from a sample
driver where it was being used during bring-up.

## Reproducing

Build environment: `mingw-w64` on Linux. Three reproducers are
included with this writeup.

### 1. DACL + low-priv CreateFile (TPPWR64V)

```bash
x86_64-w64-mingw32-gcc -O2 -Wall -Wno-format \
    tppwr64v-lowpriv.c -o tppwr64v-lowpriv.exe \
    -static -ladvapi32
```

On any current Lenovo system with the Power Manager Vendor Interface
Driver installed:

```
[+] Baseline (admin): \\.\TPPWRIF opened OK
[+] Restricted token created (LUA_TOKEN + DISABLE_MAX_PRIVILEGE)
[+] Now impersonating restricted (non-admin) token
    Thread token TokenIsElevated: 0  (NON-ELEVATED)

[VULNERABILITY CONFIRMED]
    \\.\TPPWRIF opened by RESTRICTED (non-admin) token
    Low-priv IOCTL 0x9cc0:   ok=1 bytes=28 Win32err=0
    Low-priv IOCTL 0x222040: ok=0 bytes=32 Win32err=170
```

### 2. IOCTL sweep + DACL dump (ibmpmdrv)

```bash
x86_64-w64-mingw32-gcc -O2 -Wall -Wno-format \
    ibmpmdrv-probe.c -o ibmpmdrv-probe.exe \
    -static -ladvapi32
```

Output begins:

```
=== DACL \\.\IBMPmDrv ===
  SDDL: D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1201bf;;;WD)(A;;0x1200a9;;;RC)
  [!!! World-Writable ACE present !!!]

[+] Admin opened \\.\IBMPmDrv

[VULNERABILITY: \\.\IBMPmDrv opened by NON-ADMIN]
  IOCTL=0x00222434 ok=1 bytes=4  out=00020000
  IOCTL=0x00222438 ok=1 bytes=4  out=03000000
  ... (18 IOCTLs total)
```

Full PoC source is on the SixSixSix research repo.

## Disclosure timeline

- **2026-06-05 17:32 ART** — batch report sent to `psirt@lenovo.com`:
  cover letter, both technical writeups, three PoC source files, three
  runtime evidence logs, and the SHA256 manifest. Total payload 16 KB.
- **2026-06-05 (same day)** — auto-acknowledgement from Lenovo PSIRT
  confirming receipt and a 2-business-day response SLA. Confirmation
  that this is the right inbox (not Motorola PSIRT, not LSRC, etc).
- **Expected**: CVE IDs in 2–4 weeks (Lenovo is a CNA). Patches in
  60–90 days under the disclosure window I requested. 30-day reminder
  before public disclosure.

I'll update this post with CVE IDs and the Lenovo advisory link when
they land.

## What's interesting beyond the two drivers

The driver hunt that surfaced these two also produced a tier of Intel
"Innovation Platform Framework" drivers shipping with Meteor Lake —
`ipf_acpi.sys`, `ipf_cpu.sys`, `ipf_lf.sys`, plus `intcpmt.sys` (Intel
Platform Monitoring Technology) and `npu_kmd.sys` (Intel NPU kernel
driver, very new attack surface). Those are queued for a separate
paper-class research effort.

I'll also note that the hunting methodology — enumerate signed
drivers, dump SDDLs, cross-reference against HVCI block list and
LOLDrivers, score by import surface and string references, pull the
user-mode partner where present to get ground-truth IOCTL codes — is
generic. It's the methodology that found these two, and the same
methodology will find the next class-pattern. If you're running it
against a 2020+ ThinkPad / IdeaPad and you see the
`(A;;0x1201bf;;;WD)` ACE on any other PM-family device, that's worth
reporting too.

## Acknowledgements

To Lenovo PSIRT for the prompt acknowledgement and the clear scope
guidance in their auto-response. Vendor PSIRTs that confirm inbox
routing in their first reply make a researcher's day easier.

---

*Reach: research-only writeup. Authorised lab work against an owned
system. No third-party data handled. If you want to chat about the
methodology, hit the contact link on the SixSixSix front page.*
