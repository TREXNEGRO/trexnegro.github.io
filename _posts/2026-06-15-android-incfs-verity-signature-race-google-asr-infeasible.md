---
title: 'Android IncFS verity-signature race — and what Google ASR "Won''t Fix (Infeasible)" actually means'
date: 2026-06-15 22:30:00 -0500
categories: [Research, Android Kernel]
tags: [android, kernel, incfs, fs-verity, race-condition, double-free, kaslr-bypass, slub, freelist-corruption, google-asr, vendor-declined, won-t-fix, infeasible, disclosure]
toc: true
lang: en
description: >-
  fs/incfs/verity.c::incfs_read_signature() declares its working pointer
  to the verity-signature heap buffer as `static`. The qualifier puts the
  pointer in a single BSS slot shared across every invocation from every
  thread or process on the system. Two racing ioctl calls produce a
  KASAN double-free in kmalloc-256, a cross-process information leak, a
  KASLR-relevant kernel pointer disclosure, and — on a kernel with
  CONFIG_SLAB_FREELIST_HARDENED + RANDOM + KASLR all on — SLUB freelist
  corruption with attacker-controlled bytes. Reported to Google ASR,
  closed Won't Fix (Infeasible) five weeks later. Publishing the
  reproducer and the architecture, and a working note on what the
  "Infeasible" verdict actually communicates about Google's framing of
  reporter-side exploitability work.
---

> **TL;DR** — A single-character bug in `fs/incfs/verity.c`
> (`static u8 *signature;` should be `u8 *signature;`) produces, in
> order: a KASAN double-free in `kmalloc-256`, a cross-process
> information leak reaching `priv_app`, a kernel-pointer disclosure
> that breaks slab-region KASLR, and SLUB freelist corruption with
> attacker-controlled bytes on a kernel with all stock Android
> allocator hardening turned on. The fix is dropping the `static`
> qualifier. Submitted to Google Android & Devices VRP on 2026-05-09;
> closed as **Won't Fix (Infeasible)** on 2026-06-15. Reproducer at
> [`TREXNEGRO/Research/android-incfs-verity-signature-race`](https://github.com/TREXNEGRO/Research/tree/master/android-incfs-verity-signature-race).
> The rest of this post is the bug, the runtime evidence, and a
> working note on what the "Infeasible" verdict actually
> communicates.
{: .prompt-tip }

## Why this post exists

Two reasons.

First, the bug is a clean instance of a small bug class that's been
hiding in plain sight in mainline-derived kernels for years: a
function-local `static` pointer used as scratch storage for a
heap-allocated buffer. Removing the qualifier is the entire fix, but
the dispatching of consequences if you leave it in place stretches
all the way from a cross-process privacy boundary crossing to an
attacker-controlled freelist next-pointer on a fully-hardened
kernel. I want a stable URL to point at the next time the same
shape shows up.

Second, the vendor verdict is itself the more interesting half of the
story. Google ASR closed the report on 2026-06-15 as **Won't Fix
(Infeasible)** — the canonical phrasing they reserve for bugs whose
end-to-end exploitability the reporter has not closed in the open
lab. The triager's note reads:

> *"We have logged this issue for potential remediation in a future
> version. At this time, this report is considered closed and will no
> longer be monitored."*

That's a real disclosure outcome that researchers running similar
pipelines should know how to read. The bug, as the reporter
documented and the triager presumably read, runtime-produces a
KASAN double-free deterministically, an info leak that crosses the
sepolicy boundary into `priv_app`, a kernel pointer disclosure, and
allocator metadata corruption with attacker-controlled bytes on
stock hardening. The triager looked at that and concluded "not a
security vulnerability". I think the verdict is wrong, but I think
the reason it's wrong matters more than the verdict, and the rest
of this post walks through both.

## Background — IncFS and verity signatures in 60 seconds

Modern Android (14, 15, 16) installs app code into the per-app data
directory and serves it through the in-kernel **Incremental
FileSystem** (`fs/incfs/`). IncFS is an Android-specific filesystem
in the Android Common Kernel tree; it does not ship in mainline
Linux. Its central trick is to let the package installer hand the
kernel a Merkle-tree manifest and start serving data blocks before
all of them are present on disk, fetching missing blocks
on-demand. The fs-verity layer on top guarantees that each block
served back to userspace matches the manifest's hash.

For sensitive deployments — Google Play, system apps, anything
mounted through `DataLoaderService` — IncFS also carries a
**verity signature blob** attached to the file. The signature is
supplied by userspace at verity-enable time via the
`FS_IOC_ENABLE_VERITY` ioctl, stored in the file's metadata, and
returned to userspace later via `FS_IOC_READ_VERITY_METADATA` with
`metadata_type = FS_VERITY_METADATA_TYPE_SIGNATURE`.

Two facts about the signature blob matter for this post:

1. IncFS itself does **not** validate the blob against any keyring.
   The handler at `verity.c:526-534` `memdup_user`'s the bytes and
   stores them. Whatever userspace hands the kernel becomes the
   stored signature for that file, with full attacker control over
   size and contents.
2. The trigger for the bug is the read-back ioctl, which is callable
   per stock AOSP main sepolicy from `system_server` and from
   `priv_app` — including Phonesky / `com.android.vending` and any
   privileged `DataLoaderService` consumer. The relevant attacker
   model is a compromised privileged app on the device.

## The bug

```c
/* fs/incfs/verity.c — android-common-15-6.6 @ a47b8d1a47, line 773 */

static int incfs_read_signature(struct file *filp,
                                void __user *buf, u64 offset, int length)
{
        size_t sig_size;
        static u8 *signature;     /* <-- THE BUG */
        int err;

        signature = incfs_get_verity_signature(filp, &sig_size);
        if (IS_ERR(signature)) return PTR_ERR(signature);
        if (!signature)        return -ENODATA;

        length = min_t(u64, length, sig_size);
        err = copy_to_user(buf, signature, length);
        kfree(signature);
        return err ? err : length;
}
```

The `static` qualifier on a function-local pointer allocates a
single BSS slot for the whole running kernel — verified by `nm
fs/incfs/verity.o`, which shows a `signature.0` symbol in section
`.bss`. Every invocation of the function from every thread or
process on the system shares that slot.

The C abstract machine does not save the reader from this. Because
`copy_to_user` lives in a different translation unit, the compiler
cannot prove that the function does not modify `signature`, and so
must reload the pointer from the BSS slot between the assignment
and each subsequent use. The compiler's caution gives the racing
thread a window to overwrite the slot.

### The race choreography

```
Thread A                                Thread B
────────                                ────────
signature = kzalloc(...) → ptr_A
[BSS slot := ptr_A]
                                        signature = kzalloc(...) → ptr_B
                                        [BSS slot := ptr_B]
copy_to_user(buf_A, [slot=ptr_B], lenA)
                ↑
                Thread A returns Thread B's allocation contents
                to Thread A's userspace buffer — cross-process info leak.
kfree([slot=ptr_B])
                ↑
                Thread A frees Thread B's allocation.
                                        copy_to_user(buf_B, [slot=ptr_B-FREED], lenB)
                                                                ↑
                                                                Thread B reads
                                                                from freed memory
                                                                — UAF read.
                                        kfree([slot=ptr_B-FREED])
                                                                ↑
                                                                Double-free.
```

Either two threads inside the same process or two processes on
unrelated IncFS mounts race on the same BSS slot. The signature blob
that surfaces in the racing `copy_to_user` belongs to a *different*
file — typically a file owned by a different process. That is the
privacy boundary crossing.

## The patch

The fix is one character.

```diff
diff --git a/fs/incfs/verity.c b/fs/incfs/verity.c
@@ -770,7 +770,7 @@ static int incfs_read_signature(struct file *filp,
                                void __user *buf, u64 offset, int length)
 {
        size_t sig_size;
-       static u8 *signature;
+       u8 *signature;
        int err;
```

`scripts/checkpatch.pl --strict` reports zero errors. Single-thread
behaviour is identical (the function works fine when the pointer is
a stack-local, which is what every other similar handler in the
same file does). The race window closes entirely. The patched
kernel produces zero KASAN reports and zero cross-process leak
events across 1.28 million iterations of the same workload that
generates 2,976 leak events on the vulnerable kernel.

The signed-off patch lives in
[`patch/0001-incfs-drop-misuse-of-static-local.patch`](https://github.com/TREXNEGRO/Research/blob/master/android-incfs-verity-signature-race/patch/0001-incfs-drop-misuse-of-static-local.patch)
in the reproducer repo.

## What the runtime evidence actually shows

I want to spend a little time on the runtime evidence because the
shape of the primitives is what makes the eventual verdict so
strange.

### KASAN double-free, deterministic

On a vulnerable + KASAN kernel, the minimal PoC v1 (8 threads × 200
iterations per thread, 1,600 ioctl calls total) produces a KASAN
double-free in every run. Twenty out of twenty in the reliability
suite. The faulting object is in `kmalloc-256`, which is exactly
the size class of the verity-signature allocation
(`kzalloc(vs->size, GFP_KERNEL)` with `vs->size = 256` in the PoC):

```
BUG: KASAN: double-free in __kmem_cache_free+0x175/0x2c0
Free of addr ffff8881036bdc00 by task poc-incfs-04/84
Call Trace:
 <TASK>
 ____kasan_slab_free+0x165/0x180
 kfree+0x6f/0xe0
 incfs_ioctl_read_verity_metadata+0x5b3/0x8f0
 dispatch_ioctl+0x3bd/0x1210
 __x64_sys_ioctl+0x13d/0x1b0
 ...
The buggy address belongs to the object at ffff8881036bdc00
 which belongs to the cache kmalloc-256 of size 256
```

KASAN is not a contrived instrumentation here — it's the
instrumentation Google itself uses to ship fuzzer-found kernel
bugs to syzbot. A deterministic KASAN double-free reachable from
`priv_app` is the kind of thing the program lists in its severity
matrix as **High**.

### Cross-process information leak

The v3-stress PoC partitions four unrelated processes, each
mounting its own IncFS instance and enabling verity on its own
file with a per-process marker byte (`0x41` / `0x42` / `0x43` /
`0x44`). Each process fills its userspace receive buffer with
`0x55` before each ioctl. After the ioctl, it scans the first 32
bytes of the buffer for any byte that differs from its own
marker. Any non-matching byte is recorded as a leak event.

Across 20 vulnerable + KASAN runs of the v3 stress suite (8000
iterations × 4 threads × 4 processes per run): **2,976 leak
events / 2,560,000 iterations, 100% of runs produce ≥ 1 event**.
On the patched kernel running the same workload: **0 leak events
/ 1,280,000 iterations**.

The leaks aren't subtle. Worker A returns Worker B's `0x42`
marker bytes to its own buffer. Worker D returns Worker C's
`0x43` bytes. The races resolve in any cross-process direction.
This is a privacy-boundary crossing reachable from `priv_app`.

### Kernel pointer disclosure

One sample from the v3-stress output is particularly worth
isolating:

```
[C] thread 0 FIRST LEAK at iter 150,
    sample: 00 6a 80 03 81 88 ff ff
```

Worker C's marker is `0x43`. The bytes returned are
`00 6a 80 03 81 88 ff ff`. Decoded as a little-endian `u64`, that
is `0xffff8881_03806a00` — a canonical x86\_64 kernel address in
the slab linear-mapped region. The most natural explanation is
that the racing `copy_to_user` is reading from a freed
`kmalloc-256` object whose first eight bytes have already been
populated by the SLUB allocator with a freelist next-pointer for
that slab cache.

The disclosure breaks KASLR for the slab linear-mapped region,
which is the layer of randomisation a kernel exploit normally
needs to defeat before staging a heap-spray.

### SLUB freelist corruption with attacker bytes

The most explicit primitive sits on a separate kernel build —
`CONFIG_KASAN` *off*, with all the stock Android allocator
hardening *on*:

- `CONFIG_SLAB_FREELIST_HARDENED=y`
- `CONFIG_SLAB_FREELIST_RANDOM=y`
- `CONFIG_RANDOMIZE_BASE=y`

This is the configuration a real Pixel image ships with. A single
workload run of PoC v5 produced **18 `kernel BUG at mm/slub.c:433` +
6 general protection faults**, all rooted in
`incfs_ioctl_read_verity_metadata`. Representative GPF:

```
general protection fault, probably for non-canonical address
        0xcc73cdddc8d9e7d: 0000 [#1] PREEMPT SMP NOPTI
RIP: 0010:__kmem_cache_alloc_node+0xf4/0x180
Call Trace:
 <TASK>
 __kmem_cache_alloc_node+0xf4/0x180
 __kmalloc+0x59/0x140
 load_msg+0x44/0x140
 do_msgsnd+0x123/0x460
 __x64_sys_msgsnd+0x4d/0x70
 ...
```

The leading `0xcc` byte in the faulting address is the PoC's
`0xCC` spray sentinel. The PoC sprays `0xCC` into freed
`kmalloc-256` slots (via System V message-passing); the kernel,
when it pops the corrupted slot off the freelist, reads
`0xCC...0xCC` as the freelist next-pointer, XORs it against the
per-cache cookie inside `freelist_ptr_decode`, gets a non-canonical
address, and faults. The leading `0xcc` survives the cookie XOR
because the cookie is a constant-per-cache value — proof that the
kernel was reading attacker-controlled bytes as the freelist
metadata.

That is the textbook upstream half of every modern Linux LPE
chain: attacker controls the freelist next-pointer in a generic
slab cache, allocator hands the controlled pointer to the next
`kmalloc` of the right size, controlled pointer becomes the
identity of a kernel object the attacker did not allocate.

## What the patch eliminates

I want to be careful to report the negative control too. The same
workloads, run against the patched kernel:

- v1, 10 runs: 0 KASAN reports, 0 BUGs, 0 GPFs.
- v3, 10 runs: 0 leak events / 1,280,000 iterations.
- v5, 1 run: 0 BUGs, 0 GPFs, allocator metadata clean.

Functional behaviour is preserved: a sanity read of the signature
on the patched kernel returns the right 256 bytes with the
`K-INCFS-04-MARK!` marker prefix the PoC writes. The
single-thread path uses the now-stack-local pointer exactly as it
used the BSS slot before; the only difference is that the BSS
slot no longer exists.

## What Google ASR said

The report (the technical content above plus the appendices that
unpack the reachability story, the cross-branch verification, and
the exhaustion attempt) was filed via the Bug Hunters portal on
2026-05-09. The lifecycle:

| Date         | Event |
|---           |---    |
| 2026-05-09   | Submitted. Auto-reply: assigned internal Android ID; CLA request; PoC reproduction request. |
| 2026-05-19   | I confirm CLA signed and the PoC details already in the package. |
| 2026-05-19   | Android Security Team acknowledges and forwards to the technical team. |
| 2026-06-15   | Closed: **Status: Won't Fix (Infeasible)**. |

The full closing comment:

> *"Thank you for taking the time to submit this report to the
> Android & Google Device Vulnerability Reward Program! We have
> investigated this issue and determined that this is not a
> security vulnerability. We have logged this issue for potential
> remediation in a future version. At this time, this report is
> considered closed and will no longer be monitored. If you
> believe this is an error, please submit a new report..."*

That last sentence is structurally meaningful and I'll come back
to it.

## What "Won't Fix (Infeasible)" actually communicates

ASR has a specific institutional meaning for **Infeasible** that
isn't quite what the English word suggests. It does not mean
"impossible to exploit". It means "the reporter did not close the
chain end-to-end against a real target in the open lab, and the
program does not invest internal exploitability work on the
reporter's behalf for VRP-bounty purposes".

The published severity criteria support this read. The Android
severity guidelines describe High and Critical impacts in terms
of demonstrated capability against the device (privilege
escalation, sandbox escape, remote code execution). They do not
articulate a partial-primitive bar — even a deterministic
double-free in a generic cache reachable from `priv_app` doesn't
have a named row in the matrix, because the matrix is structured
around demonstrated end-impact.

There is internal logic to this. ASR ratings drive bounty
amounts, and bounties are designed to reward the work that turns
a primitive into a chain. The CTF-style end-to-end exploit is
the work the program is buying. If a reporter ships a primitive
and not a chain, the program's position is that a different
reporter (or an internal team) could equally well ship a chain
against the same primitive, and only the chain-shipping
reporter is paid.

The friction in this particular case is twofold.

**One**, the reporter's exhaustion attempt against a public-image
QEMU lab cannot, by construction, close the chain end-to-end.
Closing it requires three things the external researcher does not
have:

- the per-cache freelist cookie value for the targeted Pixel
  build (the `random_kmem_cache_random_seed` derived per cache,
  used inside `freelist_ptr_decode`);
- victim-struct enumeration on the actual Pixel kernel image
  (which `kmalloc-256`-sized struct contains a function pointer
  the attacker can usefully reuse);
- the Pixel kernel image itself (which is delivered as part of
  the OTA system image, not as a public artefact for
  pre-release).

A QEMU lab build will produce the upstream half of the chain
deterministically and will not produce the downstream half
unless the researcher happens to ship the same per-build artefacts
Google ships internally to themselves. The "exhaustion attempt"
in the report is the documented honest answer: the upstream half
exists, the downstream half requires artefacts I don't have.

**Two**, the report says so out loud. The bug's framing volunteers
the gap:

> *"the downstream chain... did NOT close in the public-image
> lab"*

> *"potentially higher pending Google exploitability assessment"*

I think this is the right framing for the work the report
actually describes. It's also the framing the triager's algorithm
reads as "no demonstrated severity". Several other researchers
have written privately that they hit the same outcome with
similar phrasing.

I do not have a good answer for what the right rewording is for
future reports. The honest framing of an honest primitives-only
report carries the same information. Stripping the "did not
close" sentence is closer to padding than to communication. I'll
report back if someone runs the experiment of submitting the
identical evidence pack with different framing and gets a
different outcome.

## What the verdict does *not* say

For completeness:

- It does not say the bug isn't there. The first reply (#2)
  states the report has been *"filed for the Android engineering
  team to investigate further"*, the closing comment notes the
  issue is *"logged for potential remediation in a future
  version"*. The bug exists in their tree. Their position is
  that it doesn't reach the program's severity bar.
- It does not say the PoC doesn't reproduce. The PoC ships with
  20-out-of-20 reliability, full per-run logs, and a one-line
  patch that turns off the same workload's output.
- It does not say `priv_app` isn't the attacker model. The
  reachability section of the report cites the AOSP main
  sepolicy lines that grant the trigger to `priv_app`. The
  triager did not push back on the reachability claim.

The verdict says: not enough demonstrated end-impact to clear the
severity bar for VRP rating purposes.

## What I'm doing about it

The closing comment invites a re-submission "if you believe this
is an error, please submit a new report and include all necessary
information on why this is a valid vulnerability according to our
published severity guidelines."

I will not be doing that. Resubmitting without an end-to-end UID=0
payload would produce the same verdict; producing the end-to-end
payload requires the Pixel build artefacts and the per-cache
cookie value, which I do not have. I respect the program's
institutional reason for that rule even when I think it produces
the wrong outcome in this specific case.

Instead:

1. **This post.** The bug, the architecture, the reproducer, and
   a working description of what the verdict actually says are
   public so that the next researcher who hits the same wall has
   a shape to compare against. The notification to the vendor
   has been made; the responsible-disclosure obligation is
   discharged.
2. **CVE via MITRE.** A CVE request goes to MITRE on the same
   day as this post. The bug is in upstream Android Common
   Kernel code, source publicly available, runtime-confirmed,
   patch shipped. MITRE assigns on these terms.
3. **The reproducer in
   [`TREXNEGRO/Research`](https://github.com/TREXNEGRO/Research/tree/master/android-incfs-verity-signature-race).**
   PoC source for all five primitive variants, sample crash
   logs, and the one-line patch. Buildable from the public
   Android Common Kernel tree.

## What this is not

It is not an end-to-end UID=0 exploit kit. The primitives are
documented as primitives. The downstream chain (controlled reuse
to a chosen target, type confusion against a chosen victim
struct, control-flow influence, `commit_creds(prepare_kernel_cred(NULL))`
invocation) was attempted in a dedicated exhaustion phase against
the public-image lab and did not complete; the blockers are
documented above and in
[`appendix/`](https://github.com/TREXNEGRO/Research/tree/master/android-incfs-verity-signature-race)
of the original submission package.

If you are building defensive instrumentation and want to detect
the primitives, the things to watch are:

- `kfree()` arriving from `incfs_ioctl_read_verity_metadata` with
  the same address freed twice from different tasks (KASAN
  catches this trivially);
- userspace buffers returned from
  `FS_IOC_READ_VERITY_METADATA` that do not match the file's
  configured signature byte-for-byte after the read;
- pages of `kmalloc-256` showing freelist next-pointers whose
  high byte after `freelist_ptr_decode` is a constant `0xCC`-style
  attacker sentinel.

If you are an Android Common Kernel maintainer running this post
through the usual triage, the patch is two lines, the test is
`./run.sh patched 10` against an unmodified initramfs, and the
expected output is zero events.

## Acknowledgements

The Google Android Security Team triager who handled the report
was polite and prompt throughout the five-week window, which is
not always how vendor interactions go. This post pushes back on
the verdict, not on the people, and the program's institutional
reasoning is worth engaging with seriously even when (especially
when) one disagrees with where it lands in a specific case.

If anyone from the program reads this and would like to revisit,
my contact details are at the foot of the
[reproducer repo](https://github.com/TREXNEGRO/Research/tree/master/android-incfs-verity-signature-race).
