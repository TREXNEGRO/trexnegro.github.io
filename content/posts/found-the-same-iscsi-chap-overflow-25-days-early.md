---
title: "Found the same Linux iSCSI CHAP base64 overflow 25 days early — and what 'review-ready' really means"
date: 2026-06-01T21:00:00-05:00
draft: false
categories: [Research, Linux Kernel]
tags: [linux-kernel, lio, iscsi, chap, base64, overflow, kasan, qemu, upstream, walkthrough, methodology]
description: "In May I found a pre-auth heap overflow in the Linux LIO iSCSI target's CHAP BASE64 decoder. I built the patch, took a KASAN trace, wrote the review document — and then sat on it for two weeks. While the patch was in \"operator review\", another researcher (ahossu) found the same bug independently, sent upstream, and got the fix merged. This is the walkthrough of the bug, the math, the patch I almost shipped, and the lesson I actually learned about review cadence."
ShowToc: true
TocOpen: false
ShowReadingTime: true
ShowCodeCopyButtons: true
---
> **TL;DR** — `chap_server_compute_hash()` in `drivers/target/iscsi/iscsi_target_auth.c` decodes the attacker-controlled CHAP_R BASE64 string into a `kzalloc(chap->digest_size)` buffer. The decoder writes one byte per four input chars with no destination-size argument, and the post-decode length check fires *after* the write. A 128-char CHAP_R BASE64 decodes to 96 bytes; with MD5 (`digest_size = 16`) that's 80 bytes of attacker-chosen OOB into kmalloc-16, pre-auth, one TCP connection. Fixed upstream as commit `85db7391310b` ("scsi: target: iscsi: bound BASE64 CHAP_R input to digest size") by [ahossu] on the 7.1/scsi-fixes queue. I found the same bug 25 days before the fix landed and never sent the patch. This post is the walkthrough, the patch I had ready, and the lesson.

[ahossu]: https://ahossu.ro/blog/iscsi-chap-base64-overflow

## Why I'm writing this

Two reasons.

First, the bug is a textbook example of a class that's worth being able to spot at a glance: an attacker-controlled length feeds a decoder that writes without a destination-size bound. The pattern repeats often enough in kernel-network code that it earns a walkthrough. ahossu's [own write-up][ahossu] is the canonical reference; this post adds the parts I went through that didn't appear in theirs, including the patch shape I converged on independently (which turned out to be byte-identical to what shipped upstream).

Second, the meta-lesson. I found this bug on 2026-05-05, had a patch ready on 2026-05-12 marked "REVIEW-READY", and then it sat. ahossu found it independently, wrote essentially the same fix, sent it upstream, and Sasha Levin AUTOSEL'd it for stable on or around 2026-05-25. The credit went to whoever shipped, not whoever found. That's correct — kernel upstream rewards getting the work done, not getting the work nearly done — and the moral is one I'd rather absorb in public than re-learn privately.

If you've ever sat on a "near-go" patch for two weeks, this post is partly for you.

## The bug

`drivers/target/iscsi/iscsi_target_auth.c` carries the CHAP authentication handler for the Linux LIO iSCSI *target* (server-side). During Security Negotiation in the iSCSI Login phase, the target asks the initiator for a CHAP response (`CHAP_R`) and verifies it. Two response encodings are accepted: HEX and BASE64.

The HEX branch (around line 332):

```c
case HEX:
    if (strlen(chap_r) != chap->digest_size * 2) {
        pr_err("Malformed CHAP_R\n");
        goto out;
    }
    if (hex2bin(client_digest, chap_r, chap->digest_size) < 0) {
        pr_err("Malformed CHAP_R: invalid HEX\n");
        goto out;
    }
    break;
```

The HEX check is the canonical "verify length before decoding" form. `strlen(chap_r)` must exactly equal `digest_size * 2`, then `hex2bin` writes exactly `digest_size` bytes. Safe.

The BASE64 branch (around line 342):

```c
case BASE64:
    if (chap_base64_decode(client_digest, chap_r, strlen(chap_r)) !=
        chap->digest_size) {
        pr_err("Malformed CHAP_R: invalid BASE64\n");
        goto out;
    }
    break;
```

Different shape: the decoder is called *first*, the length is checked *after*. To see why that's a problem, look at `chap_base64_decode` (line 211):

```c
static int chap_base64_decode(u8 *dst, const char *src, size_t len)
{
    int i, bits = 0, ac = 0;
    const char *p;
    u8 *cp = dst;

    for (i = 0; i < len; i++) {
        if (src[i] == '=')
            return cp - dst;

        p = strchr(base64_lookup_table, src[i]);
        if (p == NULL || src[i] == 0)
            return -2;

        ac <<= 6;
        ac += (p - base64_lookup_table);
        bits += 6;
        if (bits >= 8) {
            *cp++ = (ac >> (bits - 8)) & 0xff;            /* ← write */
            ac &= ~(BIT(16) - BIT(bits - 8));
            bits -= 8;
        }
    }
    if (ac)
        return -1;

    return cp - dst;
}
```

The signature is `(u8 *dst, const char *src, size_t len)`. `dst` has no length parameter. The function writes one byte per four BASE64 chars to `*cp++` for the full length of `src`. The caller's bound check fires after the function returns — at which point the overflow is already done.

`client_digest` is allocated at line 275:

```c
client_digest = kzalloc(chap->digest_size, GFP_KERNEL);
```

`chap->digest_size` is 16 for MD5, 20 for SHA-1, 32 for SHA-256, 64 for SHA-512.

`chap_r` is bounded at line 325:

```c
if (extract_param(nr_in_ptr, "CHAP_R", MAX_RESPONSE_LENGTH, chap_r,
            &type) < 0) {
```

`MAX_RESPONSE_LENGTH` is **128**. A 128-character BASE64 string decodes to (128 × 3) / 4 = **96 bytes**.

That gives us the overflow extent per algorithm:

| digest | digest_size | max decoded | OOB extent |
|---|---:|---:|---:|
| MD5      | 16 | 96 | 80 bytes |
| SHA-1    | 20 | 96 | 76 bytes |
| SHA-256  | 32 | 96 | 64 bytes |
| SHA-512  | 64 | 96 | 32 bytes |
| SHA3-256 | 32 | 96 | 64 bytes |

80 bytes of attacker-chosen content overflowing kmalloc-16 on the MD5 path. Pre-auth — the OOB write fires during the iSCSI Login state machine, before the digest comparison that would reject a wrong response. One TCP connection, one Login PDU sequence.

## What an attacker needs

Three things:

1. **Network reachability to a port-3260 listener** running the Linux LIO iSCSI target with CHAP enabled. Targets with CHAP disabled never enter this code path. CHAP-enabled targets enter it on every Login.
2. **The CHAP username** configured on the target. CHAP_N is verified before CHAP_R, so an attacker has to know (or guess) a valid username. Usernames in iSCSI configs are often short and operationally-meaningful (`iqn.2003-01.org.linux-iscsi.example:host`, `host01`, `backup`, etc.).
3. **A BASE64 string of the right length**. 128 characters — `"0b" + 126 BASE64 chars`, or just 128 BASE64 chars. The content of the bytes that fall past the buffer is attacker-chosen.

The CHAP password is not required: the OOB happens at the decode step, before the digest comparison. A wrong CHAP_R does not stop the bug — it stops only the login from succeeding.

That's the threat model I converged on, and the threat model ahossu's commit ended up shipping with. Pre-auth network heap write with attacker-controlled content into kmalloc-16.

## The patch (which I had ready, byte-identical to what shipped)

The fix is small. Mirror the HEX branch's "validate before decode" shape, by checking that the BASE64 input length cannot decode into more bytes than the destination can hold:

```diff
@@ fs/target/iscsi/iscsi_target_auth.c, chap_server_compute_hash()
     case BASE64:
+        /*
+         * chap_base64_decode() writes one byte per four input
+         * characters into client_digest, which is kzalloc'd at
+         * exactly chap->digest_size.  Pre-validate the encoded
+         * length so that the decoder cannot produce more bytes
+         * than the destination can hold; mirrors the strict
+         * length check on the HEX branch above.
+         */
+        if (strlen(chap_r) >
+            DIV_ROUND_UP(chap->digest_size * 4, 3)) {
+            pr_err("Malformed CHAP_R: BASE64 input too long\n");
+            goto out;
+        }
         if (chap_base64_decode(client_digest, chap_r, strlen(chap_r)) !=
             chap->digest_size) {
             pr_err("Malformed CHAP_R: invalid BASE64\n");
             goto out;
         }
         break;
```

`DIV_ROUND_UP(digest_size * 4, 3)` is the maximum BASE64 input length that decodes to `digest_size` bytes. For MD5 (`digest_size = 16`), that's 22 chars. For SHA-512 (64), it's 86. Anything longer than that for a given digest is by definition malformed.

When I checked the upstream fix after it landed, this is the same expression and the same control flow. The shape of the fix is dictated by the bug. I'd be surprised if any honest review converged on a meaningfully different patch.

## Reproducing it

The repro is small. The malicious iSCSI initiator only has to:

1. Open TCP to port 3260.
2. Send Login PDUs through CSG=0 SecurityNegotiation, with `AuthMethod=CHAP`, `CHAP_A=5` (MD5), a valid `CHAP_N` matching a configured username, and `CHAP_R` set to a 128-character BASE64 string of attacker-chosen content.
3. Drop the connection. Done.

I ran this under QEMU + KASAN against an LIO target on Linux 7.0, MD5 configured, anonymous CHAP allowed in demo mode. KASAN reported:

```text
BUG: KASAN: slab-out-of-bounds in chap_base64_decode+0x4b/0x120
Write of size 1 at addr ffff888107e1e930 by task kworker/1:2/72
Workqueue: events iscsi_target_do_login_rx
Call Trace:
 chap_base64_decode+0x4b/0x120
 chap_server_compute_hash.isra.0+0x8df/0xaa0
 chap_main_loop+0x148/0x6b0
 iscsi_target_do_login+0x7cb/0x930
 iscsi_target_do_login_rx+0x3df/0x5a0
Allocated by task 72:
 __kmalloc_noprof+0x1f1/0x620
 chap_server_compute_hash.isra.0+0x16f/0xaa0       /* kzalloc(digest_size) */
The buggy address belongs to the cache kmalloc-16 of size 16
```

The smoking gun is `kmalloc-16 of size 16` plus the `chap_base64_decode → chap_server_compute_hash → chap_main_loop → iscsi_target_do_login_rx` stack. The OOB fires from the iSCSI Login work queue, on the *unauthenticated* side — there is no digest comparison upstream of the trigger.

## The other caller I checked (the one that didn't matter)

`chap_base64_decode` has two call sites in `iscsi_target_auth.c`. The one above (line 343, processing CHAP_R) is the bug. There's a second one (line 475, processing CHAP_C during mutual authentication):

```c
case BASE64:
    initiatorchg_len = chap_base64_decode(initiatorchg_binhex,
                                          initiatorchg,
                                          strlen(initiatorchg));
    if (initiatorchg_len > 1024) { /* … goto out … */ }
    break;
```

Same shape — post-decode length check. Is it a bug?

No, because the math doesn't work. `initiatorchg_binhex = kzalloc(CHAP_CHALLENGE_STR_LEN, GFP_KERNEL)` allocates **4096 bytes**, and `extract_param("CHAP_C", CHAP_CHALLENGE_STR_LEN, …)` bounds the input string at 4095 chars. 4095 BASE64 chars decode to 3071 bytes — comfortably inside the 4096-byte buffer. No overflow.

It's safe *by accident*, not by design. Change `CHAP_CHALLENGE_STR_LEN` or shrink the buffer allocation and the bug reappears. The proper fix is to give `chap_base64_decode` a `dst_size` parameter so the helper itself can't be misused — neither ahossu's upstream patch nor mine did this. A defence-in-depth follow-on is a clean small contribution that I expect to ship as a separate post once it's sent and acknowledged.

## The meta-lesson

Here's what actually happened on my side:

| Date | Event |
|---|---|
| 2026-05-05 | I find the bug, take the KASAN trace |
| 2026-05-12 | Patch ready, marked `REVIEW-READY`, awaiting my own approval on a small author-identity re-roll |
| 2026-05-13 → 2026-05-25 | Patch sits. I move on to other work. |
| ~2026-05-15 → 2026-05-25 | ahossu finds the bug independently, writes essentially the same patch, sends to Martin K. Petersen via target-devel |
| ~2026-05-25 | Patch merged as `85db7391310b` in `7.1/scsi-fixes`. AUTOSEL'd for stable by Sasha Levin. |
| 2026-05-29 | ahossu publishes the blog walkthrough |
| 2026-06-01 | I see ahossu's blog in my X feed |
| 2026-06-02 | I write this post |

Two and a half weeks from "patch ready" to "credit gone". The actual review fix I was holding for was renaming a Co-developed-by + dual Signed-off-by to a single author identity. That's a 60-second `git commit --amend`.

The kernel upstream cycle does not reward almost-shipped patches. It rewards shipped ones. That cuts both ways — the credit goes to whoever lands the work, but so does the responsibility for getting the patch into reviewable shape under time pressure. ahossu reached that bar; I didn't.

The internal rule I'm adopting after this (it's been added to my own review process, but it's worth saying out loud): **any patch for a network-reachable kernel bug that is `REVIEW-READY` must either be sent within 7 days or explicitly held with a recorded reason and a re-evaluation date**. Two weeks is too long. The bug class is too easy to find in parallel.

If you've shipped kernel work yourself, you've probably absorbed a version of this already. If you haven't, it's the cheapest lesson in the queue. Don't sit on review-ready.

## What's in the companion repo

The reproducer I used — the iSCSI initiator that crafts the malformed Login sequence — is in the unified research repo. Sanitised, MIT-licensed, intended to be run only against targets you own.

→ **[github.com/TREXNEGRO/Research/tree/master/iscsi-chap-base64-oob](https://github.com/TREXNEGRO/Research/tree/master/iscsi-chap-base64-oob)**

Contents:

- `poc/iscsi_chap_overflow.py` — Python initiator that opens TCP/3260, walks the Login state machine, and sends a malformed `CHAP_R = base64(96 bytes)` on the MD5 path.
- `lab/setup_iscsi.sh` — LIO target configuration with CHAP enabled (for the reproducer environment).
- `lab/run.sh` — QEMU lifter (vulnerable and patched kernel).
- `logs/KASAN-vulnerable.log` — example KASAN trace (redacted build identifiers).
- `logs/patched-clean.log` — same harness, patched kernel, no KASAN report.

If you want to confirm the math from this post against your own LTS kernel: the bug is fixed in `7.1/scsi-fixes` and AUTOSEL'd to stable as of 2026-05-25. Any LTS branch that has not yet picked up the stable batch with `85db7391310b` is still vulnerable. Distro kernels behind that point will catch up in the next round.

## References

1. ahossu — "iSCSI CHAP base64 overflow" (canonical write-up). <https://ahossu.ro/blog/iscsi-chap-base64-overflow>
2. Upstream commit `85db7391310b` — "scsi: target: iscsi: bound BASE64 CHAP_R input to digest size".
3. RFC 7143, *Internet Small Computer System Interface (iSCSI) Protocol (Consolidated)* — CHAP authentication flow, §10.
4. Linux source — `drivers/target/iscsi/iscsi_target_auth.c::chap_server_compute_hash()` (pre-patch).
5. `include/linux/kernel.h::DIV_ROUND_UP` — the macro the fix uses.

---

*This was independently confirmed in a private QEMU + KASAN lab. The bug is fixed upstream; no production target should remain exposed once the stable batch propagates. The reproducer in the companion repo is provided for defenders and curious readers — do not run it against systems you don't own or have explicit, written permission to test.*
