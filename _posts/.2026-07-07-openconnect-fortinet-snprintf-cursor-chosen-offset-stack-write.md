---
title: "OpenConnect Fortinet: server-induced chosen-offset stack write via snprintf-return-value cursor arithmetic"
date: 2026-07-07 22:00:00 -0500
categories: [Research, Linux]
tags: [c, snprintf, stack-overflow, cursor-accumulator, fortinet, openconnect, vpn, fortify-source, saved-rip, static-analysis, methodology]
toc: true
lang: en
description: >-
  A ten-line C block in OpenConnect's Fortinet handler builds a
  version-info string with the classic snprintf-cursor idiom:
  advance a pointer by snprintf's return value across successive
  calls into a fixed stack buffer. Because snprintf returns the
  length it *would have* written — not the length it did — a
  single oversized field advances the cursor past the buffer end.
  The subsequent size argument computed as `e - p` is a negative
  ptrdiff_t that implicitly converts to a near-SIZE_MAX size_t.
  The next call happily writes a short, format-string-controlled
  payload at a caller-chosen offset — including the saved-RIP
  slot of the parent stack frame. Full walkthrough of the C
  language semantics that make the primitive, the stack-frame
  math that lands the write on saved RIP, the mitigation matrix
  (FORTIFY catches, SSP does not), and the pattern to grep for
  in any C codebase that builds strings incrementally.
---

> **TL;DR** — `parse_fortinet_xml_config()` in `fortinet.c:502-514` uses the classic C idiom `p += snprintf(p, e-p, fmt, ...)` in a loop over an XML `<fos>` element's attributes to build a version string into an 80-byte stack buffer. `snprintf(3)` returns the number of bytes it *would* have written given unbounded space, not the number it did write. On the first oversized field (e.g. `platform="A"×296`), the cursor `p` is advanced by the "would-have-written" value, overshooting `e`. The next call computes `e - p` as a negative `ptrdiff_t` (say `-216`), which implicitly converts to a `size_t` of `SIZE_MAX - 215`. `snprintf(p, huge, " v%s", major)` then writes a short attacker-controlled string at `p` — 216 bytes past the buffer, which stack-frame math places exactly on the caller's saved RIP slot. The write source is a Fortinet-compatible VPN gateway serving `/remote/fortisslvpn_xml`, so the corruption is server-induced across a TLS session, in a client that typically runs as root. On builds without `-D_FORTIFY_SOURCE=2` the RIP-slot content is under attacker control (`0x0000414141417620` = LE bytes of `" vAAAAA\0"`); on FORTIFY-hardened builds `__snprintf_chk` traps on the enormous `size` argument before the write completes, producing a client abort. `-fstack-protector-strong` alone does not detect this because the chosen-offset write skips the canary slot entirely. Fixed upstream in OpenConnect v9.20 by replacing the snprintf-cursor block with the project's heap-resizing `oc_text_buf` API.
{: .prompt-tip }

## Why this bug shape recurs in C

The C standard library exposes `snprintf(3)` with a return-value contract that trips practitioners at least once per career. From C99 §7.19.6.5:

> *The `snprintf` function is equivalent to `fprintf`, except that the output is written into an array (specified by argument `s`) rather than to a stream. If `n` is zero, nothing is written [...] Otherwise, output characters beyond the `n-1`st are discarded rather than being written to the array, and a null character is written at the end of the characters actually written into the array. [...] The `snprintf` function returns the number of characters that **would have been written** had `n` been sufficiently large, not counting the terminating null character, or a negative value if an encoding error occurred. Thus, the null-terminated output has been completely written if and only if the returned value is nonnegative and less than `n`.*

The consequence: the return value is *not bounded by* `n`. It can, and does, exceed `n` whenever the format expansion would need more space than the destination provides. A developer writing an incremental string builder as:

```c
char buf[SIZE], *p = buf, *e = buf + SIZE;
p += snprintf(p, e - p, fmt1, ...);
p += snprintf(p, e - p, fmt2, ...);  // <-- p may be past e here
p += snprintf(p, e - p, fmt3, ...);
```

is asserting, implicitly, that no single `snprintf` call in the chain will exceed the remaining window. The correct discipline is:

```c
int rc = snprintf(p, e - p, fmt, ...);
if (rc < 0 || rc >= e - p) { /* handle */ }
p += rc;
```

or, equivalently, the platform-specific `scnprintf` in Linux kernel-flavored codebases, which by construction returns the count actually written and caps to `n - 1`. When the cap is skipped, one oversized field is enough to advance `p` past `e`. From that point on, the "remaining window" expression `e - p` is a negative `ptrdiff_t`. Passed as the `size_t n` argument of the next `snprintf`, C's implicit integer conversion rules (§6.3.1.3 for signed-to-unsigned, and §6.3.1.8 for arithmetic conversions when signed and unsigned meet) yield a `size_t` value near `SIZE_MAX`. `snprintf` then believes it has essentially unbounded destination room, and writes the full format expansion to wherever `p` currently points — which is not inside the original buffer.

That is the class specimen for what this bug is.

## The bug: `parse_fortinet_xml_config()`

`fortinet.c:502-514`:

```c
} else if (xmlnode_is_named(xml_node, "fos")) {
    char platform[80], *p = platform, *e = platform + 80;
    if (!xmlnode_get_prop(xml_node, "platform", &s)) {
        p += snprintf(p, e-p, "%s", s);
        if (!xmlnode_get_prop(xml_node, "major",  &s)) p += snprintf(p, e-p, " v%s", s);
        if (!xmlnode_get_prop(xml_node, "minor",  &s)) p += snprintf(p, e-p, ".%s", s);
        if (!xmlnode_get_prop(xml_node, "patch",  &s)) p += snprintf(p, e-p, ".%s", s);
        if (!xmlnode_get_prop(xml_node, "build",  &s)) p += snprintf(p, e-p, " build %s", s);
        if (!xmlnode_get_prop(xml_node, "branch", &s)) p += snprintf(p, e-p, " branch %s", s);
        if (!xmlnode_get_prop(xml_node, "mr_num", &s))     snprintf(p, e-p, " mr_num %s", s);
        vpn_progress(vpninfo, PRG_INFO,
                     _("Reported platform is %s\n"), platform);
    }
```

The XML source is the response body from `GET /remote/fortisslvpn_xml`, delivered by the VPN gateway after the client has issued `POST /remote/logincheck` and stored the returned `SVPNCOOKIE`. The `<fos>` element's attributes are attacker-controlled fields on the server side. Every subsequent `snprintf(p, e - p, ...)` in the block trusts the invariant that `p` stays inside `[platform, e)`. That invariant is not defended.

## Trigger arithmetic

Concretize the values. The stack buffer is 80 bytes: `char platform[80]`. Take an XML payload of the form:

```xml
<fos platform="AAAA…AAAA"    <!-- 296 chars of 'A' -->
     major="AAAAA"           <!-- 5 chars of 'A' -->
/>
```

Call `(1)`, the `snprintf` for `platform`:

- Format: `"%s"` with `s` = 296-byte string.
- Destination window: `e - p = 80`.
- Bytes actually written into `platform[]`: 79 chars + NUL terminator.
- Return value: `296`.
- `p += 296` → `p = platform + 296`. `p` is now 216 bytes past `e`.

Call `(2)`, the `snprintf` for `major`:

- Second argument: `e - p = 80 - 296 = -216` as `ptrdiff_t`.
- Implicit conversion to `size_t n`: `-216` in a 64-bit two's-complement environment becomes `0xFFFFFFFFFFFFFF28`, which is `SIZE_MAX - 215`.
- Format: `" v%s"` with `s` = 5-byte `"AAAAA"`. Total emit length: 8 bytes including NUL.
- Destination pointer: `platform + 296`. No relation to the original buffer.
- The write proceeds because `snprintf` sees a huge `n` and a short format. Eight bytes land at `platform + 296`.

The question is what `platform + 296` is, in the caller's stack frame.

## Stack-frame math: landing the write on saved RIP

Compile `parse_fortinet_xml_config` at `-O1 -g -fno-omit-frame-pointer` and disassemble the prologue. The relevant instruction sequence is:

```asm
push   %rbp
mov    %rsp,%rbp
sub    $0x???,%rsp
...
lea    -0x120(%rbp),%r14      ; %r14 = &platform[0]  = rbp - 288
...
```

`platform[]` sits at `rbp - 288`. The 80-byte buffer therefore occupies `[rbp - 288, rbp - 208)`. The saved RIP of the caller lives at `rbp + 8` (the standard SysV-AMD64 frame layout: caller pushes return address, callee pushes old rbp, so saved RBP is at `rbp` and saved RIP is at `rbp + 8`).

Distance from `&platform[0]` to the saved-RIP slot: `288 + 8 = 296` bytes.

The first `snprintf` needs to advance `p` by exactly 296 to land the *next* write on saved RIP. That is: `platform` attribute must decode to 296 or more bytes of string body. The construction is server-side, so the attacker picks 296 exactly.

Call `(2)`'s destination pointer `p = platform + 296` is now `&saved_RIP`. The eight bytes written by `" v%s"` with `major="AAAAA"` are, byte-wise, `20 76 41 41 41 41 41 00` — space, 'v', five 'A's, NUL. Little-endian read as a `uint64_t`, that is `0x00'41414141'417620`. That is the value the CPU will pop into RIP when the function returns.

## Runtime evidence

Compile OpenConnect with `-O1 -g -fno-stack-protector -fno-omit-frame-pointer -U_FORTIFY_SOURCE`, ship a fake Fortinet gateway (Python HTTP server implementing `GET /` → `POST /remote/logincheck` → `GET /remote/fortisslvpn_xml`), point `openconnect --protocol=fortinet` at the fake gateway. Crash trace on client:

```text
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x0000414141417620 in ?? ()
rip            0x414141417620      0x414141417620
rbp            0x7ffedacb71a0
r12            0x1e9               489
rbx            0x55aba7bf9a70
```

The instruction pointer is the byte string `" vAAAAA"` reinterpreted as an address. It is a canonical-but-unmapped address (bits 47-63 are the sign extension of bit 47 = zero, so the OS accepts it as a valid userland VA, but no page is mapped there), so the page-fault handler fires on the instruction-fetch attempt and the process dies at exactly the moment control transfer would have completed.

Reproducibility: six trigger runs across two flow variants (with `--cookie` shortcut, with full auth dance). Six coredumps, six identical RIP values. 100% deterministic.

On a hardened build — the default binary shipped by every mainstream distribution — CFLAGS include `-D_FORTIFY_SOURCE=2` and glibc redirects `snprintf` to `__snprintf_chk`. `__snprintf_chk` (glibc source: `debug/snprintf_chk.c`) has the signature:

```c
int __snprintf_chk(char *s, size_t maxlen, int flag, size_t slen, const char *fmt, ...);
```

with `slen` being the compiler-inferred size of the destination object at the call site (via `__builtin_object_size`). The runtime guard is:

```c
if (__glibc_unlikely(maxlen > slen))
    __chk_fail();
```

On the vulnerable call `(2)`, `s = platform + 296`, `maxlen = 0xFFFFFFFFFFFFFF28`, `slen` = compiler-inferred bound at the call site (which sees the write as targeting somewhere related to `platform[]` and derives an 80-byte bound). `maxlen >> slen`, `__chk_fail` fires, and glibc raises SIGABRT via the standard FORTIFY diagnostic:

```text
*** buffer overflow detected ***: terminated
```

The corruption never completes. The result on hardened builds is a client-side denial of service — the openconnect process aborts on connecting to a malicious gateway — but no code-execution primitive.

`-fstack-protector-strong` alone, without FORTIFY, does not catch this bug. SSP places a canary between local variables and the saved-RBP/RIP slot at function entry, and checks its value before `ret`. The check works when a write overflows *linearly* from a local buffer into the canary and beyond. Here the write does not overflow linearly; it skips directly to `platform + 296`, which is past the canary and lands on saved RIP. The canary is untouched. On a `-fstack-protector-strong -U_FORTIFY_SOURCE` build the RIP is corrupted, the epilogue's `mov -0x8(%rbp),%rcx; xor %fs:0x28,%rcx` canary check succeeds, and the process crashes exactly the same way it does on the no-SSP build. Chosen-offset writes are the specific SSP failure mode.

## Threat model

The write source is any Fortinet-compatible SSL VPN gateway. To reach the vulnerable code path a server needs to respond correctly to the three phases of the client-side auth dance:

1. `GET /` → 200 OK with an HTML page containing a Fortinet marker.
2. `POST /remote/logincheck` → 200 OK with `Set-Cookie: SVPNCOOKIE=<value>`.
3. `GET /remote/fortisslvpn_xml` → 200 OK with an XML body whose root element contains `<fos platform="…" major="…" .../>`.

No credentials are validated by the server; the client submits whatever the user typed, and the server accepts. From that point on, the XML at phase 3 is the entire attack surface reached by the code above. The reproducer's fake gateway is under 200 lines of Python. The TLS session between client and gateway does not defend against this because the corruption *originates* at the gateway; the TLS layer only prevents an intermediate on-path attacker without the gateway's private key from modifying the payload.

Two attacker models therefore produce the primitive:

- **Malicious operator of a Fortinet-compatible gateway.** Any host claiming to run FortiSSL VPN can trigger the bug on any client that connects. No user credentials are required at any step, though the user has to be induced to run `openconnect --protocol=fortinet <malicious-host>`.

- **Adversary in the middle who has broken the TLS assumption**, either via a compromised CA in the client's trust store, a leaked gateway certificate, a downgraded/misconfigured client (`--servercert=<pin>` mismatch), or a captive-portal box that terminates and re-encrypts. Any of these lets the attacker rewrite the XML body at phase 3.

Openconnect on Linux typically runs as root (it needs raw sockets, `tun` creation, `setuid` for privilege drops), so the corrupted process is a root-context process.

## Mitigation matrix

|                          | SSP off, FORTIFY off | SSP strong, FORTIFY off | SSP strong, FORTIFY=2 |
|---|---|---|---|
| Write completes          | Yes                  | Yes                     | No                     |
| Saved RIP corrupted      | Yes                  | Yes                     | No                     |
| Process reaches epilogue | No (SIGSEGV in ret)  | No (SIGSEGV in ret)     | Aborts before write    |
| Attacker-controlled RIP  | Yes                  | Yes                     | No                     |
| Observable failure       | SIGSEGV @ chosen VA  | SIGSEGV @ chosen VA     | SIGABRT via `__chk_fail` |

The upshot: every default-hardened distro binary reaches only the DoS state; the RIP-control primitive requires the client to be built with FORTIFY disabled, which is a niche configuration but a real one (custom builds for constrained targets, certain distro-specific packages that turn FORTIFY off for optimization reasons, packages built by third parties that inherit `CFLAGS` from unrelated environments).

## Fix strategy

The failure mode is not "80 was too small." Any fixed-size buffer would fail the same way against a big-enough input. The failure mode is "the return value of `snprintf` is not the bytes written." Three orthogonal remedies exist.

**(a) Enforce the discipline explicitly at every call site.** Replace each `p += snprintf(p, e - p, ...)` with:

```c
int rc = snprintf(p, e - p, fmt, ...);
if (rc < 0 || rc >= e - p)
    /* handle: truncate, error out, or realloc */;
p += rc;
```

Verbose but semantically local. Every `snprintf` in the codebase needs the same audit.

**(b) Switch to `scnprintf`-style semantics.** Linux-kernel and Android codebases use `scnprintf`, which caps the return value at `n - 1`. Userspace projects can wrap `snprintf` themselves. The idiom `p += scnprintf(p, e - p, ...)` is safe because `p` cannot advance past `e`.

**(c) Abandon the fixed-buffer + cursor model.** Use a heap-resizing text builder that owns its capacity and grows on demand. OpenConnect ships exactly this — `struct oc_text_buf` with `buf_alloc`, `buf_append`, `buf_error`, `buf_free` — and uses it consistently in `cstp.c`, `gpst.c`, and other protocol handlers. The Fortinet handler is the outlier.

The upstream fix in v9.20 chose (c): replace `char platform[80], *p, *e` with `struct oc_text_buf *platform = buf_alloc()`, and every `p += snprintf(p, e - p, fmt, ...)` with `buf_append(platform, fmt, ...)`. The auto-resizing allocator makes overflow structurally impossible, the API is already documented and used across the tree, and the fix is a mechanical translation preserving every emitted attribute.

## The same class in the rest of the tree

A quick audit of the same codebase surfaced additional instances of the anti-pattern with varying degrees of exploitability:

- Windows `socketpair` reimplementation in `compat.c`: same `p += snprintf(...)` pattern into a `sockaddr_un.sun_path` buffer, with input from `GetWindowsDirectory()`. Not remotely reachable; the input is host-controlled. Still a footgun awaiting an attacker who can influence `GetWindowsDirectory`.
- `handle_external_browser` in `hpke.c`: builds an HTTP `302` response with a `returl` from a callback. Currently benign because the format specifier's static portion dominates the length, but the cursor discipline is the same — a maintenance change to the format string would produce the primitive.
- `setenv_cstp_opts` in `script.c`: builds an environment-variable value by pre-computing a length, `malloc`-ing, and filling with `snprintf`-cursor. Not exploitable because the length pass sizes correctly, but the second pass is one buffer-sizing error away from the same class.

The upstream v9.20 fix migrated three of these to `oc_text_buf` and hardened `dumb_socketpair` with explicit rc-vs-window checks. Only `openconnect__vasprintf` in `compat.c` was left as-is because its retval logic already handles the case correctly.

## Static-analysis-visible shape

The primitive is a two-token sequence in C source: the composite assignment `+=` immediately followed by an `snprintf(` call, followed at any distance in control flow by another `snprintf` call using the same cursor. Grep starting point:

```bash
rg -nP '\+=\s*snprintf\s*\('
```

Each hit is a candidate. False positives are common — an `snprintf`-cursor into a heap buffer whose size is checked before allocation is not exploitable in the same way — but every match warrants a look. The classification filter is a two-question sequence:

1. Is the destination a fixed-size stack buffer, or a heap buffer whose length was computed as an upper bound on the total input?
2. Does the enclosing loop or block contain a subsequent `snprintf` using the same cursor without an intervening range check?

If (1) is "fixed-size stack" and (2) is "yes," the bug class applies. Semgrep-style pattern:

```yaml
pattern-either:
  - pattern: |
      char $BUF[$N];
      $P += snprintf($P, ..., $FMT1, ...);
      $P += snprintf($P, ..., $FMT2, ...);
  - pattern: |
      $P += snprintf($P, $E - $P, ...);
      ...
      $P += snprintf($P, $E - $P, ...);
```

Callable against any C codebase with `#include <stdio.h>`. Historical CVEs in the same class include multiple GNU utilities (coreutils, tar), a family of Linux kernel `snprintf` misuses in string-building helpers (fixed by the introduction of `scnprintf`), several `sprintf`-cursor variants in printf-like macros in older `libc` implementations, and network protocol handlers in a broad set of embedded HTTP servers. The pattern is not rare and the primitive is not novel — what is novel is running the grep on codebases that ship as root-context clients against untrusted servers.

## Takeaways

**On `snprintf(3)` return semantics.** The C standard's contract is not "returns what it wrote." It is "returns what it would have written if the caller had provided infinite space." Every consumer of the return value in a bounded-buffer context is asserting the caller-provided space was sufficient. That assertion has to be checked, or the value has to be clamped, or the buffer has to be resizable.

**On `ptrdiff_t → size_t` conversion.** Any expression of the form `end - start` where `start` might legitimately land past `end` is a source of near-`SIZE_MAX` values. If the result flows into an argument typed as `size_t`, the C implicit conversion rules will not warn. Compilers can be persuaded to warn (`-Wsign-conversion`, sometimes `-Wconversion`) but the warning is off by default in every mainstream build configuration. Codebases that rely on cursor arithmetic into bounded destinations need `-Wsign-conversion` on and a clean tree, or they need to eliminate the pattern entirely.

**On FORTIFY vs SSP for chosen-offset writes.** `-fstack-protector-strong` is defense against overflows that traverse the canary slot on their way to saved RIP. A chosen-offset write skips the canary. The defense that matters against this bug is `-D_FORTIFY_SOURCE=2` and glibc's `__snprintf_chk`, which enforces the compiler's `__builtin_object_size` estimate on every `snprintf` call site. Shipping `-fstack-protector-strong` without `-D_FORTIFY_SOURCE=2` is a common configuration in third-party builds and it leaves this class of bug fully exploitable on the RIP-control side.

**On heap-backed text builders.** The upstream fix substitutes a `char[80] + cursor + snprintf` block with a heap-resizing text buffer. This is not a "workaround" — it is the correct data structure for the operation being performed. Building a variable-length string incrementally into a fixed-size stack buffer is committing to a length bound at compile time that the runtime cannot enforce cheaply. Every C codebase that ships a text-building API alongside the raw `snprintf` idiom should be using its own API on every call site, and reserving raw `snprintf` for the strict single-shot-into-known-size case.

**On the audit envelope.** A single `rg` grep finds every latent instance of this pattern in a codebase in under a second. Reviewing each hit costs minutes. The cost-benefit for security-relevant C code is dominated: run the grep, review the hits, migrate the ones that pass both classification questions. The rest of the codebase — protocol handlers reading server-side input over TLS into fixed stack buffers — is exactly where the primitive lives, and every one of them is a chosen-offset write waiting to be discovered on the input distribution the code was not tested against.

## References

1. ISO/IEC 9899:1999 §7.19.6.5 — `snprintf` return-value contract.
2. ISO/IEC 9899:1999 §6.3.1.3, §6.3.1.8 — implicit signed-to-unsigned conversion semantics.
3. glibc `debug/snprintf_chk.c` — `__snprintf_chk` runtime check invoked under `-D_FORTIFY_SOURCE=2`.
4. GCC — `__builtin_object_size` compile-time estimation, used by FORTIFY to size destinations.
5. SysV AMD64 ABI — stack frame layout, saved RIP at `rbp + 8` under `-fno-omit-frame-pointer`.
6. OpenConnect release notes — v9.20, "Fix unsafe `snprintf()` cursor arithmetic in string construction helpers."
7. Linux kernel `scnprintf` — capped-return variant of `snprintf` that eliminates this class by construction.
8. CWE-121 — Stack-based Buffer Overflow.
9. CWE-193 — Off-by-one Error (adjacent pattern where the cursor discipline is present but off by one).
10. CWE-190 — Integer Overflow or Wraparound (the `ptrdiff_t → size_t` conversion that produces the near-`SIZE_MAX` size).
