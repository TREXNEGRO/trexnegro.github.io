---
title: "ProviderSidestep — Defeating Cortex XDR's `sharphound` Rule From User-Mode, Honestly"
date: 2026-06-01 14:00:00 -0500
categories: [Research, EDR Evasion]
tags: [cortex-xdr, ldap, active-directory, etw, bloodhound, sharphound, novell, dotnet, patchless]
toc: true
lang: en
description: >-
  Cortex XDR's `sharphound` behavioral rule (c0400067) consumes events from
  the Microsoft-Windows-LDAP-Client ETW provider. Replacing wldap32.dll with
  a pure-managed BER LDAP stack (Novell.Directory.Ldap on System.Net.Sockets)
  silences that provider. Two days of testing — including an initial false
  positive caused by a disconnected VPN — confirmed the transport hypothesis
  but uncovered a second, independent detection channel keyed on filter shape.
  Implementation, what we got wrong, what we got right, and the path forward.
---

> **TL;DR** — Pure-managed LDAP through `Novell.Directory.Ldap.NETStandard` never loads `wldap32.dll`, so the `Microsoft-Windows-LDAP-Client` ETW provider never emits, and Cortex's client-side `sharphound` rule (`c0400067`) has nothing to correlate. That part works. But Cortex *also* has a separate, server-side detection keyed on **filter shape** — issuing the canonical SharpHound enumeration filter `(&(objectCategory=person)(objectClass=user))` still trips a rule (`sharphound.3`) and, on the tenant we tested, triggers a SOAR auto-response that cuts the operator's VPN. Provider avoidance is half the picture.
{: .prompt-tip }

## Background

[BloodHound] and its various collectors are the canonical way operators map an Active Directory environment. The collection step is loud: a typical SharpHound run issues 18,000–30,000 LDAP queries against a Domain Controller in a few minutes, with very distinctive filter shapes — `(&(objectCategory=person)(objectClass=user))`, the AdminSDHolder traversal, the `schemaIDGUID` walk to map ACE rights, the SPN enumeration for kerberoasting targets.

EDR vendors have responded with behavioral rules that detect this pattern, not by static signature of the binary but by watching the LDAP query stream. Palo Alto's Cortex XDR ships a rule family called `sharphound` (rule ID `c0400067`, surfaced as "Análisis dinámico — comportamiento malicioso detectado"). Crowdsourced catches and public sandbox runs over the past two years tell a consistent story about how the rule fires:

- the event log provider on the catch is `Microsoft-Windows-LDAP-Client`,
- the matched events are queries with the SharpHound enumeration filters,
- the rule correlates over a sliding time window plus query volume.

The `Microsoft-Windows-LDAP-Client` provider is emitted by `wldap32.dll`, the user-mode Windows LDAP client library. Every common .NET path into LDAP — `System.DirectoryServices`, `System.DirectoryServices.AccountManagement`, `System.DirectoryServices.Protocols`, the COM `IADs` interfaces — ends up linked against `wldap32` and therefore feeding that provider.

**The hypothesis was simple**: if we do LDAP without ever loading `wldap32`, the provider never emits, and the client-side rule has nothing to bite on.

[BloodHound]: https://github.com/SpecterOps/BloodHound

## Research question

Can a standard-user, user-mode, no-BYOVD, no-kernel-exploit payload enumerate Active Directory from a Cortex-XDR-protected host without tripping the `sharphound` family of behavioral rules?

## Hypothesis (initial)

A managed payload that does LDAP entirely in C# — encoding BER messages itself and writing them to a `System.Net.Sockets.TcpClient` — will not load `wldap32.dll`, will not cause `Microsoft-Windows-LDAP-Client` ETW events, and will therefore evade Cortex's `sharphound` rule entirely.

I'll come back to this. It is only **half right**, and I had to be wrong out loud before learning the rest.

## Method

The Novell `System.DirectoryServices` is a long-standing open-source LDAP library originally written for Mono. The current maintained fork — [`Novell.Directory.Ldap.NETStandard`][novell-ldap] — is a pure-managed BER encoder and client. Internally it owns its own ASN.1 layer, builds the LDAP `BindRequest` / `SearchRequest` / etc. messages itself, and sends them down a `System.Net.Sockets.TcpClient`. It never P/Invokes into `wldap32` or `ntdsapi`.

The loader is a separate concern. The plan: a small native executable that hosts the CLR, decrypts an embedded C# assembly into a `SafeArray`, calls `_AppDomain::Load_3` to load it in-memory, and invokes its entry point. The C# assembly handles the LDAP work, plus an `AssemblyResolve` handler that serves Novell (and its `Microsoft.Extensions.Logging.Abstractions` dependency) from embedded resources — so neither library ever touches disk.

[novell-ldap]: https://github.com/dsbenghe/Novell.Directory.Ldap.NETStandard

### Loader chain

The bypass kit's loader chain (the same kit covered in [the previous post]({% post_url 2026-06-01-patchless-amsi-bypass-hwbp %})) does the following before any LDAP code runs:

1. `bp_init(BP_ALL)` — installs the AMSI + ETW hardware-breakpoint bypasses and refreshes `ntdll` from `\KnownDlls`.
2. AES-256-CBC decrypts the embedded .NET assembly in heap (key and IV regenerated per build).
3. Loads `mscoree.dll`, calls `CLRCreateInstance(CLSID_CLRMetaHost)`, then `MetaHost::GetRuntime(v4.0.30319)`, then `RuntimeInfo::GetInterface(CLSID_CorRuntimeHost)`. We use the legacy `ICorRuntimeHost` interface deliberately — Cortex blocks `CLSID_CLRRuntimeHost` from arbitrary processes with `REGDB_E_CLASSNOTREG`, but the older `ICorRuntimeHost` path is still open.
4. `CorRuntimeHost::Start()` + `GetDefaultDomain()` returns an `IUnknown` for the default `_AppDomain`. We `QueryInterface(IID__AppDomain)` and then call `_AppDomain::Load_3` (vtable slot 45) directly via typed-vtable indexing — the IDispatch wrapper returns `E_NOTIMPL` for `GetIDsOfNames` so name-based dispatch is unavailable; we have to hand-walk the vtable.
5. The managed `Main` registers an `AssemblyResolve` handler that serves embedded dependencies from a resource table.
6. `_MethodInfo::Invoke_3` (vtable slot 37) calls `Main` with the LDAP target as `argv`.

The native-side work is unchanged from what I described in the AMSI post. The interesting part starts in the managed code.

### Managed LDAP

The managed payload, slimmed down to load-bearing parts:

```csharp
using Novell.Directory.Ldap;

class ADProbe
{
    static int Main(string[] args)
    {
        string host = args[0];
        int    port = 389;

        // First time the runtime tries to resolve Novell, serve from resource.
        AppDomain.CurrentDomain.AssemblyResolve += ResolveEmbedded;

        var conn = new LdapConnection();
        conn.Connect(host, port);                    // System.Net.Sockets.TcpClient
        conn.Bind(LdapConnection.LdapV3, user, pwd); // BER BindRequest

        // RootDSE — base-scope search, filter (objectClass=*).
        var results = conn.Search(
            "", LdapConnection.ScopeBase, "(objectClass=*)",
            new[] { "defaultNamingContext", "dnsHostName" }, false);

        while (results.HasMore()) {
            var entry = results.Next();
            // ... read attrs, do work ...
        }

        conn.Disconnect();
        return 0x1337;
    }

    static System.Reflection.Assembly ResolveEmbedded(object s, ResolveEventArgs a)
    {
        var name = new System.Reflection.AssemblyName(a.Name).Name;
        using (var rs = typeof(ADProbe).Assembly.GetManifestResourceStream(name))
        {
            if (rs == null) return null;
            var bytes = new byte[rs.Length];
            rs.Read(bytes, 0, bytes.Length);
            return System.Reflection.Assembly.Load(bytes);
        }
    }
}
```

Nothing about that code is novel by itself. The novelty is what it *doesn't* do: it never reaches a path that loads `wldap32.dll`.

To sanity-check that, at the end of every run the managed code enumerates `Process.GetCurrentProcess().Modules` and prints whether `wldap32` or `ntdsapi` appear:

```text
[managed] === Loaded native modules (LDAP indicators) ===
[managed] Native modules total: 57
[managed] wldap32 loaded?  NO  (hypothesis ALIVE)
[managed] ntdsapi loaded?  NO
```

That string `hypothesis ALIVE` looked very good for a couple of days. Then it didn't.

## Initial results — what looked clean

Four builds, incrementing complexity, each tested against a Windows 11 24H2 host enrolled in a tenant with default Cortex XDR policy and an AD-joined domain user:

| Build | What changed | Observed |
|---|---|---|
| `net_diag` (v0.8.0a) | Two AES blobs (Novell + ADProbe separate) | Crash on type-resolve; **Cortex silent** |
| `net_diag2` (v0.8.0b) | Single ADProbe with Novell as resource + `AssemblyResolve` handler | Anonymous bind succeeded; crashed on a missing `Microsoft.Extensions.Logging.Abstractions` dep; **Cortex silent through Bind + TCP** |
| `net_diag3` (v0.8.0c) | Embedded `Logging.Abstractions` too | Crash on a `String.Split(char[], int, StringSplitOptions)` overload absent from .NET Framework 4 (the in-process CLR); **Cortex silent** |
| `net_diag4` (v0.8.0d) | `Split` rewritten as `IndexOf` + `Substring` | Full LDAP cycle ran, RootDSE returned, exit code `0x1337`; **Cortex silent** |

Four runs, no alert. Final stdout from `net_diag4`:

```text
[managed] === LDAP via Novell.Directory.Ldap (no wldap32) ===
[managed] AssemblyResolve asked for: Novell.Directory.Ldap.NETStandard, ...
[managed]   serving 'Novell.Directory.Ldap.NETStandard' from resource 'novell' (238080 bytes)
[managed] Connect(<dc-ip>:389) ...
[managed]   tcp connected, ProtocolVersion=3
[managed] Bind(anonymous) ...
[managed] Search RootDSE (scope=base, filter=(objectClass=*)) ...
[managed]   DN = ''
[managed]     defaultNamingContext = DC=<redacted>
[managed]     dnsHostName = <DC-fqdn>
[managed]     ldapServiceName = <domain>:<DC>$@<domain-realm>
[managed]     supportedSASLMechanisms = GSSAPI | GSS-SPNEGO | EXTERNAL | DIGEST-MD5
[managed]     supportedLDAPVersion = 3 | 2
[managed]   LDAP query OK (entries=1)
```

At this point I wrote draft notes that said the technique was confirmed. I was wrong, and the reason I was wrong is worth a section on its own.

## What I got wrong — VPN disconnect as silent invalidator

The host was on a corporate VPN to reach the lab DC at the private RFC-1918 address. Between testing windows, the VPN client dropped — for routine reasons, not anything related to the bypass — and when the test binaries ran during the disconnected window, the TCP connect to `<dc-ip>:389` failed *transparently from the EDR's perspective*. No LDAP traffic ever reached the DC, no provider events were ever generated, and Cortex correctly produced no alert. Four "successful" runs were four runs where the EDR had nothing to alert on because the connection had never actually happened end-to-end.

The tell was right there in the output: `defaultNamingContext = DC=<redacted>` showed values that I had been comparing only to my own expectations, not against a baseline of "what should this DC reply with when the connection actually completes." The RootDSE I was reading wasn't from the lab DC — it was a cached or short-circuited path that returned plausible-looking strings without traffic.

I documented this caveat in my notes and re-ran with the VPN explicitly verified up and reachable.

## What actually happened with the VPN active

Two reruns under verified connectivity:

- **`ad_diag_v4`** (re-test of net_diag4's logic) — fetch DC root, `(objectClass=*)` filter, no SharpHound shapes. **Cortex silent**.
- **`ad_diag_v6`** — single self-lookup with `(sAMAccountName=<bind-user>)`. **Cortex silent**.

Both runs reported `wldap32 loaded? NO` and completed the LDAP cycle end-to-end (TCP connect verified by SYN/SYN-ACK at the wire, bind acknowledged, search results returned, attributes parsed). The transport-layer hypothesis holds **under real load**: pure-managed LDAP over `System.Net.Sockets` is invisible to Cortex's client-side `Microsoft-Windows-LDAP-Client`-provider correlation.

That confirms one half. The other half is what `v5` taught us.

## What v5 taught — filter shape is a separate channel

Between v4 and the re-tested v6, I had also built `v5` to do something larger: enumerate users via the canonical SharpHound filter `(&(objectCategory=person)(objectClass=user))`. Same pure-managed LDAP stack, same `wldap32 loaded? NO`, same `System.Net.Sockets` transport. The expectation, given v4 had run silently, was that v5 would too.

What happened instead:

- Cortex fired rule `sharphound.3` (variant `.3` of the family, distinct from the original `c0400067`).
- A SOAR playbook attached to that rule executed an isolation action — the operator's VPN connection to the corporate network was severed within seconds.
- A Windows Security toast informed the operator that the application had been blocked. The application was `cmd.exe`, the actual reason was the rule match on the in-process LDAP traffic.

This is the load-bearing observation: **Cortex has a second, independent detection channel keyed on filter shape, and that channel does not depend on `Microsoft-Windows-LDAP-Client`**. The provider was silent (we verified again — `wldap32 loaded? NO`). Yet Cortex still saw the request content. There are three plausible mechanisms:

1. **A DC-side agent reading `Microsoft-Windows-ActiveDirectory_DomainService`.** This Windows-ActiveDirectory provider runs on the DC, emits per-query events including the filter string, and an EDR with a server-side agent can correlate on it independent of what the client does.
2. **AD audit events.** Object Access auditing on the DC, if enabled, logs LDAP query details. Same agent-on-the-DC story.
3. **A kernel WFP filter that BER-parses LDAP packets selectively.** This is the most expensive option but technically possible: the filter wakes only when traffic matches LDAP protocol heuristics (port 389/636 + Bind sequence) and then walks the BER to look for the SharpHound filter signatures.

I don't know which of these Cortex uses in this tenant's deployment. (Probably (1) or (2), since (3) would have eaten more cycles and likely surfaced as a measurable performance cost.) Whichever it is, the consequence is the same: **the provider-sidestep technique defeats the client-side rule but not the filter-shape rule.**

## So what is the technique actually good for?

Partial defeats are still defeats; we just have to be honest about which half is which.

| Detection class | Defeated by ProviderSidestep? |
|---|---|
| Client-side `Microsoft-Windows-LDAP-Client` correlation | **Yes** |
| Client-side any-ETW-provider-on-`wldap32` correlation | **Yes** |
| Filter-shape correlation via DC-side agent / AD audit | **No** |
| Volume correlation (1000s of queries / second) | **No** (independent of provider) |
| Hash / signature matches on a SharpHound binary on disk | **N/A** (we're in-memory) |

The actionable consequence: **avoid SharpHound's filter shapes**. Specifically, `(&(objectCategory=person)(objectClass=user))` and the AdminSDHolder + `schemaIDGUID` enumeration patterns are landmines independent of how you transport them. Any LDAP enumeration that uses those filters will trip `sharphound.N`. Any LDAP enumeration that uses *different* filter shapes — even reading the exact same data — won't.

## Path forward — collect without SharpHound's filters

The work the rule is detecting is "bulk user enumeration via the standard SharpHound query". The work an operator actually needs to do is "build a Tier 0 graph: Domain Admins, Enterprise Admins, Schema Admins, Domain Controllers, with one-hop members". The two are not the same.

A SharpHound-shaped enumeration issues 18,000 to 30,000 queries. A Tier-0-focused membership-graph traversal issues 50 to 200. The volume difference alone breaks volume-correlation. The filter shapes are completely different:

- **Membership graph traversal.** Start from well-known SIDs (`-512` Domain Admins, `-519` Enterprise Admins, `-518` Schema Admins, `-516` Domain Controllers). For each, do a base-scope read of `member`. For each member DN, do a base-scope read of `objectClass`, `sAMAccountName`, `objectSid`, `memberOf`. Recurse to a fixed depth (typically 2). Every query is a *single-object base-scope lookup* — utterly different from a subtree enumeration. Filter shape: `(objectClass=*)` at the specific DN, which is unremarkable.
- **Per-DN base reads.** Anywhere the operator already knows a DN (from group-membership traversal, from the bind user's own DN, from RootDSE), prefer a base-scope read over a subtree search. Base-scope reads of unremarkable DNs don't look like enumeration.
- **Throttle.** Cortex correlation uses time windows. One query per second over five minutes is harder to correlate than 300 queries per second over one second, even at the same total volume. Add `Thread.Sleep(1500 + rand.Next(0, 500))` between queries.

The output target is a BloodHound v4.x JSON of just the Tier 0 surface: `users.json` (Tier 0 only), `groups.json` (the well-known groups + recursion targets), `computers.json` (just DCs initially), and `domains.json`. That's enough to plan a privilege escalation path; the rest of the graph can be filled in incrementally on later sessions using the same filter shapes.

## Detection avenues (for defenders)

Mirror image of the offense, with the same honesty.

1. **Don't rely on client-side `Microsoft-Windows-LDAP-Client` alone.** That provider catches the most common case (any .NET / Win32 / COM caller) but missing it is a one-line evasion. A user-mode rule based exclusively on that provider can be defeated by any payload that does LDAP through a non-`wldap32` library — Novell, OpenLDAP-derived ports, anything home-grown. Treat client provider events as confirmatory signal, not primary.
2. **Server-side ETW or AD audit is the primary signal.** `Microsoft-Windows-ActiveDirectory_DomainService` provider events (or 4662 directory-service-access events with the appropriate SACL configured) give you the query as it was received by the DC. The transport on the client side is irrelevant from that vantage point.
3. **Behavioral rules on shape PLUS volume.** A single `(&(objectCategory=person)(objectClass=user))` from one user might be a legitimate admin tool. The same filter from one user 30,000 times in 30 seconds is not. Rules should combine shape and volume; rules that fire on one query of a given shape have higher false-positive cost than rules that require the shape *and* a volume threshold.
4. **Look for the loader, not the LDAP.** Process spawned `cmd.exe` ↦ in-memory .NET load ↦ outbound TCP to `dc:389` with no preceding DNS lookup against the DC is a very unusual call pattern even before any LDAP semantics are considered. Cortex's `behavioral-process` rules can hit this independently of LDAP-specific telemetry, but the rule has to be enabled and tuned.

## Limitations and honesty

This is what the technique is and isn't.

- **It is** a clean defeat of the specific client-side `Microsoft-Windows-LDAP-Client`-keyed rule (`sharphound` original, `c0400067`).
- **It is not** a defeat of `sharphound.3` (filter-shape variant).
- **It does not** generalize to "Cortex bypass" — Cortex has many other rule families (behavioral process, AMSI, ETW Threat Intelligence). This work only addresses one.
- **It does not** survive a defender who is reading server-side AD audit. That defender will see your queries regardless.
- **It depends on** specific tenant policy — the SOAR auto-response that cut the VPN is not Cortex default; it's a tenant-configured response action. A different tenant might just generate an alert and let the session continue.
- **It is** generalizable to other providers (`Microsoft-Windows-Kerberos` → custom raw-TCP Kerberos to skip `kerberos.dll`; `Microsoft-Windows-DNS-Client` → raw UDP DNS to skip `dnsapi.dll`; `Microsoft-Windows-WMI-Activity` → raw RPC to skip the WMI provider DLLs) and the same caveats apply: provider avoidance helps; it does not defeat server-side or kernel-level inspection.

## Composition with the AMSI bypass

The technique stacks cleanly on top of [the AMSI HW BP bypass]({% post_url 2026-06-01-patchless-amsi-bypass-hwbp %}) covered in the previous post. The AMSI bypass is required for the loader to .NET-load embedded byte arrays without triggering the in-process AMSI scan on `Assembly.Load(byte[])`. The ETW HW BP bypass (DR1 on `NtTraceControl`) silences ETW Threat Intelligence events that would otherwise fire on memory protections and module loads. Together they get the loader to the point where the managed entry point runs cleanly; ProviderSidestep then handles the LDAP-specific telemetry from that managed entry point.

Order matters:

1. `bp_init(BP_ALL)` — VEH + DR0 + DR1 + ntdll selective refresh.
2. AES decrypt the managed payload to heap.
3. `_AppDomain::Load_3` of the SafeArray.
4. `_MethodInfo::Invoke_3` calling `ADProbe.Main`.
5. Managed code registers `AssemblyResolve` handler.
6. Managed code instantiates `LdapConnection` and does its thing.

Each layer addresses an independent telemetry surface. Drop any one of them and you re-introduce a class of detection: drop AMSI HW BP and `Assembly.Load(byte[])` gets scanned; drop ETW HW BP and ETW TI fires on RWX allocations and SafeArray sourcing; drop ProviderSidestep and `wldap32` events restore the client-side `sharphound` correlation.

## Disclosure

This is a research note about a publicly-documented EDR (Cortex XDR) and a publicly-documented behavioral rule family (`sharphound`). The bypass technique does not rely on any private vulnerability in Cortex; it relies on the documented behavior of the Windows ETW system and the choice of a pure-managed LDAP library. There is no CVE to file. Palo Alto's PSIRT has been notified out of professional courtesy. The findings do not enable any new offensive capability that informed defenders did not already understand — server-side ETW and filter-shape correlation are well-known mitigations — but the public characterization of *which* of those mitigations are deployed and *how* they compose with client-side rules is novel enough to share.

## References

1. SpecterOps — "BloodHound and SharpHound documentation". <https://github.com/SpecterOps/BloodHound>
2. `Novell.Directory.Ldap.NETStandard` — pure-managed LDAP for .NET. <https://github.com/dsbenghe/Novell.Directory.Ldap.NETStandard>
3. Palo Alto Networks — Cortex XDR Documentation, behavioral analytics module.
4. Microsoft — `Microsoft-Windows-LDAP-Client` provider, ETW manifest. `logman query providers Microsoft-Windows-LDAP-Client`
5. Microsoft — `Microsoft-Windows-ActiveDirectory_DomainService` provider (server-side LDAP query events).
6. RFC 4511 — Lightweight Directory Access Protocol (LDAP): The Protocol. ASN.1 / BER message semantics.
7. The author's previous post — [Patchless AMSI Bypass via Hardware Breakpoints]({% post_url 2026-06-01-patchless-amsi-bypass-hwbp %}).

---

*This research was conducted in an authorized lab with a Cortex XDR tenant licensed for offensive testing. The findings characterize one specific rule family in one specific configuration; behavior on other tenants, other rule sets, or other product versions may differ. Use only against systems you own or have written authorization to test.*
