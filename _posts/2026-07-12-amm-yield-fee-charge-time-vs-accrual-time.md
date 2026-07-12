---
title: "Charge-time vs accrual-time yield fees in AMMs: a design choice most LPs never see"
date: 2026-07-12 20:00:00 -0500
categories: [Research, DeFi]
tags: [defi, amm, balancer, uniswap, curve, yield-fee, rate-provider, liquidity-provider, protocol-design, methodology]
toc: true
lang: en
description: >-
  When a pool's creator raises the yield fee, does the new rate apply to
  yield that accrued before the change, or only to yield that accrues
  after? Balancer V3, Uniswap V4 hooks, and Curve pick different
  answers. The choice is invisible in the UI, matters to any LP holding
  liquid staking or restaking assets, and is defensible on both sides.
  This post walks the mechanics on-chain, quantifies the drift for a
  worked example, and offers a small checklist LPs can run before
  joining a creator-owned pool.
---

> **TL;DR** — Balancer V3's `Vault.collectAggregateFees()` (`pkg/vault/contracts/Vault.sol`) settles only fee amounts already charged into aggregate accounting. It does not settle pending yield reported by a `RateProvider` since the last pool operation. When a pool creator raises the creator yield fee via `setPoolCreatorSwapFeePercentage` or `setPoolCreatorYieldFeePercentage`, the next pool operation applies the new percentage to the entire balance increase reported by the rate provider since the last settlement, including the portion that accrued while the old rate was in force. This is a deliberate design choice ("point-in-time charging"), not a bug, and the on-chain trust model is that liquidity providers accept the creator's fee authority on join. But the same behavior is not universal across AMMs, LP UIs do not surface it, and the drift for a wstETH-style pool at typical LST APRs is not zero. This post walks the mechanic, the alternatives, and the practical implications.
{: .prompt-tip }

## 1. Why the mechanic exists

Rate-provider-backed pools (LST/LRT/RWA vaults) do not settle every block. A pool of wstETH-and-something updates its accounting only when someone touches it: a swap, an add, a remove. Between operations, the wstETH:stETH rate drifts upward as the beacon chain accrues rewards, and the pool's `RateProvider.getRate()` reflects that drift on read.

That gap between "the last operation" and "now" is *pending yield*. It is real value the pool owes the LPs. It has not been charged a fee yet because it has not been settled yet.

At the next pool operation, the vault:

1. Reads the current `getRate()`.
2. Compares against the stored rate from the last operation.
3. Computes the yield delta over the interval.
4. Applies the current yield-fee percentage to that delta.
5. Sends the fee share to the aggregate-fee bucket, splits the bucket between protocol and creator.

The question this post is about is what happens if step 4's "current percentage" is not the same as the percentage that was in force during the interval. Concretely: what happens when the creator raised the yield fee at some point after the last operation but before the current one?

## 2. Balancer V3's answer: point-in-time

The relevant paths in the Balancer V3 monorepo (as of the current tag):

- `pkg/vault/contracts/Vault.sol` — `_computeYieldFeesDue()` computes the fee amount for a single token based on the *current* `aggregateYieldFeePercentage`, applied to the full delta.
- `pkg/vault/contracts/ProtocolFeeController.sol` — `setPoolCreatorYieldFeePercentage()` updates the stored creator percentage and calls `withLatestFees()` before the update takes effect.
- `withLatestFees()` — the intent is to "flush anything already charged" before the change so the protocol-vs-creator split of already-charged fees does not get mismixed with the new percentage.
- `collectAggregateFees()` — sweeps amounts already in the aggregate-fee accounting into per-token buckets. It reads only the aggregate-fee balance. It does not load pool data, it does not read `getRate()`, it does not settle any pending yield.

The important line from the design perspective is inside `collectAggregateFees()` (I paraphrase; the exact line number moves between tags):

```solidity
// Aggregate fees already charged in prior operations are swept here.
// Pending yield from rate providers is NOT settled: that happens on
// the next pool operation (swap/add/remove), at whatever the rate is
// at that time.
uint256[] memory aggregateFees = _aggregateFeeAmounts[pool];
```

So the ordering, when a creator raises the yield fee at time `t`, looks like this:

```
t = T-1:  last pool operation. Stored rate = R0. All yield charged so far
          is at old percentage F0. Aggregate-fee bucket flushed.

T-1 < t < T:  no pool operations. Rate provider drifts R0 -> R1. Pending
              yield = balance_delta(R0, R1). Not settled, not charged.

t = T:    Creator calls setPoolCreatorYieldFeePercentage(F1) where F1 > F0.
          withLatestFees() runs first. It calls collectAggregateFees(),
          which sweeps whatever is already in the aggregate bucket. The
          pending R0 -> R1 yield is NOT in that bucket, so it is NOT
          swept. The stored creator percentage is now F1.

t = T+1:  Next pool operation. Vault reads R1, sees delta since R0, applies
          the CURRENT percentage F1 to the whole delta, including the
          portion that accrued at t < T.
```

The Balancer team's stated position is that this is by design. The fee model is *point-in-time*: the fee rate applied to a settlement is the rate in effect at the moment the settlement runs, not the rate in effect while the underlying yield accrued.

The trust-model framing is that the creator has authority to set the yield fee anywhere up to the hard cap (99.999% at the time of writing), that this authority is disclosed on pool creation, and that liquidity providers who join a creator-owned pool accept that authority. Timing a fee increase to catch an unsettled interval is that same authority applied strategically to the current window.

## 3. The alternative: accrual-time

An accrual-time fee model would apply, to each unit of yield, the fee rate that was in force during the sub-interval when that unit accrued. Implementing it requires the pool to either:

- Snapshot the fee rate at every rate-provider update (expensive; rate providers can update per-block on some chains), or
- Store enough interval history that a settlement can reconstruct the correct split (unbounded state growth), or
- Force a settlement transaction at the moment of the fee change (griefable; adds gas cost to any fee update).

Neither is cheap. Every AMM design that has considered the trade-off has arrived at a variant of point-in-time charging, but the specifics vary.

**Uniswap V4** does not price yield fees at the vault level. Yield-fee accounting is delegated to hooks, and any given hook can pick its own policy. A hook designed for LST/LRT pools can (in principle) snapshot the rate at fee-change time and enforce accrual-time semantics; the trade-off is gas cost and hook complexity, which the hook author owns. The point is that V4 does not have a "right answer" in the core; it has a marketplace of hook implementations that make different choices.

**Curve V2**'s stableswap-style pools with rate multipliers use a similar point-in-time model to Balancer V3, with the added constraint that Curve pools do not typically expose a per-pool creator fee. The admin-fee split is a protocol parameter, and changes go through the governance timelock, which functionally gives LPs advance notice of any rate change. There is no equivalent "flash-timed" surface in the Curve V2 architecture.

**Balancer V3** sits between the two: it uses point-in-time charging like Curve but exposes a per-pool creator with unilateral, un-timelocked, up-to-99.999% control. The combination is what makes the drift visible when it might not be on other AMMs with the same math.

## 4. A worked example

Consider a wstETH/WETH pool where the creator's initial yield-fee percentage is 5% and the LST accrues at approximately 3.5% APR (typical for stETH-family assets through 2026).

Interval assumptions:

- Time between the previous settlement and the fee change: 7 days.
- Time between the fee change and the next settlement: 1 hour (assume a natural swap arrives on that timescale in an active pool).
- Pool wstETH balance at previous settlement: 1,000 wstETH.
- Rate delta over 7 days: 1000 wstETH * (0.035 / 365) * 7 = 0.671 wstETH of yield.

Under point-in-time charging with a creator raise from 5% to 50% at hour 168:

```
Yield accrued 0..168 h at intended 5%:  0.671 * 5%  = 0.0336 wstETH
Yield accrued 168..169 h at intended 50%: (0.671 / 168) * 50% = 0.002 wstETH

Expected fee (accrual-time):  0.0336 + 0.002 = 0.0356 wstETH
Actual fee (point-in-time):   (0.671 + 0.671/168) * 50% = 0.3376 wstETH

Drift:  0.302 wstETH per 1000 wstETH per 7 days ~= 0.03% of pool value.
```

Recurring or not, applied at each fee change, this is a real drift. It is bounded by the frequency of settlement operations and by how conservatively creators use their fee authority. In an active pool, someone touches it every few hours and the maximum captured interval is short. In an idle or thinly traded pool, the maximum captured interval is the maximum time between operations, which can be days.

## 5. What an LP can check before joining

For any pool where a creator address exists and the yield-fee percentage is not zero, the following handful of questions distinguishes acceptable-risk pools from ones where the LP is silently exposed to fee-timing drift:

1. **Is the pool active?** A pool that has had a swap or a rebalance in the last few hours has bounded exposure: the maximum interval a creator can catch is bounded by the settlement cadence. An idle pool exposes the full time-since-last-op window.

2. **What is the creator's current yield-fee percentage and history?** A pool where the creator has changed the yield-fee percentage multiple times, especially close to observable settlement events, is a signal.

3. **Does the pool use a rate provider whose read function updates continuously?** If yes, the pending-yield gap between operations is real and growing. Static-rate pools do not have this drift.

4. **What is the yield-fee cap?** The 99.999% cap is theoretical for most legitimate deployments, but it exists and it is the upper bound on any single fee-change captured drift.

5. **Is there a timelock or minimum notice period on creator fee changes?** Balancer V3's default is none. Some pools opt in to a wrapper contract that adds a timelock, and those are safer for a passive LP.

None of these questions requires reading Solidity. Four out of five are visible on-chain via Etherscan and on the pool's dashboard.

## 6. What a protocol designer can consider

Not every AMM needs to change its model. Point-in-time charging is defensible, and the trust-model framing is honest as long as it is disclosed. The specific improvements that would remove the drift, in decreasing order of feasibility:

- **Force `withLatestFees()` to trigger a real settlement, not just an aggregate flush.** The vault would need to iterate over rate providers and settle each one to bring the aggregate bucket up to date before the fee change takes effect. Gas-expensive but bounded.

- **Add a minimum notice / timelock on `setPoolCreatorYieldFeePercentage`.** Even a one-block delay would let LPs observe the pending change and either exit or force a settlement themselves.

- **Emit an `AllowedFeeRange` event on pool creation** that establishes an LP-visible ceiling for future fee changes, below the theoretical hard cap. The pool creator still has authority within that range; LPs know what they signed up for.

- **Surface the drift in the LP UI.** "Your current unsettled yield since last operation is X wstETH. A fee change would apply to the full X." One line of copy.

None of these is a "must." They are choices with trade-offs, and different protocols have different LP populations and different risk appetites. The point is that the current default in Balancer V3 is the aggressive end of the spectrum: maximum creator authority, no timelock, no notice, no UI disclosure. That is fine if the LP knows. It is worth writing down when they do not.

## 7. Not a bug

For the avoidance of doubt, the behavior described here is intentional in Balancer V3. It reproduces because the code is deliberately structured to keep `collectAggregateFees()` scoped to already-charged fees only, and to charge yield fees at the rate current at the moment of settlement. The `onlyPoolCreator` gate, the 99.999% cap, and the LP-on-join acceptance of creator authority together form the on-chain trust model, and inside that trust model the behavior is expected.

What is worth writing down is that the trust model contains a mechanic that most LPs never see documented, and that other AMMs with the same math but different governance surfaces (Curve's timelock, Uniswap V4's hook flexibility) close the same gap in different ways. If you are a passive LP holding a rate-provider-backed pool position, the questions in Section 5 are worth running before you join, and worth periodically re-running while you hold.

---

*Notes on scope: This analysis covers Balancer V3 as of the current mainnet tag, Uniswap V4 as of its initial mainnet release, and Curve V2 stableswap architecture. Fork protocols with modifications to `Vault.sol` or hook logic may behave differently. Governance parameters (caps, timelocks, cadence) change over time; check on-chain state at read time rather than trusting protocol documentation.*
