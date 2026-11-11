# Intent Firewall

**Read what you're about to sign.** Intent Firewall decodes a NEAR Intents payload — the exact message your wallet asks you to sign — and tells you, in plain language, what it really does *before* your signature exists: **OK**, **REVIEW**, or **DO NOT SIGN**.

Built for **NEAR HACKATHON** · Tracks: **AI Security & Defense** (`security`), **Unstoppable DeFi** (`defi`)

## The problem

NEAR Intents swaps are settled from signed `token_diff` messages. To a user, that payload is unreadable JSON: asset IDs like `nep141:eth-0xa0b8….omft.near`, amounts in smallest units, a deadline, and a list of intents. A malicious or careless app/solver can hide, inside a "swap" signature:

- a fill far below the quote's guaranteed minimum,
- an unlisted look-alike token on the receiving side,
- a deadline days in the future (your signature stays live),
- extra intents — including a withdrawal to someone else's account.

Wallets show you the payload; nobody translates it. Intent Firewall is the translation layer, written by a working smart-contract auditor.

## Try it — do X, see Y

Open `index.html` in a browser (or the hosted demo). The token registry loads live from 1Click.

1. **Click "Sample: safe swap"** → see verdict **✅ LOOKS CONSISTENT**, a "You give / You receive" breakdown in human amounts with USD values, and an info finding that value in ≈ value out.
2. **Click "Sample: costly & long-lived"** → see verdict **⚠️ REVIEW CAREFULLY**, with a warning for the ≈2% effective spread and another for the 7-day deadline.
3. **Click "Sample: drainer bundle"** → see verdict **⛔ DO NOT SIGN**, with critical findings: expired deadline, an unknown `scam-token.near` asset, and a bundled `ft_withdraw` to `attacker.near` hiding behind the swap.
4. **Click "Sample: below quote minimum"** → see verdict **⛔ DO NOT SIGN**: the payload credits less than the pasted 1Click quote's `minAmountOut` — the solver keeps the difference.
5. **Paste your own payload** (raw intent message, or a full NEP-413 signed payload) into box 1 and click **Analyze payload** → see it decoded and checked. Optionally paste the 1Click quote response you were shown into box 2 to enable the quote cross-checks.

## What it checks

| Check | Catches |
|---|---|
| Decode (incl. NEP-413 wrappers) | Payloads that cannot be parsed at all — never sign undecodable data |
| Deadline sanity | Expired payloads, sub-2-minute deadlines, signatures that stay live > 24 h |
| Bundled intents | `ft_withdraw` / transfers / any extra intent riding inside a "swap"; withdrawals to accounts that are not you are critical |
| Unknown assets | Asset IDs absent from the 1Click token registry (look-alike / scam tokens) |
| Value balance | Give-side vs receive-side USD value at live registry prices: > 1% spread warns, > 3% is critical |
| Quote cross-check | Payload vs the quote you were shown: wrong give/receive asset, wrong amount, receive below `minAmountOut`, embedded app fees > 100 bps |

Verdict logic: any critical finding → **DO NOT SIGN**; any warning → **REVIEW**; otherwise **OK**.

## How it works

- `src/firewall.js` — the whole engine: parser + registry + checks. Dependency-free, runs in the browser and in Node.js, so the code judges click is the code the tests exercise.
- Token metadata and **live USD prices** come from the public 1Click token list, `GET https://1click.chaindefuser.com/v0/tokens` (a snapshot is kept in `assets/` for the tests). No JWT is required for this endpoint.
- Everything runs locally in the browser. No keys, no wallet connection, no backend, nothing is sent anywhere except the public token-list fetch.

## Run it

```sh
# any static server, or just open index.html in a browser
python3 -m http.server 8080   # then visit http://localhost:8080

# tests (Node.js, no dependencies)
node test/firewall.test.mjs
```

The test suite covers: a safe swap, a wide-spread/long-deadline swap, a drainer bundle, quote cross-checks against a real 1Click quote captured from the live API (below-minimum and at-quote cases), NEP-413 unwrapping, and garbage input.

## Limitations (stated plainly)

- This is a **structure-and-economics** check. It does not verify the payload's signature and cannot judge whether the app showing you the payload is honest — it judges what the payload itself says.
- Value checks depend on registry prices; an asset with no registry price is flagged as unknown rather than silently trusted.
- Spread thresholds are heuristics: on illiquid or long cross-chain routes, a legitimate quote can show an effective spread above the 3% critical line. Treat a value-imbalance verdict as a demand to re-check the route and the quote — not as proof of a scam.
- A "OK" verdict means *no red flags found*, not a guarantee of safety.

## Built with

- NEAR Intents payload format & the Verifier's intent types (`token_diff`, `ft_withdraw`, …), per docs.near-intents.org
- 1Click API token list (asset registry + USD prices) — https://1click.chaindefuser.com/v0/tokens
- Vanilla HTML/CSS/JS. No framework, no build step.
- Code in this repository was written during the hackathon window (from 2026-11-09) with AI assistance (Claude), as permitted by the hackathon rules; the security rule set and test scenarios are the author's own audit methodology.

## License

MIT — see `LICENSE`.
