// Node tests for the Intent Firewall engine.
// Run: node test/firewall.test.mjs
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import assert from "node:assert";

const require = createRequire(import.meta.url);
const FW = require("../src/firewall.js");

const snapshot = JSON.parse(readFileSync(new URL("../assets/tokens-snapshot.json", import.meta.url), "utf8"));
const registry = FW.buildRegistry(snapshot);
const meta = (id) => registry.get(id);

const USDC = "nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1"; // NEAR USDC, 6 dp
const WNEAR = "nep141:wrap.near"; // 24 dp
assert.ok(meta(USDC) && meta(WNEAR), "registry must contain USDC and wNEAR");

// raw amount of `asset` worth `usd` dollars at snapshot prices
function rawForUsd(assetId, usd) {
  const m = meta(assetId);
  const human = usd / m.price;
  const raw = BigInt(Math.round(human * 10 ** Math.min(m.decimals, 15))) * 10n ** BigInt(Math.max(0, m.decimals - 15));
  return raw.toString();
}
const inMin = (n) => new Date(Date.now() + n * 60000).toISOString();
const rules = (r) => r.findings.map((f) => f.rule);
let passed = 0;
function check(name, fn) { fn(); passed++; console.log("PASS", name); }

// 1 — SAFE: 10 USDC -> wNEAR at a fair rate, 30-minute deadline, single token_diff
check("safe swap -> OK", () => {
  const payload = {
    signer_id: "alice.near",
    deadline: inMin(30),
    intents: [{ intent: "token_diff", diff: { [USDC]: "-10000000", [WNEAR]: rawForUsd(WNEAR, 9.95) } }],
  };
  const r = FW.analyze(payload, { registry });
  assert.strictEqual(r.verdict, "OK", JSON.stringify(r.findings, null, 2));
  assert.ok(rules(r).includes("value-ok"));
});

// 2 — SUSPICIOUS: 2% spread + deadline a week out -> REVIEW (warnings, no critical)
check("wide spread + long deadline -> REVIEW", () => {
  const payload = {
    signer_id: "alice.near",
    deadline: inMin(60 * 24 * 7),
    intents: [{ intent: "token_diff", diff: { [USDC]: "-10000000", [WNEAR]: rawForUsd(WNEAR, 9.79) } }],
  };
  const r = FW.analyze(payload, { registry });
  assert.strictEqual(r.verdict, "REVIEW", JSON.stringify(r.findings, null, 2));
  assert.ok(rules(r).includes("value-spread") && rules(r).includes("deadline-long"));
});

// 3 — DANGEROUS: expired deadline + bundled withdrawal to a stranger + unknown scam token
check("drainer bundle -> DO_NOT_SIGN", () => {
  const payload = {
    signer_id: "alice.near",
    deadline: inMin(-10),
    intents: [
      { intent: "token_diff", diff: { [USDC]: "-10000000", "nep141:scam-token.near": "999999999" } },
      { intent: "ft_withdraw", receiver_id: "attacker.near", token: USDC, amount: "5000000" },
    ],
  };
  const r = FW.analyze(payload, { registry });
  assert.strictEqual(r.verdict, "DO_NOT_SIGN");
  for (const rule of ["deadline-expired", "bundled-withdraw", "unknown-asset"]) {
    assert.ok(rules(r).includes(rule), "missing rule " + rule + " in " + rules(r).join(","));
  }
});

// 4 — QUOTE CROSS-CHECK: real 1Click quote captured 2026-11-09 (10 USDC@Ethereum -> ETH).
//     Payload credits LESS than minAmountOut -> CRITICAL below-min-out.
const quote = {
  quote: { amountIn: "10000000", amountOut: "4650232079580513", minAmountOut: "4603729758784707" },
  quoteRequest: {
    originAsset: "nep141:eth-0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48.omft.near",
    destinationAsset: "nep141:eth.omft.near",
    appFees: [{ recipient: "5880ad2b362620fadf759cbceb1cd5737ce8c6ed7fb8e9942881e6731f9247dd", fee: 20 }],
  },
};
check("receive below quote minimum -> DO_NOT_SIGN", () => {
  const payload = {
    signer_id: "bob.near",
    deadline: inMin(20),
    intents: [{ intent: "token_diff", diff: { [quote.quoteRequest.originAsset]: "-10000000", [quote.quoteRequest.destinationAsset]: "4000000000000000" } }],
  };
  const r = FW.analyze(payload, { registry, quote });
  assert.strictEqual(r.verdict, "DO_NOT_SIGN");
  assert.ok(rules(r).includes("below-min-out"));
});
check("receive at quote amount -> no below-min-out finding", () => {
  const payload = {
    signer_id: "bob.near",
    deadline: inMin(20),
    intents: [{ intent: "token_diff", diff: { [quote.quoteRequest.originAsset]: "-10000000", [quote.quoteRequest.destinationAsset]: "4650232079580513" } }],
  };
  const r = FW.analyze(payload, { registry, quote });
  assert.ok(!rules(r).includes("below-min-out"));
  assert.ok(rules(r).includes("min-out-ok"));
});

// 5 — NEP-413 wrapped payload (message as escaped JSON string) parses identically
check("NEP-413 wrapper unwraps", () => {
  const inner = { signer_id: "carol.near", deadline: inMin(15), intents: [{ intent: "token_diff", diff: { [USDC]: "-1000000", [WNEAR]: rawForUsd(WNEAR, 0.995) } }] };
  const wrapped = { standard: "nep413", payload: { message: JSON.stringify(inner), nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", recipient: "intents.near" }, signature: "ed25519:xyz" };
  const r = FW.analyze(JSON.stringify(wrapped), { registry });
  assert.strictEqual(r.parsed.signerId, "carol.near");
  assert.strictEqual(r.verdict, "OK", JSON.stringify(r.findings, null, 2));
});

// 6 — garbage input -> CRITICAL decode finding, verdict DO_NOT_SIGN
check("garbage -> DO_NOT_SIGN with decode finding", () => {
  const r = FW.analyze("this is not json at all", { registry });
  assert.strictEqual(r.verdict, "DO_NOT_SIGN");
  assert.ok(rules(r).includes("decode"));
});

console.log("\nAll " + passed + " checks passed");
