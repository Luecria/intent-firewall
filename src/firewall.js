/*
 * Intent Firewall — core engine.
 * Decodes a NEAR Intents signed payload (the exact message a user is about
 * to sign) and checks its economics and structure BEFORE the signature exists.
 *
 * Dependency-free. Works in the browser (window.IntentFirewall) and in
 * Node.js (module.exports) so the same code the judges click is the code
 * the tests exercise.
 *
 * Scope of v1: structure + economics checks. This is NOT signature
 * verification and NOT a substitute for checking the app you are using.
 */
(function (global) {
  "use strict";

  // ---------------------------------------------------------------- registry
  // Registry shape: Map assetId -> { symbol, decimals, blockchain, price }
  // Built from the 1Click token list (GET https://1click.chaindefuser.com/v0/tokens),
  // which conveniently carries live USD prices per asset.
  function buildRegistry(tokensArray) {
    const reg = new Map();
    for (const t of tokensArray || []) {
      if (!t || !t.assetId) continue;
      reg.set(t.assetId, {
        symbol: t.symbol || "?",
        decimals: typeof t.decimals === "number" ? t.decimals : 18,
        blockchain: t.blockchain || "?",
        price: typeof t.price === "number" ? t.price : null,
      });
    }
    return reg;
  }

  // ------------------------------------------------------------------ parser
  // Accepts any of the shapes a user might copy out of a wallet / dApp:
  //  1. the raw intent message object  { signer_id, deadline, intents: [...] }
  //  2. the message as a (possibly escaped) JSON string
  //  3. a full NEP-413 signed payload  { standard:"nep413", payload:{ message:"<json string>", ... }, signature }
  //  4. wrappers with a string .payload or .message field
  function extractMessage(input) {
    let obj = input;
    if (typeof obj === "string") {
      obj = JSON.parse(obj); // throws on garbage — caller reports it
    }
    if (obj && typeof obj === "object") {
      // NEP-413 style: payload.message holds the escaped intent JSON string
      if (obj.payload && typeof obj.payload.message === "string") {
        return JSON.parse(obj.payload.message);
      }
      if (typeof obj.message === "string" && obj.message.trim().startsWith("{")) {
        return JSON.parse(obj.message);
      }
      if (typeof obj.payload === "string" && obj.payload.trim().startsWith("{")) {
        return JSON.parse(obj.payload);
      }
      return obj;
    }
    throw new Error("Unrecognized payload shape");
  }

  function parseIntentPayload(input) {
    const msg = extractMessage(input);
    if (!msg || typeof msg !== "object") throw new Error("Payload is not a JSON object");
    if (!Array.isArray(msg.intents)) throw new Error("Payload has no intents[] array");
    return {
      signerId: msg.signer_id || null,
      deadline: msg.deadline || null,
      intents: msg.intents,
      raw: msg,
    };
  }

  function tryParseQuote(text) {
    if (!text || !String(text).trim()) return null;
    try {
      const q = JSON.parse(text);
      if (q && q.quote && q.quoteRequest) return q;
      return null;
    } catch (e) {
      return null;
    }
  }

  // A diff amount must be a signed integer string ("-10000000"). Anything
  // else ("abc", "1.5", an object) is malformed — hostile input must
  // produce a finding, never an exception.
  function isIntStr(s) {
    return typeof s === "string" && /^-?\d+$/.test(s);
  }

  // ------------------------------------------------------------------ amounts
  function toHuman(rawAmountStr, decimals) {
    // rawAmountStr is a signed integer string in the asset's smallest unit.
    const neg = rawAmountStr.startsWith("-");
    const digits = neg ? rawAmountStr.slice(1) : rawAmountStr;
    const v = BigInt(digits || "0");
    const scale = 10n ** BigInt(decimals);
    const whole = v / scale;
    const frac = v % scale;
    let fracStr = frac.toString().padStart(decimals, "0").replace(/0+$/, "");
    const num = Number(whole) + (fracStr ? Number("0." + fracStr) : 0);
    return neg ? -num : num;
  }

  // ------------------------------------------------------------------- checks
  const SEV = { INFO: "info", WARN: "warn", CRITICAL: "critical" };

  function analyze(intentInput, opts) {
    try {
      return analyzeInner(intentInput, opts);
    } catch (e) {
      // A firewall must never crash on hostile input: any unexpected
      // analysis failure is itself a reason not to sign.
      return {
        verdict: "DO_NOT_SIGN",
        findings: [{
          severity: SEV.CRITICAL, rule: "analysis-error", title: "Payload could not be fully analyzed",
          detail: "The analyzer hit an unexpected error (" + (e && e.message ? e.message : e) + "). Treat un-analyzable payloads like undecodable ones: do not sign.",
        }],
        parsed: null,
        flows: null,
      };
    }
  }

  function analyzeInner(intentInput, opts) {
    opts = opts || {};
    const registry = opts.registry || new Map();
    const now = opts.now ? new Date(opts.now) : new Date();
    const quote = opts.quote || null; // parsed 1Click quote response, optional
    const findings = [];
    const add = (severity, rule, title, detail) => findings.push({ severity, rule, title, detail });

    let parsed;
    try {
      parsed = parseIntentPayload(intentInput);
    } catch (e) {
      add(SEV.CRITICAL, "decode", "Payload cannot be decoded",
        "This does not parse as a NEAR Intents message (" + e.message + "). Never sign data you cannot decode.");
      return finish(parsed || null, findings, null);
    }

    // ---- deadline checks -------------------------------------------------
    let deadlineDate = null;
    if (!parsed.deadline) {
      add(SEV.WARN, "deadline-missing", "No deadline in payload",
        "The intent carries no deadline. A signed intent without an expiry can be executed much later than you expect.");
    } else {
      deadlineDate = new Date(parsed.deadline);
      if (isNaN(deadlineDate.getTime())) {
        add(SEV.WARN, "deadline-unparseable", "Deadline is not a readable timestamp",
          "Deadline value: " + parsed.deadline);
      } else {
        const msLeft = deadlineDate.getTime() - now.getTime();
        if (msLeft <= 0) {
          add(SEV.CRITICAL, "deadline-expired", "Deadline already passed",
            "This intent expired at " + deadlineDate.toISOString() + ". Signing expired payloads is pointless at best and a replay risk at worst.");
        } else if (msLeft < 2 * 60 * 1000) {
          add(SEV.WARN, "deadline-tight", "Deadline is less than 2 minutes away",
            "The intent will likely expire before it can be executed, wasting the signature attempt.");
        } else if (msLeft > 24 * 3600 * 1000) {
          add(SEV.WARN, "deadline-long", "Deadline is more than 24 hours away",
            "Your signature stays live until " + deadlineDate.toISOString() + ". Long-lived signatures can be executed at a moment and price you did not choose.");
        } else {
          add(SEV.INFO, "deadline-ok", "Deadline looks sane",
            "Expires " + deadlineDate.toISOString() + " (" + Math.round(msLeft / 60000) + " min from now).");
        }
      }
    }

    // ---- collect token_diff flows ----------------------------------------
    const gives = [];    // { assetId, raw, human, usd, known, symbol, blockchain }
    const receives = [];
    let tokenDiffCount = 0;

    parsed.intents.forEach((it, idx) => {
      if (!it || typeof it !== "object") {
        add(SEV.CRITICAL, "intent-malformed", "Intent #" + (idx + 1) + " is malformed", "An intent entry is not an object.");
        return;
      }
      if (it.intent === "token_diff") {
        tokenDiffCount++;
        const diff = it.diff || {};
        for (const assetId of Object.keys(diff)) {
          const raw = String(diff[assetId]);
          const rawValid = isIntStr(raw);
          const meta = registry.get(assetId) || null;
          const entry = {
            assetId,
            raw,
            known: !!meta,
            symbol: meta ? meta.symbol : assetId,
            blockchain: meta ? meta.blockchain : "?",
            human: meta && rawValid ? toHuman(raw.replace("-", ""), meta.decimals) : null,
            usd: null,
          };
          if (meta && meta.price != null && entry.human != null) {
            entry.usd = entry.human * meta.price;
          }
          if (!meta) {
            add(SEV.WARN, "unknown-asset", "Unknown asset in the diff: " + assetId,
              "This asset is not in the 1Click token registry. Unlisted assets are a classic scam vector — you may be signing for a worthless look-alike token.");
          }
          if (!rawValid) {
            add(SEV.CRITICAL, "malformed-amount", "Amount for " + assetId + " is not a number",
              "The diff value for this asset is " + JSON.stringify(diff[assetId]) + " — not an integer amount in smallest units. A payload with non-numeric amounts is malformed or hostile. Never sign it.");
          }
          if (raw.startsWith("-")) gives.push(entry); else receives.push(entry);
        }
      } else {
        // ---- bundled / non-swap intents ----------------------------------
        const kind = it.intent || "(missing intent type)";
        if (kind === "ft_withdraw" || kind === "native_withdraw" || kind === "token_transfer" || kind === "transfer") {
          const receiver = it.receiver_id || it.receiverId || it.account_id || "unknown";
          const isSelf = parsed.signerId && receiver === parsed.signerId;
          add(isSelf ? SEV.WARN : SEV.CRITICAL, "bundled-withdraw",
            "Bundled " + kind + " intent to " + receiver,
            "This payload does more than swap: it also moves tokens out" + (isSelf ? " (back to your own account)." : " to an account that is NOT you. Bundled withdrawals are how drainers hide inside a normal-looking swap."));
        } else {
          add(SEV.WARN, "bundled-intent", "Extra intent bundled in this payload: " + kind,
            "You were probably shown a swap, but this signature also authorizes a '" + kind + "' action. Make sure you intended every action in the list.");
        }
      }
    });

    if (tokenDiffCount > 1) {
      add(SEV.WARN, "multi-diff", tokenDiffCount + " token_diff intents in one signature",
        "Multiple token diffs in a single payload are unusual for a simple swap. Review each one.");
    }
    if (tokenDiffCount === 0) {
      add(SEV.WARN, "no-diff", "No token_diff intent found",
        "This payload contains no swap diff. If you were told you are swapping, this is not the payload you were promised.");
    }

    // ---- value balance (needs prices) --------------------------------------
    const sumUsd = (arr) => arr.every((e) => e.usd != null) && arr.length ? arr.reduce((s, e) => s + e.usd, 0) : null;
    const giveUsd = sumUsd(gives);
    const receiveUsd = sumUsd(receives);
    if (giveUsd != null && receiveUsd != null && giveUsd > 0) {
      const lossPct = ((giveUsd - receiveUsd) / giveUsd) * 100;
      if (lossPct > 3) {
        add(SEV.CRITICAL, "value-imbalance", "You receive ~" + lossPct.toFixed(2) + "% less value than you give",
          "Giving ≈ $" + giveUsd.toFixed(2) + " but receiving only ≈ $" + receiveUsd.toFixed(2) + " at current registry prices. That is far beyond normal solver spread — a bad fill or a trap.");
      } else if (lossPct > 1) {
        add(SEV.WARN, "value-spread", "Effective spread ≈ " + lossPct.toFixed(2) + "%",
          "Giving ≈ $" + giveUsd.toFixed(2) + ", receiving ≈ $" + receiveUsd.toFixed(2) + ". Acceptable for some routes, expensive for a stablecoin-to-stablecoin swap.");
      } else {
        add(SEV.INFO, "value-ok", "Value in ≈ value out (spread " + lossPct.toFixed(2) + "%)",
          "Giving ≈ $" + giveUsd.toFixed(2) + ", receiving ≈ $" + receiveUsd.toFixed(2) + " at current registry prices.");
      }
    } else if (gives.length && receives.length) {
      add(SEV.INFO, "value-unpriced", "Value balance not computed",
        "At least one asset has no registry price, so the in/out value comparison was skipped. Check the amounts by hand.");
    }

    // ---- cross-check against a 1Click quote the user was shown -------------
    if (quote) {
      const qr = quote.quoteRequest || {};
      const q = quote.quote || {};
      const qGive = gives.find((g) => g.assetId === qr.originAsset);
      const qRecv = receives.find((r) => r.assetId === qr.destinationAsset);
      if (qr.originAsset && !qGive) {
        add(SEV.CRITICAL, "quote-asset-mismatch", "Intent does not give the asset the quote promised",
          "The quote was for giving " + qr.originAsset + ", but the payload's diff does not take that asset from you. You are signing a different trade than the one quoted.");
      }
      if (qr.destinationAsset && !qRecv) {
        add(SEV.CRITICAL, "quote-asset-mismatch", "Intent does not deliver the asset the quote promised",
          "The quote promised " + qr.destinationAsset + " in return, but the payload never credits it. You would pay and receive something else — or nothing.");
      }
      if (qGive && q.amountIn && qGive.raw.replace("-", "") !== String(q.amountIn)) {
        add(SEV.CRITICAL, "quote-amount-mismatch", "Amount taken differs from the quote",
          "Quote amountIn is " + q.amountIn + " but the payload takes " + qGive.raw.replace("-", "") + " (smallest units). Never sign for a different amount than you approved.");
      }
      if (qRecv && q.minAmountOut && isIntStr(qRecv.raw) && isIntStr(String(q.minAmountOut))) {
        if (BigInt(qRecv.raw) < BigInt(q.minAmountOut)) {
          add(SEV.CRITICAL, "below-min-out", "You receive LESS than the quote's guaranteed minimum",
            "Payload credits " + qRecv.raw + " but the quote's minAmountOut is " + q.minAmountOut + " (smallest units). The solver is keeping the difference.");
        } else {
          add(SEV.INFO, "min-out-ok", "Received amount meets the quote minimum",
            "Payload credits " + qRecv.raw + " ≥ minAmountOut " + q.minAmountOut + ".");
        }
      }
      const appFees = Array.isArray(qr.appFees) ? qr.appFees : [];
      const totalAppFeeBps = appFees.reduce((s, f) => s + (Number(f.fee) || 0), 0);
      if (totalAppFeeBps > 100) {
        add(SEV.WARN, "app-fees", "Embedded app fees total " + totalAppFeeBps + " bps (" + (totalAppFeeBps / 100).toFixed(2) + "%)",
          "The quote embeds app fees to " + appFees.map((f) => f.recipient).join(", ") + ". Fees above 1% on a swap deserve an explanation.");
      }
    }

    return finish(parsed, findings, { gives, receives, giveUsd, receiveUsd });
  }

  function finish(parsed, findings, flows) {
    const hasCritical = findings.some((f) => f.severity === SEV.CRITICAL);
    const hasWarn = findings.some((f) => f.severity === SEV.WARN);
    const verdict = hasCritical ? "DO_NOT_SIGN" : hasWarn ? "REVIEW" : "OK";
    return { verdict, findings, parsed, flows };
  }

  const api = { buildRegistry, parseIntentPayload, tryParseQuote, analyze, SEV };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.IntentFirewall = api;
})(typeof window !== "undefined" ? window : globalThis);
