# WEBC AI-agent commerce plan

Sources: `WEBC-DEFINITION.md` §6, §15.5, §15.32; the service-registry
discovery format is §16 open item 8, delegated and given an initial design
here. Everything is **not-yet-built**. Signature/custody details for agent
keys are security-document scope.

## 1. The three primitives — decided (§15.5)

1. **Mandate** — an on-chain, instantly revocable authorization a principal
   grants an agent (a "digital permission slip / prepaid card with rules
   engraved on it" — §15.32).
2. **Service registry** — services publish machine-readable prices and
   interfaces for agent discovery; the commerce counterpart of the component
   catalog.
3. **HTTP-402 compatibility** — an agent pays for a resource inside an
   ordinary web request cycle.

## 2. Mandate object — decided spec (§15.32)

Fields (an on-chain object):

- `principal` — the owner account;
- `agent_key` — the AI's signing key;
- `budget_total`, `spent` — u128 base units;
- `expiry` — epoch;
- `counterparty_policy` — open, or an allowlist of services / registry
  categories;
- `per_tx_max` — per-transaction limit;
- `rate_limit` — max spends per day;
- **no re-delegation** — an agent cannot mint sub-mandates;
- **instant revocation** by the principal at any time;
- every spend references the mandate ID → complete audit trail; any site can
  verify a mandate's validity on-chain before serving the agent.

Wire-format details are delegated to implementation (§15.32). Designed here:

- A mandate is an **owned object** of the principal (object model, §8);
  spends are transactions signed by `agent_key` that declare the mandate in
  their access set; the runtime enforces budget/expiry/allowlist/limits
  atomically with the payment.
- Revocation and top-up are principal-signed operations on the object;
  revocation is effective from the block it lands in (single-owner object →
  **fast-path eligible** for sub-second revocation, `speed-roadmap.md`).
- Relationship to session keys: the prototype's constrained session keys
  authorize *the owner's own device flows*; a mandate authorizes *a distinct
  agent identity* with its own key and audit trail. Both reuse the
  authorization-policy machinery; they are separate primitives.

## 3. Service registry — initial design (delegated open item)

Purpose (§15.5): agents discover services, prices, and interfaces on-chain,
and can pay for them under mandates without bespoke integration.

### 3.1 Registry entry schema (v1 draft)

An on-chain object per service, machine-readable, versioned:

```text
service_id        32-byte id (namespace-scoped)
owner             account that controls the entry
category          registry taxonomy tag(s) (mandate allowlists may reference these)
title             short human/machine label
endpoint          HTTPS URL (or on-chain entrypoint reference for pure on-chain services)
interface         manifest reference: the machine-readable interface description
                  (same schema family as the Weft compiler manifest / component
                  catalog — one description format across the platform)
pricing[]         list of { operation, price (u128 base units, asset), unit,
                  subscription terms? }
payment           accepted flows: on-chain direct | HTTP-402 | subscription object
attestations      optional first-party/on-chain track-record references
status            active | paused | retired
revision          monotonically increasing; prior revisions remain readable
```

Registration/update is permissionless for a fee (spam-priced); entries are
namespace-scoped objects so registry activity does not contend with unrelated
apps (§8).

### 3.2 Trust and quality

Like the DEX registry (§15.13), trust is an **on-chain track record**, not a
gatekeeper: age, paid-call volume, dispute flags, uptime attestations
accumulate on the entry; wallets, agent frameworks, and aggregators filter.
No central approval; mandates' `counterparty_policy` gives principals the
allowlist control.

### 3.3 Discovery

- On-chain: category/tag scan via light-client reads (free display reads —
  §15.21).
- Off-chain mirror: the docs-as-data pipeline (§15.44) publishes an
  LLM-ingestible flat snapshot of the registry so agents can discover
  services the same way they read the component catalog.

## 4. HTTP-402 payment flow — designed here (delegated)

Goal (§15.5): an agent pays inside an ordinary web request cycle.

1. Agent requests a resource; service responds `402 Payment Required` with a
   machine-readable challenge: service_id, operation, price, asset,
   pay-to address, invoice nonce, expiry.
2. Agent validates the challenge against the on-chain registry entry (price
   and pay-to must match — a compromised endpoint cannot overcharge silently).
3. Agent pays under its mandate (fast-path payment; sub-second certificate —
   `speed-roadmap.md`), referencing the invoice nonce in the transaction.
4. Agent retries the request with the payment reference; the service
   verifies on-chain (certificate or finality per its risk policy) and
   serves the resource, optionally returning a signed receipt (§9 external
   actions model).
5. Disputes: the audit trail (mandate ID + invoice nonce + receipt hash)
   makes non-delivery provable enough for track-record flags; the protocol
   does not adjudicate content quality.

Subscriptions: a service may sell a subscription object (prepaid allowance)
that the 402 challenge can reference instead of per-call payment — mirroring
the oracle's subscription design (`oracle-economics.md`).

## 5. The flagship showcase (§15.36)

The **AI-agent API marketplace** — services list machine-readable prices;
agents discover and pay per call via mandates — is one of the four named
flagship candidates and the showcase of the AI-native thesis. Its build rides
entirely on the three primitives above plus the SDK agent toolkit
(development plan, platform phase).

## 6. Build plan (phase alignment: development-plan Phase 9)

1. Mandate object + runtime enforcement + revocation/top-up + audit indexing.
2. Adversarial tests: over-budget, expired, rate-limited, revoked-mid-flight,
   re-delegation attempts, allowlist bypass attempts, replayed invoices.
3. Registry objects + fee-priced registration + revision history.
4. SDK: mandate management UI for principals (grant/monitor/revoke), agent
   client (discover → validate challenge → pay → retry), service middleware
   (challenge issue + verification), all against the manifest schema.
5. Docs-as-data registry snapshot pipeline.
6. Reference flagship: a small real service (e.g. paid inference or data API)
   run end-to-end by an autonomous agent on testnet, published as the
   showcase demo.

## 7. Open items

- Registry taxonomy (category set) — freeze with catalog schema work.
- Receipt format standardization (shared with §9 external-action receipts).
- Mandate fee sponsorship interaction (can a service sponsor the agent's
  fees? — default yes via existing caps; verify no drain vector in tests).
