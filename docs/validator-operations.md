# WEBC validator operations and bootstrap plan

Sources: `WEBC-DEFINITION.md` §7, §15.2, §15.10, §15.15, §15.19, §15.23,
§15.24, §15.26, §15.28. Status: economics and environment decisions are
**decided**; operational specifics are delegated and designed here.
Everything below the "decided" headings is **not-yet-built**.

## 1. Economics — the deliberate middle path (decided, §15.23)

- **Low stake barrier:** pool activates at 100 WEBC total; operator ≥20 WEBC
  and always ≥20% of pool; delegation ≤80%; minimum delegation 1 WEBC (§7).
- **Mid-range hardware target:** a decent multi-core server with NVMe and
  ~1 Gbps — an ordinary cloud instance, not a data-center monster. §12's
  lightweight-device promise applies to *users verifying*, not validators
  producing.
- **No per-vote fees:** votes are permissioned aggregated consensus
  messages, not transactions. Participating in consensus costs nothing;
  only misbehavior costs stake. Vote spam is structurally impossible
  (§15.28): only current committee keys may vote; one vote per member per
  round (traffic fixed by protocol, not demand); equivocation is provable
  and slashable; persistent invalid senders are scored down and banned at
  the p2p layer.
- Rewards: issuance (10%→1% floor), 50% of base fees, priority fees.
  Extractive MEV is not a validator revenue stream (§15.37).

## 2. Node environment (decided, §15.26)

- **Official container image** is the standard way to run a validator: zram,
  zstd, kernel/database tuning on by default — everyone gets the tuned
  environment without a protocol mandate (memory configuration is invisible
  to consensus and cannot be a consensus rule).
- **Minimum vs recommended spec split (decided):** a low floor keeps entry
  broad; a higher recommended profile gives comfortable operation.
- **The floor rises only with evidence (decided + guardrail):** initial floor
  ~1 GbE + NVMe SSD + modest RAM; later raises (more RAM, 10 GbE, optional
  GPU for batch signature verification/erasure coding) require governance
  with **measured demand** (sustained utilization/benchmarks) and a published
  multi-year hardware roadmap, because every raise prices out operators.
  GPU is never consensus-mandatory without a governance decision.

### Designed here: spec table skeleton (values are measurement placeholders, §15.35 method)

| Profile | CPU | RAM | Disk | Network |
|---|---|---|---|---|
| Minimum floor | modern multi-core (≈4–8c) | modest (SSD-first design) | NVMe SSD | ~1 Gbps, flat-rate preferred |
| Recommended | ≈8–16c | comfortable cache headroom | NVMe, larger | ~1 Gbps+ |
| Verification node (no stake) | below floor is fine | small | SSD | consumer broadband |

Exact numbers are frozen from reference-machine benchmarks
(`speed-roadmap.md`), never guessed.

## 3. Bandwidth and memory frugality (decided, §15.19, §15.24)

Communication is expected to be the bottleneck — and the classic cloud
**egress billing bomb** — with RAM next:

- **zstd on by default** on gossip/wire and at the storage layer; hashes and
  signatures are always computed over canonical uncompressed bytes, so
  compression never affects verification (§15.24); implementations may skip
  compression adaptively for incompressible payloads (§15.29).
- **Compact-block relay:** blocks reference transactions by hash; peers
  fetch only missing bodies.
- **Vote aggregation:** committee votes travel as aggregated signatures.
- **SSD-first state:** modest RAM cache; never full-state-in-memory. zram is
  an operator option in the image, not a protocol dependency.
- **Client-side bandwidth budgets/rate limits** so an operator on metered
  egress cannot be surprise-billed; node docs recommend flat-bandwidth
  providers and ship sizing guides (§15.23).

## 4. Bootstrap program (decided direction, §15.10, §15.15; sequence §15.2)

See `distribution-program.md` §3.2 for the grant mechanics (stake-locked,
vest by proven operation, co-stake, diversity criteria, 5% ceiling with
reversion). Operational side designed here:

1. **Recruitment (testnet):** public program announcement; operators run the
   official image on their own infrastructure for a multi-week evaluation
   window; selection scores **sustained correct operation** (uptime under
   rotation, correct votes, sync recovery, upgrade drills) — not raw compute.
2. **Diversity enforcement:** per-operator caps; hosting-provider and
   geography quotas so the set is not concentrated on one cloud (§15.10).
3. **Genesis:** granted operators start staked and active; founder-run nodes,
   if any, are labeled temporary with published retirement criteria
   (phase-0 honesty, §15.10).
4. **Vesting operation:** unlock per epoch of provably correct validation
   over a 1–2 year horizon; forfeit on quit/misbehavior; co-stake ramps.
5. **Bootstrap exit (§15.2 — proposed):** published sunset criteria
   (validator count, stake dispersion, distribution progress) close the
   bootstrap phase; the issuance-keying element remains an owner decision at
   the economics freeze.

## 5. Operator documentation to ship (designed here)

- Image + compose/systemd quickstart; key provisioning via permissioned
  keystore file (never argv/env — security docs own the details).
- Sizing guide per profile; egress budgeting worksheet; flat-bandwidth
  provider notes.
- Upgrade, rollback, and state-sync drills; monitoring endpoints and alert
  defaults.
- The hardware roadmap page (multi-year, governance-updated — §15.26).

## 6. Open items

- Committee sampling algorithm and aggregated-signature scheme (ADR-tracked;
  consensus-security scope).
- Exact spec-floor numbers and bandwidth budgets (benchmark-frozen).
- Bootstrap scoring weights and evaluation-window length (published with the
  distribution specification before the program starts).
