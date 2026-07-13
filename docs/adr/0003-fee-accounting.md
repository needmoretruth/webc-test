# ADR-0003: deterministic resource and fee accounting

Status: accepted direction; numeric prices remain benchmark gates

Fees account for signatures, computation, state access, storage growth, and
contention. Base fees split exactly into burn and reward accounting; odd base
units follow one documented deterministic remainder rule. Priority fees never
change unrelated application lanes.

All arithmetic uses checked integers. Fee bids cap total user exposure and are
validated before mutation. Sponsors use constrained budgets and cannot acquire
authority over user funds.
