# Schnorr — Noir Signature Library

## Overview

Noir library providing Schnorr signature verification over BN254/Grumpkin elliptic curves. Used by `stx-circuit` for spend-auth and compliance signature verification in ZK proofs.

## Commands

```sh
nargo test       # run tests
nargo check      # type-check
nargo fmt        # format
```

## Implementation

Single library crate exporting `verify_signature()`:
- Verifies equation: `zG == R + cP`
- Challenge computed via Poseidon2 with domain separation
- Uses embedded curve operations (Grumpkin multi-scalar multiplication)
- Validates curve point properties

## Dependencies

- `poseidon` v0.2.0 — Poseidon hash for challenge calculation
- Compiler: Noir >= 1.0.0

## After Any Change

- Run `nargo test` — all tests must pass
- If tests fail, fix the regression before moving on
- If you changed verification logic, add a test for it

## Conventions

- Published as library (`type = "lib"` in Nargo.toml)
- Consumed by `stx-circuit` as a git dependency
- Changes here require rebuilding `stx-circuit` artifacts
