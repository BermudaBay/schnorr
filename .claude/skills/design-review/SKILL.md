---
name: design-review
description: Pre-implementation design review for new features. Analyzes the proposed feature against current ZK/crypto best practices, checks for security issues, and suggests better approaches before any code is written. Run this BEFORE /feat.
argument-hint: "<feature description>"
allowed-tools: WebSearch WebFetch Read Grep Glob Agent
---

# Design Review: $ARGUMENTS

Before writing any code or tests, perform a thorough design review of this feature. Research, analyze, and recommend the best approach.

## Step 1: Understand the Feature

- Parse the feature request and identify what it touches (circuits, contracts, SDK, compliance, etc.)
- Read the relevant source files to understand the current implementation
- Identify which repos will be affected

## Step 2: Research Current State of the Art

Search the web for the latest developments relevant to this feature:

- **Noir language**: Check noir-lang.org/docs and github.com/noir-lang/noir releases for new features, optimizations, or deprecations that affect our approach
- **Barretenberg / HONK**: Check for proving system updates, performance improvements, or new proof types
- **ZK patterns**: Search for recent papers, blog posts, or implementations solving similar problems (e.g., "efficient UTXO circuit 2025", "privacy pool design improvements")
- **Cryptographic primitives**: Check if Poseidon2, Schnorr/Grumpkin, or X25519-XChaCha20-Poly1305 have known issues or better alternatives
- **Solidity/EVM**: Check for relevant EIPs, gas optimizations, or security advisories
- **Similar protocols**: Look at how Aztec, Railgun, Tornado Nova, Zcash, or Penumbra handle equivalent features

## Step 3: Security Analysis

Evaluate the feature design against BermudaBay-specific attack vectors:

- **Privacy leaks**: Does the feature introduce information leakage? Timing side channels? Metadata correlation?
- **Proof soundness**: Can the circuit constraints be satisfied by invalid inputs? Are public inputs properly constrained?
- **Double-spend vectors**: Does the feature affect nullifier derivation or UTXO lifecycle?
- **Compliance bypass**: Could the feature allow circumventing deposit authorization or withdrawal checks?
- **Sub-deposit tracking**: Does it maintain the deposit-id lineage invariant across transfers?
- **Cross-contract consistency**: Do sdk proof inputs, circuit public inputs, and pool verification stay aligned?
- **Front-running / MEV**: Can a relayer or miner exploit ordering?
- **Merkle tree integrity**: Does it affect the append-only property or root history?

## Step 4: Efficiency Analysis

- **Circuit constraints**: Can the feature be implemented with fewer constraints? Would a different circuit topology reduce proving time?
- **On-chain gas**: Can verification or state updates be made cheaper?
- **Client-side performance**: Does it affect proof generation time on consumer hardware?
- **Bandwidth**: Does it increase calldata or proof size?

## Step 5: Output Design Recommendation

Present findings as a structured recommendation:

```
## Feature: [name]

### Proposed Approach
[Describe the recommended implementation path]

### Key Design Decisions
1. [Decision and rationale]
2. [Decision and rationale]

### Research Findings
- [Relevant finding from current ZK/crypto landscape]
- [What similar protocols do differently and why]

### Security Considerations
- [Risk and mitigation]

### Rejected Alternatives
- [Alternative approach and why it was rejected]

### Affected Repos
- [ ] stx-circuit — [what changes]
- [ ] sdk — [what changes]
- [ ] pool — [what changes]
- [ ] compliance — [what changes]
- [ ] relayer — [what changes]

### Open Questions
- [Anything that needs team input before proceeding]
```

## Important

- Do NOT write any code or tests during this review
- Do NOT skip the web research step — the whole point is catching what static analysis misses
- If the research reveals that the feature as described has a fundamental design flaw, say so clearly
- If a novel or more efficient approach exists, recommend it even if it differs significantly from the original request
- After this review is accepted, proceed to `/feat` for TDD implementation
