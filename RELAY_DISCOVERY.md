# Relay Discovery & ZK-Gossip Protocol Design

## Overview

MortusOS Relay implements a privacy-first relay discovery protocol that maintains anonymity while enabling decentralized network formation. Unlike traditional gossip protocols that leak metadata, our ZK-Gossip protocol uses zero-knowledge proofs for relay discovery and reputation.

## Core Principles

1. **Zero Metadata Leakage** - No relay identities or locations revealed during discovery
2. **Censorship Resistance** - No central authority controls the relay list
3. **Sybil Resistance** - Proof-of-stake/reputation prevents fake relay attacks
4. **Forward Secrecy** - Relay lists can't be reconstructed from captured data
5. **Onion-Only Communication** - All discovery happens over Tor

## Architecture

### 1. Bootstrap Mechanism

```rust
pub struct RelayBootstrap {
    /// Hardcoded seed relays (diversity across jurisdictions)
    seed_relays: Vec<OnionAddress>,
    /// DHT-style distributed discovery
    discovery_dht: KademliaDHT<ZKRelayId>,
    /// Anonymous relay verification
    verification_system: ZKRelayVerifier,
}
```

**Initial Seed List Strategy:**
- 5-7 geographically distributed seed relays
- Operated by different entities/jurisdictions
- Hardcoded in initial release, updatable via consensus
- Each seed relay cryptographically signed and verified

### 2. ZK-Gossip Protocol

#### Relay Advertisement
```rust
pub struct RelayAdvertisement {
    /// Anonymous relay identifier (ZK proof of valid key)
    relay_id: ZKRelayId,
    /// Onion service address (encrypted)
    onion_address: EncryptedOnion,
    /// Capability proof (what services this relay provides)
    capability_proof: ZKCapabilityProof,
    /// Reputation proof (without revealing history)
    reputation_proof: ZKReputationProof,
    /// Network stake proof (prevents Sybil attacks)
    stake_proof: ZKStakeProof,
    /// Timestamp (anonymous, prevents replay)
    anonymous_timestamp: AnonymousTimestamp,
}
```

#### Discovery Process
1. **Anonymous Query**: Client sends ZK proof of legitimate interest
2. **Capability Matching**: Relays respond with capability proofs
3. **Reputation Verification**: Verify relay reputation without revealing metrics
4. **Connection Establishment**: Forward-secret connection setup

### 3. Anonymous Reputation System

```rust
pub struct AnonymousReputationSystem {
    /// Reputation without identity linkage
    reputation_tree: MerkleTree<AnonymousReputation>,
    /// Zero-knowledge reputation proofs
    reputation_proofs: ZKReputationEngine,
    /// Distributed consensus on reputation updates
    consensus_engine: ByzantineFaultTolerant,
}
```

**Reputation Metrics (Anonymous):**
- Uptime percentage (proven via ZK)
- Response time percentiles (anonymous aggregation)
- Data integrity score (cryptographic verification)
- Privacy compliance score (automated verification)

### 4. Consensus Mechanism

**Byzantine Fault Tolerant Consensus** for:
- Relay admission to network
- Reputation score updates
- Network policy changes
- Seed relay updates

```rust
pub struct RelayConsensus {
    /// Minimum 2/3 consensus for network changes
    consensus_threshold: f64, // 0.67
    /// Anonymous voting via ZK proofs
    voting_system: ZKVotingSystem,
    /// Slashing for malicious behavior
    slashing_conditions: SlashingRules,
}
```

## Implementation Plan

### Phase 1: Basic Tor Integration
```rust
// Add to network/mod.rs
pub struct TorManager {
    /// Tor controller for onion service management
    tor_controller: TorController,
    /// Hidden service configuration
    hidden_service: HiddenServiceConfig,
    /// Circuit management for relay discovery
    circuit_manager: CircuitManager,
}
```

### Phase 2: ZK-Gossip Protocol
```rust
// New module: network/discovery.rs
pub struct ZKGossipProtocol {
    /// Anonymous relay discovery
    discovery_engine: RelayDiscoveryEngine,
    /// ZK proof generation for relay advertisements
    advertisement_system: ZKAdvertisementSystem,
    /// Reputation verification without disclosure
    reputation_verifier: AnonymousReputationVerifier,
}
```

### Phase 3: Reputation & Consensus
```rust
// New module: consensus/mod.rs
pub struct DistributedConsensus {
    /// Byzantine fault tolerant consensus
    bft_consensus: ByzantineConsensus,
    /// Anonymous reputation tracking
    reputation_system: AnonymousReputationSystem,
    /// Slashing for malicious behavior
    slashing_engine: SlashingEngine,
}
```

## Message Types

### Discovery Messages (Over Tor)
```json
{
  "type": "RELAY_DISCOVERY_REQUEST",
  "zk_proof": "<proof of legitimate client>",
  "capability_requirements": ["post_quantum", "zk_auth"],
  "reputation_threshold": 80
}

{
  "type": "RELAY_ADVERTISEMENT",
  "relay_id": "<anonymous ZK relay ID>",
  "onion_address": "<encrypted onion address>",
  "capability_proof": "<ZK proof of capabilities>",
  "reputation_proof": "<ZK proof of reputation>",
  "stake_proof": "<proof of network stake>"
}
```

### Consensus Messages
```json
{
  "type": "REPUTATION_UPDATE",
  "relay_id": "<anonymous relay ID>",
  "reputation_delta": "+5",
  "evidence": "<cryptographic proof>",
  "consensus_votes": ["<zk_vote_1>", "<zk_vote_2>"]
}
```

## Security Considerations

### Against Traffic Analysis
- **Onion routing mandatory** for all discovery traffic
- **Dummy traffic injection** to obscure discovery patterns
- **Random delays** in discovery responses
- **Circuit rotation** for each discovery operation

### Against Sybil Attacks
- **Proof of stake** requirement for relay operators
- **Reputation decay** over time requiring continuous good behavior
- **Geographic distribution enforcement** via consensus
- **Resource requirements** (computational and bandwidth)

### Against Censorship
- **No single point of failure** in discovery
- **Multiple bootstrap paths** via different seed strategies
- **Consensus-based seed updates** prevent capture
- **Fallback discovery mechanisms** (DHT, I2P backup)

## Implementation Priority

1. **[HIGH]** Basic Tor onion service integration
2. **[HIGH]** Simple seed relay bootstrap mechanism  
3. **[MEDIUM]** ZK-based relay advertisement system
4. **[MEDIUM]** Anonymous reputation tracking
5. **[LOW]** Full Byzantine consensus implementation

This provides a roadmap for building a truly privacy-first relay discovery network that maintains the security goals of MortusOS while enabling decentralized operation.