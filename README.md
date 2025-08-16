# Universal Inter-Blockchain Communication Protocol (UIBCP)

## Overview
UIBCP is a chain-agnostic messaging protocol designed to enable secure and cost-efficient interoperability across blockchains. It leverages ZK-STARKs for proof verification and an optimistic dual-proof mechanism with mutual slashing to ensure reliability. Version 1 (V1) targets IBC-EVM compatibility, focusing on token transfers between networks like Sepolia and Cosmos testnets, with a scalable economic model.

## Architecture
- **Rust Components**:
  - `RelayerClient`: Submits messages with ZK proofs and handles optimistic relaying.
  - `ChallengerService`: Monitors relayed messages and submits disputes for detected fraud.
  - `ChainAdapter`: Abstracts chain-specific logic (e.g., EVM, IBC adapters).
- **Solidity Contracts**:
  - `IbcPacketHandler.sol`: Manages packet relaying and relayer bonding.
  - `StarkVerifier.sol`: Verifies ZK-STARK proofs on-chain.
  - `FeeManager.sol`: Handles fee calculations (TBD: integration).
- **Protobuf Schema**: `uibc/v1/uibc.proto` defines `UniversalMessage`, `MessageFees`, and economic structures for cross-chain compatibility.

## Setup
1. **Prerequisites**:
   - Install Rust (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`) and Solidity compiler (`npm install -g solc`).
2. **Clone Repository**:
   - `git clone <repo-url>` (replace `<repo-url>` with your repo).
3. **Build Project**:
   - Navigate to the root directory and run `cargo build` to generate protobuf code.
4. **Configure Testnets**:
   - Set up Sepolia and Cosmos testnet endpoints (TBD: specific RPC URLs and keys).
   - Install dependencies: `cargo install --path .`.

## Usage
- **Run Relayer**:
  - Initialize `RelayerClient` with a `UniversalMessage` (e.g., `TokenTransfer` payload).
  - Example: `cargo run --bin relayer -- --message <message-json>`.
- **Monitor Challenges**:
  - Start `ChallengerService` to watch for fraud: `cargo run --bin challenger`.
- **Deploy Contracts**:
  - Deploy `IbcPacketHandler.sol` and `StarkVerifier.sol` on Sepolia (TBD: deployment scripts).

## Limitations
- **ZK Proof Integration**: `Ics23Prover.prove` is stubbed; output format TBD.
- **Challenger Logic**: `fetch_canonical_proof` and `verify_optimistic_proof` are placeholders, requiring light client integration.
- **Fee Oracle**: Uses `MockFeeOracle`; real-time data (e.g., Chainlink) pending.
- **Testing**: No end-to-end testnet validation yet; edge cases (e.g., timeouts) untested.

## Roadmap
- **V1 (August 2025)**: IBC-EVM relay, basic token transfers, and optimistic economics.
- **V2 (September 2025)**: Multi-chain support (e.g., Solana, Polkadot).
- **V3 (Q4 2025)**: Advanced incentives and performance-based fees.

## Contributing
- Contributions welcome! Please open issues or PRs on the repository (TBD: link).
- Guidelines TBD post-V1.

## License
TBD: Specify license (e.g., MIT, Apache 2.0).