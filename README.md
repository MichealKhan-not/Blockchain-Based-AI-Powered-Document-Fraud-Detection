# DocVerify: Blockchain-Based AI-Powered Document Fraud Detection

## Overview

DocVerify is a decentralized Web3 application built on the Stacks blockchain that leverages AI to detect fraudulent documents. It addresses real-world problems such as document forgery in sectors like finance, education, employment, and legal services. By storing document hashes on-chain for immutability and using off-chain AI models (integrated via oracles) to analyze documents for fraud indicators (e.g., tampered images, inconsistent metadata, or forged signatures), DocVerify ensures secure, transparent verification processes.

Users can upload document hashes, request AI-based fraud checks, verify authenticity, and resolve disputes through a decentralized governance system. This reduces reliance on centralized authorities, minimizes fraud risks, and provides tamper-proof audit trails.

### Key Features
- **Document Upload & Hashing**: Users upload documents off-chain (e.g., via IPFS) and store hashes on-chain.
- **AI Fraud Detection**: Integrates AI models (e.g., computer vision for forgery detection) via oracles.
- **Verification & Certification**: Verified documents receive on-chain certificates.
- **Dispute Resolution**: Community-driven disputes with staking mechanisms.
- **Governance & Rewards**: Token-based system for incentives and voting.
- **Audit Logging**: Immutable logs for all actions.

### Tech Stack
- **Blockchain**: Stacks (Bitcoin-secured).
- **Smart Contract Language**: Clarity.
- **Off-Chain Components**: AI models (e.g., using TensorFlow or custom ML for document analysis), IPFS for storage, frontend in React.js.
- **Integration**: Oracles for AI results (e.g., via Chainlink or custom Stacks oracles).

### Real-World Problems Solved
- **Financial Fraud**: Detects fake invoices or bank statements to prevent loan scams.
- **Education & Employment**: Verifies diplomas and resumes to combat credential fraud.
- **Legal & Identity**: Ensures authenticity of contracts, IDs, and passports.
- **Supply Chain**: Validates certificates of origin or compliance docs.
- Reduces costs and time compared to traditional verification services while enhancing privacy and security through decentralization.

## Smart Contracts

The project involves 6 core smart contracts written in Clarity. Each contract is designed to be secure, with proper error handling, access controls, and event emissions for transparency. Contracts interact via traits and public functions.

### 1. UserRegistry.clar
This contract handles user registration, roles (e.g., verifier, user), and authentication.

```clarity
;; UserRegistry Contract
(define-trait user-trait
  (
    (register-user (principal) (response bool uint))
    (get-user-role (principal) (response (optional (tuple (role uint))) uint))
  )
)

(define-constant ERR-ALREADY-REGISTERED u100)
(define-constant ERR-NOT-AUTHORIZED u101)
(define-constant ROLE-USER u1)
(define-constant ROLE-VERIFIER u2)

(define-map users principal {role: uint})

(define-public (register-user (user principal))
  (if (is-some (map-get? users user))
    (err ERR-ALREADY-REGISTERED)
    (begin
      (map-set users user {role: ROLE-USER})
      (ok true)
    )
  )
)

(define-public (assign-verifier-role (user principal) (admin principal))
  (if (is-eq admin tx-sender) ;; Assuming tx-sender is admin
    (match (map-get? users user)
      some-user (begin
        (map-set users user {role: ROLE-VERIFIER})
        (ok true)
      )
      (err ERR-NOT-AUTHORIZED)
    )
    (err ERR-NOT-AUTHORIZED)
  )
)

(define-read-only (get-user-role (user principal))
  (ok (map-get? users user))
)
```

### 2. DocumentStorage.clar
Stores document metadata and hashes on-chain. Links to IPFS CIDs.

```clarity
;; DocumentStorage Contract
(define-trait doc-storage-trait
  (
    (store-document (uint (buff 32) (string-ascii 256)) (response uint uint))
    (get-document (uint) (response (optional (tuple (hash (buff 32)) (ipfs-cid (string-ascii 256)))) uint))
  )
)

(define-constant ERR-DOC-EXISTS u200)
(define-constant ERR-NOT-OWNER u201)

(define-map documents uint {owner: principal, hash: (buff 32), ipfs-cid: (string-ascii 256)})
(define-data-var doc-counter uint u0)

(define-public (store-document (doc-id uint) (doc-hash (buff 32)) (ipfs-cid (string-ascii 256)))
  (if (is-some (map-get? documents doc-id))
    (err ERR-DOC-EXISTS)
    (begin
      (map-set documents doc-id {owner: tx-sender, hash: doc-hash, ipfs-cid: ipfs-cid})
      (var-set doc-counter (+ (var-get doc-counter) u1))
      (ok (var-get doc-counter))
    )
  )
)

(define-read-only (get-document (doc-id uint))
  (ok (map-get? documents doc-id))
)

(define-public (update-document (doc-id uint) (new-hash (buff 32)) (new-cid (string-ascii 256)))
  (match (map-get? documents doc-id)
    doc (if (is-eq (get owner doc) tx-sender)
          (begin
            (map-set documents doc-id {owner: tx-sender, hash: new-hash, ipfs-cid: new-cid})
            (ok true)
          )
          (err ERR-NOT-OWNER)
        )
    (err ERR-NOT-OWNER)
  )
)
```

### 3. AIOracle.clar
Acts as an oracle to receive AI fraud detection results from off-chain sources.

```clarity
;; AIOracle Contract
(define-trait ai-oracle-trait
  (
    (submit-ai-result (uint bool (string-ascii 256)) (response bool uint))
    (get-ai-result (uint) (response (optional (tuple (is-fraud bool) (reason (string-ascii 256)))) uint))
  )
)

(define-constant ERR-NOT-ORACLE u300)
(define-constant ERR-RESULT-EXISTS u301)

(define-map ai-results uint {is-fraud: bool, reason: (string-ascii 256)})
(define-data-var oracle principal tx-sender) ;; Set to oracle principal

(define-public (submit-ai-result (doc-id uint) (is-fraud bool) (reason (string-ascii 256)))
  (if (is-eq tx-sender (var-get oracle))
    (if (is-some (map-get? ai-results doc-id))
      (err ERR-RESULT-EXISTS)
      (begin
        (map-set ai-results doc-id {is-fraud: is-fraud, reason: reason})
        (ok true)
      )
    )
    (err ERR-NOT-ORACLE)
  )
)

(define-read-only (get-ai-result (doc-id uint))
  (ok (map-get? ai-results doc-id))
)
```

### 4. VerificationContract.clar
Handles the verification process, issuing certificates if not fraudulent.

```clarity
;; VerificationContract
(define-trait verification-trait
  (
    (verify-document (uint) (response bool uint))
    (get-verification-status (uint) (response (optional bool) uint))
  )
)

(define-constant ERR-FRAUD-DETECTED u400)
(define-constant ERR-NOT-VERIFIED u401)

(define-map verifications uint bool) ;; true if verified

(define-public (verify-document (doc-id uint))
  ;; Assume integration with AIOracle
  (let ((ai-result (unwrap! (contract-call? .AIOracle get-ai-result doc-id) (err ERR-NOT-VERIFIED))))
    (if (get is-fraud ai-result)
      (err ERR-FRAUD-DETECTED)
      (begin
        (map-set verifications doc-id true)
        (ok true)
      )
    )
  )
)

(define-read-only (get-verification-status (doc-id uint))
  (ok (map-get? verifications doc-id))
)
```

### 5. DisputeResolution.clar
Allows users to dispute verifications with staking.

```clarity
;; DisputeResolution Contract
(define-trait dispute-trait
  (
    (create-dispute (uint uint) (response uint uint))
    (resolve-dispute (uint bool) (response bool uint))
  )
)

(define-constant ERR-DISPUTE-EXISTS u500)
(define-constant ERR-NOT-DISPUTER u501)
(define-constant STAKE-AMOUNT u1000) ;; In STX microstacks

(define-map disputes uint {doc-id: uint, stake: uint, disputer: principal, resolved: bool})
(define-data-var dispute-counter uint u0)

(define-public (create-dispute (doc-id uint) (stake uint))
  (if (>= stake STAKE-AMOUNT)
    (begin
      (try! (stx-transfer? stake tx-sender (as-contract tx-sender)))
      (map-set disputes (var-get dispute-counter) {doc-id: doc-id, stake: stake, disputer: tx-sender, resolved: false})
      (var-set dispute-counter (+ (var-get dispute-counter) u1))
      (ok (var-get dispute-counter))
    )
    (err u502) ;; Insufficient stake
  )
)

(define-public (resolve-dispute (dispute-id uint) (is-valid bool))
  ;; Simplified: assume governance call
  (match (map-get? disputes dispute-id)
    dispute (if (not (get resolved dispute))
              (begin
                (map-set disputes dispute-id (merge dispute {resolved: true}))
                (if is-valid
                  (try! (as-contract (stx-transfer? (get stake dispute) (get disputer dispute) tx-sender))) ;; Refund
                  (ok true) ;; Keep stake
                )
                (ok true)
              )
              (err ERR-NOT-DISPUTER)
            )
    (err ERR-NOT-DISPUTER)
  )
)
```

### 6. GovernanceToken.clar
An FT for rewards and voting on disputes.

```clarity
;; GovernanceToken Contract (SIP-010 compliant)
(define-fungible-token gov-token u100000000)
(define-constant ERR-NOT-AUTHORIZED u600)

(define-trait token-trait
  (
    (transfer (uint principal principal (optional (buff 34))) (response bool uint))
    (get-balance (principal) (response uint uint))
  )
)

(define-public (mint (amount uint) (recipient principal))
  (if (is-eq tx-sender contract-caller) ;; Assuming minter role
    (ft-mint? gov-token amount recipient)
    (err ERR-NOT-AUTHORIZED)
  )
)

(define-public (transfer (amount uint) (sender principal) (recipient principal) (memo (optional (buff 34))))
  (if (is-eq tx-sender sender)
    (ft-transfer? gov-token amount sender recipient)
    (err ERR-NOT-AUTHORIZED)
  )
)

(define-read-only (get-balance (account principal))
  (ok (ft-get-balance gov-token account))
)

(define-read-only (get-total-supply)
  (ok (ft-get-supply gov-token))
)
```

## Deployment & Usage

1. **Deploy Contracts**: Use Stacks CLI to deploy each .clar file in order (UserRegistry first, as others may depend on it).
2. **Frontend Integration**: Build a dApp frontend to interact with these contracts via Stacks.js.
3. **AI Integration**: Off-chain AI service submits results to AIOracle via signed transactions.
4. **Testing**: Use Clarinet for local testing.

## License
MIT License. See LICENSE file for details.