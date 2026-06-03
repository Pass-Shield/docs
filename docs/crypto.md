# [RFC-001] Zero-Knowledge Key Hierarchy and Derivation Protocol

---

| Metadata | Details                             |
| :--- |:----------------------------------------|
| **Document ID** | PSHD-ZKA-01                  |
| **Status** | `PROPOSED`                        |
| **Authors** | Patryk Krawczyk (@astrohack)     |
| **Created** | 2026-04-10                       |
| **Updated** | 2026-04-10                       |
| **Version** | 1.0.0                            |

---

## Abstract

This document specifies the cryptographic architecture, key management, and data model for a Zero-Knowledge (ZK) vault system. The protocol mandates client-side-only encryption using an **Envelope Encryption** and **Key Wrapping**. It enables secure password storage, metadata protection (`is_breached`, `entropy`, etc.), and account recovery without compromising the ZK principle.

---

## 1. Introduction

### 1.1 Design Principles
- **Zero-Knowledge:** The server MUST NOT have access to the USK or any plaintext secrets.
- **Client-Side Derivation:** All key derivation (KDF) MUST occur on the client.
- **Envelope Encryption:** Each item is encrypted with a unique Data Encryption Key (DEK).
- **Recovery:** Recovery keys MUST be independent of the Master Password.

---

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

### 2.1 Cryptographic Definitions
| Term | Definition |
| :--- | :--- |
| **Master Password** | High-entropy user secret; the source of truth for daily access. |
| **Master Key (MK)** | Ephemeral 256-bit key derived via **Argon2id**. Used solely to wrap/unwrap the USK. |
| **User Symmetric Key (USK)** | Permanent, random 256-bit root key. Acts as the **Key Encrypting Key (KEK)** for the entire vault. |
| **Recovery Key (RSK)** | Randomly generated 256-bit key, presented to the user as a mnemonic or Base32 string. |
| **Item Key (DEK)** | Random AES-256-GCM key unique to a single vault entry. |
| **AEAD** | Authenticated Encryption with Associated Data, specifically **AES-256-GCM**. |

---

## 3. Architecture Overview

### 3.1 Key Hierarchy

```mermaid
graph LR
%% --- node definitions ---
   MP["Master Password<br/>(User Input)"]:::source
   Salt["Salt<br/>(from Server)"]:::source
   RSK["Recovery Key (RSK)<br/>(Static Passphrase)"]:::source

   MK[["Master Key (MK)<br/>(Ephemeral Session Key)"]]:::session

   USK(("USER SYMMETRIC KEY (USK)<br/>(Static Root KEK)")):::root

   DEK[["Item Key (DEK)<br/>(Per-item AES Key)"]]:::dek

   Data["Sensitive Item Data"]:::data

%% --- processes---
   Argon2id[["Argon2id KDF"]]:::op
   WrapP[["Wrap/Unwrap<br/>(AES-GCM)"]]:::op
   WrapR[["Wrap/Unwrap<br/>(AES-GCM)"]]:::op
   EncDEK[["Encrypt/Decrypt<br/>(AES-GCM)"]]:::op
   EncData[["Encrypt/Decrypt<br/>(AES-GCM)"]]:::op

%% --- connections ---
   MP & Salt --> Argon2id --> MK
   MK --> WrapP --> USK
   RSK --> WrapR --> USK
   USK --> EncDEK --> DEK
   DEK --> EncData --> Data

%% --- style ---
   classDef source fill:#fbc02d,color:#000,stroke:#f9a825,stroke-width:2px;
   classDef session fill:#3f51b5,color:#fff,stroke:#1a237e,stroke-width:2px;
   classDef root fill:#d32f2f,color:#fff,stroke:#b71c1c,stroke-width:3px;
   classDef dek fill:#388e3c,color:#fff,stroke:#1b5e20,stroke-width:2px;
   classDef data fill:#616161,color:#fff,stroke:#424242;
   classDef op fill:none,stroke:#9e9e9e,stroke-dasharray: 5 5,color:#757575;

   linkStyle default stroke:#757575,stroke-width:1px;
   linkStyle 3,5 stroke:#d32f2f,stroke-width:2px;
```
---

### 3.2. Cryptographic Primitives

All implementations MUST use:

| Primitive               | Algorithm                          | Parameters                  |
|-------------------------|------------------------------------|-----------------------------|
| Key Derivation          | Argon2id                           | -                           |
| Symmetric Encryption    | AES-256-GCM                        | 96-bit nonce, 128-bit tag   |
| Asymmetric Keys         | X25519 (preferred) or RSA-2048     | –                           |
| Hashing                 | SHA-256 / SHA-512                  | –                           |
| MAC / Integrity         | Included in AEAD                   | –                           |

---

## 4. Key Derivation
```mermaid
flowchart TD
    subgraph CLIENT ["CLIENT (Frontend)"]
        direction TB

        subgraph S_KEYS ["1. Access Sources"]
            MP["Master Password<br/>(User Input)"]
            RSK["Recovery Key (RSK)<br/>(Generated once, 32 chars)"]
        end

        subgraph S_DERIVATION ["2. Derivation & Generation"]
            MP -->|Argon2id| PW_K["Password-Derived Key<br/>(Ephemeral Session Key)"]
            USK_RAW["USER SYMMETRIC KEY (USK)<br/>(Static, Random 256-bit)"]
        end

        subgraph S_WRAPPING ["3. Key Wrapping"]
            PW_K -->|AES-256-GCM| WRAP_P["Wrapped USK (by Password)"]
            RSK -->|AES-256-GCM| WRAP_R["Wrapped USK (by RSK)"]
        end

        subgraph S_DATA ["4. Data Encryption"]
            USK_RAW -->|Encrypts| ITEM_K["Item Key (DEK)"]
            ITEM_K -->|Encrypts| PAYLOAD["Item Payload (AES-GCM)"]
        end
    end

%% Data Flow
    WRAP_R -->|HTTPS POST| SRV_AUTH
    WRAP_P -->|HTTPS POST| SRV_AUTH
    ITEM_K -->|HTTPS POST| SRV_VAULT
    PAYLOAD -->|HTTPS POST| SRV_VAULT

    subgraph SERVER ["SERVER (Encrypted Storage)"]
        direction TB
        subgraph SRV_AUTH ["Auth Service / DB"]
            S2["blob: Encrypted USK (RSK)"]
            S1["blob: Encrypted USK (Pass)"]
        end
        subgraph SRV_VAULT ["Vault Service / DB"]
            S3["blob: Encrypted Item Keys"]
            S4["blob: Encrypted Items"]
        end
    end

%% Theme-Aware Styling (Contrast optimized for Dark/Light)
    style MP fill:#303f9f,color:#fff,stroke:#1a237e
    style RSK fill:#fbc02d,color:#000,stroke:#f9a825
    style USK_RAW fill:#d32f2f,color:#fff,stroke:#b71c1c,stroke-width:3px
    style S1 fill:#455a64,color:#fff,stroke:#26323
```

**Registration Flow (MUST):**
1. User enters **Master Password**.
2. Client derives **Master-Password-Derived Key (MK)** using Argon2id.
3. Client generates Random 256-bit as **User Symmetric Key (USK)** (`enc_usk_password`).
4. Client generates **asymmetric key pair (private_key + `public_key`)**.
5. Client generates a cryptographically secure random **Recovery Symmetric Key (RSK)** – 32 bytes (256 bits).
6. Client encrypts the **USK** using the **RSK** (AES-256-GCM) (`enc_usk_recovery`).
7. Client encrypts the user's **asymmetric private key** using the USK (`enc_private_key`).
8. Client displays the **Recovery Key (RSK)** to the user in a human-readable format (e.g. 32-character base58 or 4 groups of 8 characters) together with a QR code and a strong warning to store it securely offline.

Server receives and stores:
- `public_key` (plaintext)
- `enc_usk_password` (encrypted by MK)
- `enc_private_key` (encrypted by USK)
- `enc_usk_recovery` (encrypted by Recovery Key (RSK))
- `rsk_fingerprint` (RSK MUST be derived using Argon2id – used for verification)

### 4.3 Normal Operation (Daily Use)

- User provides Master Password.
- Client derives Master Key (MK) using Argon2id from Master Password.
- Client use MK to decrypt wrapped USK.
- USK is used to decrypt all `encrypted_item_key` values.
- All subsequent operations (decrypting items, custom fields including `meta_is_breached`, `meta_entropy`, `meta_semantic_category`) proceed as defined in Section 5.

```mermaid
sequenceDiagram
    participant U as User
    participant C as Client App
    participant S as Vault Server

    U->>C: Provide Master Password
    C->>S: GET /auth/keys
    S-->>C: enc_usk_password
    
    Note over C: Derive MK via Argon2id<br/>Decrypt USK using MK
    
    C->>S: GET /vault/items
    S-->>C: encrypted_items, encrypted_item_keys
    
    Note over C: For each vault item:<br/>1. Decrypt DEK using USK<br/>2. Decrypt item payload using DEK
    
    C->>U: Render plaintext vault
```

### 4.4 Recovery Flow (Forgotten Master Password)

1. User provides the **Recovery Key (RSK)** (typed or scanned from QR).
2. Client generates `rsk_fingerprint` and server verifies it.
3. Client decrypts `enc_usk_recovery` using the provided RSK → obtains original USK.
4. With the recovered USK, client can decrypt all Item Keys and the entire vault content.
5. User is prompted to set a **new Master Password**.
6. Client derives a new USK from the new **MK**.
7. Client re-encrypts the old USK with the new USK.
8. (Optional but recommended) Client generates a **new Recovery Key (RSK)**, encrypts the new USK with it, and asks the user to store the new key.

After successful recovery, the old `enc_usk_recovery` may be replaced with a new one.

```mermaid
sequenceDiagram
    participant U as User
    participant C as Client App
    participant S as Vault Server

    U->>C: Provide Recovery Key (RSK)
    C->>S: POST /auth/recovery/init
    Note right of C: Payload: rsk_fingerprint
    S-->>C: enc_usk_recovery
    
    Note over C: Decrypt USK using RSK
    
    U->>C: Provide New Master Password
    
    Note over C: Derive new MK via Argon2id<br/>Encrypt recovered USK with new MK
    
    C->>S: POST /auth/keys/update
    Note right of C: Payload: new enc_usk_password
    S-->>C: 200 OK
```

### 4.5 Database

The following fields SHOULD be present at `users` table:

| Column                  | Type | Nullable | Description                                                                         |
|:------------------------| :--- | :--- |:------------------------------------------------------------------------------------|
| **id**                  | `UUID` | No | Primary key. Unique identifier for the user.                                        |
| **email**               | `String` | No | Unique user identifier for authentication.                                          |
| **kdf_salt**            | `String` | No | Cryptographic salt used for Argon2id key derivation.                                |
| **kdf_params**          | `JSONB` | No | Configuration for KDF (iterations, memory, parallelism).                            |
| **enc_usk_password**    | `Blob/Text` | No | **USK** wrapped by the Password-Derived Key (AES-256-GCM).                          |
| **enc_usk_recovery**    | `Blob/Text` | No | **USK** wrapped by the **Recovery Key (RSK)** (AES-256-GCM).                        |
| **public_key**          | `Text` | No | User's public asymmetric key (RSA-2048 or X25519) in Base64.                        |
| **enc_private_key**     | `Blob/Text` | No | User's private asymmetric key, **encrypted by USK**.                                |
| **rsk_fingerprint**     | `String` | No | RSK derived using Argon2Id for verification without storage.                        |
| **rsk_fingerprint_salt** | `String` | No | Salt used to derive `rsk_fingerprint`                                               |
| **rsk_created_at**      | `Timestamp` | No | Audit timestamp of when the recovery key was generated.                             |

### 4.6 Security Considerations – Recovery Key (RSK)

- The Recovery Key **MUST** be generated with a cryptographically secure random number generator.
- The Recovery Key is **NEVER** sent to the server in plaintext.
- The server stores only the encrypted wrapper and a non-reversible fingerprint (derived using Argon2Id with salt).
- Users **MUST** be strongly warned to store the Recovery Key in a safe, offline location (e.g. printed Emergency Kit, password manager backup, physical safe).
- After using the Recovery Key, it is **RECOMMENDED** to generate and store a new one (key rotation).
- Compromise of the Recovery Key alone does not grant access without the encrypted vault data.

---


## 5. Item Encryption (Create / Update)

**Per-Item Encryption (REQUIRED):**

1. Client generates fresh random **Item Key** (32 bytes).
2. Client encrypts **all sensitive data** with Item Key using AES-256-GCM:
    - login
    - password
    - notes
    - **all custom field values** (`meta_is_breached`, `meta_entropy`, `meta_semantic_category`, etc.)
3. Client includes **Associated Data (AD)** in AEAD:
    - `item_id|user_id|field_name|revision_timestamp`
4. Client encrypts the Item Key itself with USK → `encrypted_item_key`.
5. Client sends to Vault Service only:
    - `encrypted_item_key`
    - `encrypted_data`
    - plaintext structural metadata (`folder_id`, `is_favorite`, timestamps)

Server **NEVER** receives plaintext or Item Key in the clear.

---

## 6. Custom Fields and Metadata Encryption

All custom fields **MUST** be encrypted exactly like the password:

- Field `name` (e.g. `meta_is_breached`) → stored in plaintext (for UI filtering).
- Field `value` → encrypted with the Item Key (AEAD).
- Supported types: Text, Hidden, Boolean.

**Recommended prefix convention:**
- `meta_is_breached`
- `meta_entropy`
- `meta_semantic_category`
- `meta_last_hibp_check`

---

## 7. Single-Item Sharing

**Sharing Protocol (MUST implement):**

1. Owner (A) requests sharing with user B.
2. Client A:
    - Decrypts Item Key locally using own USK.
    - Fetches B’s `public_key`.
    - Re-encrypts the **same Item Key** with B’s public key (asymmetric).
3. Server stores additional record: e.g. `shared_item_key_for_b` (encrypted with B’s public key).
4. User B:
    - Decrypts shared Item Key with own private key (decrypted by B’s USK).
    - Decrypts item data normally.

No re-encryption of the entire item is required.

```mermaid
sequenceDiagram
    participant A as Client A (Owner)
    participant S as Vault Server
    participant B as Client B (Recipient)

    A->>S: GET /users/{B_id}/public-key
    S-->>A: public_key_B
    
    Note over A: 1. Decrypt DEK using USK_A<br/>2. Encrypt DEK using public_key_B
    
    A->>S: POST /vault/items/{item_id}/share
    Note right of A: Payload:<br/>- target_user_id: B_id<br/>- encrypted_dek_for_B
    S-->>A: 200 OK
    
    B->>S: GET /vault/items/{item_id}
    S-->>B: encrypted_payload, encrypted_dek_for_B, enc_private_key
    
    Note over B: 1. Decrypt Private Key using USK_B<br/>2. Decrypt DEK using Private Key<br/>3. Decrypt payload using DEK
```

---

## 8. Database Schema (Summary)

See Section 10 of the companion document “SPM-ZKAI Database Schema” for full PostgreSQL schema with four schemas: `vault`, `security`, `audit`, `ai`.

Key tables:
- `vault.items` – `encrypted_item_key`, `encrypted_data`
- `vault.item_custom_fields` – encrypted `value`
- `security.breach_events`
- `audit.audit_logs`
- `ai.recommendations`

---

## 9. Security Considerations

- Server compromise yields only ciphertext.
- Per-item keys limit blast radius.
- AEAD prevents cut-and-paste attacks.
- Asymmetric sharing prevents key reuse.
- Audit log is immutable and tamper-evident.
- All custom metadata (`is_breached`, `entropy`, etc.) is encrypted.

---

## 10. References

- Bitwarden Security Whitepaper (2024)
- RFC 8446 (TLS 1.3)
- RFC 5869 (HKDF)
- Argon2 Specification (RFC 9106)
- NIST SP 800-63B

---

**Appendix A – Example JSON Item Structure (after client encryption)**

```json
{
  "id": "uuid",
  "encrypted_item_key": "2.aes256-gcm|...|...",
  "encrypted_data": "2.aes256-gcm|...|...",
  "folder_id": "uuid",
  "custom_fields": [
    { "name": "meta_is_breached", "value": "2.aes256-gcm|...|..." }
  ]
}
```
**Appendix B – Recovery Key Display Example**
```
Your Recovery Key (store this safely!):

X7K9-P4M2-Q8V6-L3N1-R9T5-B2H7-J4W8-F6G3

This key allows full vault recovery if you forget your Master Password.
It will NOT be shown again.
```
