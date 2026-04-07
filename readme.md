# 🔐 HIPAA-Compliant Data Anonymization Service (.NET Core)

![.NET](https://img.shields.io/badge/.NET-8.0%2B-blueviolet)
![Security](https://img.shields.io/badge/Security-AES--GCM-success)
![Cryptography](https://img.shields.io/badge/Cryptography-HMACSHA256-success)
![Compliance](https://img.shields.io/badge/Compliance-HIPAA-critical)

A robust, enterprise-grade cryptographic service built in ASP.NET Core for securing Personally Identifiable Information (PII) and Protected Health Information (PHI) in relational databases.

## 🚨 The Problem

Storing sensitive medical data (like National IDs, Phone Numbers, and Names) in plaintext violates strict healthcare regulations such as HIPAA. A compromised database directly leads to identity exposure. This repository demonstrates a highly secure architectural pattern to ensure that stolen database records remain mathematically unreadable.

## 💡 The Solution: A Two-Pronged Cryptographic Architecture

Not all database fields serve the same purpose. This service implements two distinct strategies based on data usage requirements.

### 1️⃣ Deterministic Hashing (For Searchable Data)

For fields requiring exact-match queries (e.g., searching for a patient by `NationalId`), two-way encryption degrades database index performance and adds unnecessary complexity.

- **Implementation:** `HMACSHA256`
- **Mechanism:** Uses a server-side secret key to hash normalized data.
- **Advantage:** Allows `WHERE NationalIdHash = @hash` queries while neutralizing Rainbow Table attacks if the database is leaked.

### 2️⃣ Authenticated Encryption (For Recoverable Data)

For data that must be read and displayed back to the UI (e.g., `Phone`, `Address`), hashing is impossible.

- **Implementation:** `AES-GCM` (Galois/Counter Mode)
- **Mechanism:** Replaces legacy AES-CBC. It dynamically generates a cryptographically secure, randomized `Nonce` (IV) for _every single row_.
- **Advantage:** Encrypting the same phone number twice yields completely different byte structures, preventing pattern recognition. The included Authentication Tag ensures the database payload has not been tampered with.

---

## 🏗️ Implementation Details

### Service Methods

#### Hashing (HMACSHA256)

![Hash Implementation](./docs/images/hash_implementation.png)

#### Encryption & Decryption (AES-GCM)

![Encrypt Implementation](./docs/images/encrypt_implementation.png)
![Decrypt Implementation](./docs/images/decrypt_implementation.png)

---

## 🚀 Getting Started

### 1. Generate a Secure AES Key (Developer Utility)

Do **NOT** use hardcoded keys in production. To generate a cryptographically secure 32-byte key for your local environment, use the included utility method.

In your `Program.cs` (Development environment only):

```csharp
// Run once, copy the output from the console, then DELETE this line.
string localAesKey = AnonymizationService.GenerateAesKey();
```
