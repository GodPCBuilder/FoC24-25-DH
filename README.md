---

# Digital Signature Server (DSS)

The **Digital Signature Server (DSS)** is a secure client-server application written in **C**, leveraging the **OpenSSL library** to implement cryptographic protocols for key management and digital signing.

It provides a controlled environment for organizations or individuals to securely generate, store, and use digital keys, while ensuring **confidentiality, integrity, and authenticity** of all communications.

---

## 🔑 Features

* **Key Generation**:
  RSA-3072 public/private key pair creation, unique per user.
* **Public Key Retrieval**:
  Clients can request and retrieve public keys securely.
* **Digital Signature**:
  Server signs a document hash with the client’s private key.
* **Key Deletion**:
  Users can delete their key pair (requires re-registration offline).
* **Session Security**:
  Sessions are encrypted and authenticated using modern cryptographic standards.

---

## 🛠️ Architecture

The system follows a **client-server architecture** over TCP sockets, secured through a layered protocol:

* **Key Exchange**: Ephemeral Diffie-Hellman (RFC 7919, ffdhe2048)
* **Authentication**: RSA-3072 digital signatures (server authentication with nonce protection)
* **Encryption**: AES-256 in Galois/Counter Mode (GCM) for authenticated encryption
* **Password Security**: SHA-256 with per-user salts for password hashing

This design ensures **perfect forward secrecy**, prevents replay attacks, and provides a tamper-resistant communication channel.

---

## ⚙️ Protocol Flow

1. **Authentication Phase**

   * Client submits username and nonce
   * Server signs `(PubKeyServer || Nonce)` with RSA-3072
   * Ephemeral Diffie-Hellman establishes session key
   * Client sends password encrypted under the session key

2. **Application Phase**

   * Key creation (if not existing)
   * Public key retrieval
   * Signature requests (document hash signing)
   * Key deletion
   * Session closure

Each request and response is exchanged in an **encrypted and authenticated message format**.

---

## 📦 Dependencies

* **Language**: C
* **Libraries**:

  * [OpenSSL](https://www.openssl.org/) (RSA, AES-GCM, SHA-256, EDH)
  * Standard C libraries (sockets, I/O, etc.)

---

## 🚀 Installation & Usage

### 1. Clone the repository

```bash
git clone https://github.com/your-username/digital-signature-server.git
cd digital-signature-server
```

### 2. Build the project

```bash
gcc -o server server.c -lssl -lcrypto
gcc -o client client.c -lssl -lcrypto
```

### 3. Run server and client

```bash
./server
./client
```

Clients will connect to the server via TCP sockets, performing authentication and secure operations.

---

## 🔮 Future Extensions

* Integration with **digital certificates (X.509)**
* **Audit logging** for compliance and accountability
* Support for **multiple signature algorithms** (e.g., ECDSA)
* Enhanced **user management and key policies**

---

## 📚 Context

This project was developed as part of the **Master’s degree in Cybersecurity** at the **University of Pisa**.
It demonstrates a practical, standards-based implementation of secure digital identity management using **C and OpenSSL**.

---
