# Secure-Data-Exchange-ANAE-Internship

This is a project form my internship with the minstry of knowledge economy and startups.

This project demonstrates a hybrid encryption system for securely exchanging data (any file type) between two parties — using RSA and AES-GCM, with the encrypted result encoded into a QR code for convenient transfer.
The idea:

- ANAE (Sender) encrypts the entrepreneur’s data and generates a QR code.
- The entrepreneur (User) presents the QR code to DOUANE (Receiver).
- DOUANE (Receiver) scans or imports the QR code (or text) and decrypts it to recover the original file.

---

## ✨ Features

- Supports any input file type (JSON, PDF, image, binary, etc.)
- Accepts any scanned QR or raw text data as input
- Hybrid encryption (AES-GCM + RSA-OAEP256)
- Built-in compression (zlib) for smaller QR codes
- Works fully offline
- Cross-platform Python implementation

## 🚀 How it Works

### 🔄 Flow Diagram (Hybrid Encryption)

```text
          ┌────────────────────────┐
          │        Sender          │
          └────────────┬───────────┘
                       │
               Generate AES key
                       │
         Encrypt file (any format) with AES-GCM
                       │
             Encrypt AES key using
             Receiver's RSA Public Key
                       │
       ┌─────────── Package ───────────────────┐
       │ { encrypted_aes_key, iv, ciphertext } │
       └───────────────────────────────────────┘
                       │
                Convert to QR Code
                       │
                       ▼
          ┌────────────────────────┐
          │       Receiver         │
          └────────────┬───────────┘
                       │
             Scan QR → Extract Envelope
                       │
         Decrypt AES key with RSA Private Key
                       │
          Decrypt ciphertext with AES key
                       │
             Recover the Original File


```

### 🔒 Encryption side (Sender / Encrypter):

1. Generate a random **AES key** (Initialization Vector).
2. Encrypt the JSON data with AES (fast, symmetric encryption).
3. Encrypt the AES key with the **recipient’s RSA public key**.
4. Package everything into a JSON object:
   ```json
   {
     "encrypted_aes_key": "...",
     "ciphertext": "..."
   }
   ```
   5.Convert this package into a QR code for transfer.

### 🔓 Decryption side (Receiver / Decrypter):

1.Scan the QR → extract {encrypted_aes_key, ciphertext}.
2.Use the RSA private key to decrypt encrypted_aes_key.
3.Recover the original AES key.
4.Use AES key to decrypt the JSON payload.
5.Write out the recovered JSON file.

### ⚡ Why Hybrid?

. AES → Super Fast, efficient encryption for any file size.
. RSA → Secure exchange of the AES key without needing a shared secret.
. zlib Compression: Reduces data size before encryption, allowing smaller QR codes.

### 📦 Project Setup

1.Create a Python virtual environment:

```shell
    python -m venv venv
    source venv/bin/activate   # Linux/Mac
    venv\Scripts\activate      # Windows
```

2.Install dependencies:

```shell
pip install -r requirements.txt
```

### Usage

1. Key Management:

- Before encrypting data, you need an RSA keypair.

Generate keys:

```shell
python generate_shared_keys.py --out-dir keys --bits 3072 --encrypt-private

# --out-dir → folder where keys are stored.
# --bits → RSA key size (2048 / 3072 / 4096).
# --encrypt-private → protect private key with a passphrase.

```

- This will create:
  -- keys/private.pem (private key, encrypted with passphrase)
  -- keys/public.pem (public key)

2. Encrypt Any File and Create a QR Code

- Encrypt and generate a QR for any input file:

Run:

```shell
python encrypt_to_qr_shared.py --input-file example.png --out-png encrypted_shared.qr.png
```

- Optionally specify the RSA public key:

```shell
python encrypt_to_qr_shared.py --public-key keys/system_public.pem --input-file report.pdf --out-png encrypted_report.qr.png

```

- This will:
  -- Compress the JSON data with zlib.
  -- Generate a random AES-256 key and 96-bit IV.
  -- Encrypt the file using AES-GCM (authenticated symmetric encryption).
  -- Encrypt (wrap) the AES key with the shared RSA public key using RSA-OAEP (SHA-256).
  -- Package { encrypted_aes_key, iv, ciphertext } into a compact JSON envelope.
  -- Convert that envelope into a QR code → encrypted_shared.qr.png.

3. Decrypt from QR (or Text)

- Decrypt the QR code and recover the original file::

```shell
python decrypt_from_qr_shared.py --qr encrypted_shared.qr.png --private-key keys/system_private.pem --out-file recovered.bin --passphrase mysecret

# --qr → QR code image to decrypt.
# --private-key → path to the shared RSA private key.
# --out-file → output file for the decrypted JSON.
# --passphrase → password for the private key (if encrypted).
```

- Simpler example (no passphrase):

```shell
python decrypt_from_qr_shared.py --qr encrypted_shared.qr.png --out-file recovered.bin

```

- This will:
  - Read and decode the QR or text input automatically to extract:
    `{ encrypted_aes_key, iv, ciphertext }`
  - Decrypt the AES key using the shared RSA private key (**RSA-OAEP**, SHA-256)
  - Use the AES key and IV to decrypt the ciphertext (**AES-GCM**)
  - Write the recovered data:
    - As **prettified JSON**, if the decrypted content is valid JSON
    - Or as a **binary file** (e.g., image, document, archive, etc.) if not JSON

## 🏁 Conclusion

This system ensures secure and efficient data exchange between two parties without requiring an online connection.
It supports any file format, accepts any QR or text input, and guarantees end-to-end encryption with modern cryptographic standards.
