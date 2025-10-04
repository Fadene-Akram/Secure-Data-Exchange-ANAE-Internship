# Secure-Data-Exchange-ANAE-Internship

This is a project form my internship with the minstry of knowledge economy and startups.

This project demonstrates **hybrid encryption** for securely sharing JSON data between two companies.  
The idea:

- ANAE (Sender) encrypts the data of the interpreneur and put it in qr code .
- the interpreneur (user) gives douan the qr code
- DOUAN (Receiver) scan it decrypts it.

---

## 🚀 How it Works

### 🔄 Flow Diagram (Hybrid Encryption)

```text
          ┌────────────────────────┐
          │        Sender          │
          └────────────┬───────────┘
                       │
            Generate AES key
                       │
             Encrypt JSON with AES
                       │
             Encrypt AES key with
          Receiver's RSA Public Key
                       │
       ┌─────────── Package ───────────────────┐
       │ { encrypted_aes_key, ciphertext }     │
       └───────────────────────────────────────┘
                       │
                 Convert to QR Code
                       │
                       ▼
          ┌────────────────────────┐
          │       Receiver         │
          └────────────┬───────────┘
                       │
             Scan QR → Extract JSON
                       │
     Decrypt AES key with RSA Private Key
                       │
       Decrypt ciphertext with AES key
                       │
               Recover original JSON

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

. AES → Super fast for encrypting large JSON files.
. RSA → Secure way to exchange AES keys (no need to pre-share a secret).

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

2. Encrypt JSON and Create QR Code

- Prepare a JSON file, e.g. user_123.json.

Run:

```shell
python encrypt_to_qr_shared.py --in-json secret_data.json --out-png encrypted_shared.qr.png

# Example with explicit public key path:

# python encrypt_to_qr_shared.py --public-key keys/system_public.pem --in-json secret_data.json --out-png encrypted_shared.qr.png
```

- This will:
  -- Compress the JSON data with zlib.
  -- Generate a random AES-256 key and 96-bit IV.
  -- Encrypt the JSON using AES-GCM (authenticated symmetric encryption).
  -- Encrypt (wrap) the AES key with the shared RSA public key using RSA-OAEP (SHA-256).
  -- Package { encrypted_aes_key, iv, ciphertext } into a compact JSON envelope.
  -- Convert that envelope into a QR code → encrypted_shared.qr.png.

3. Scan QR and Decrypt

- To recover the original JSON from the QR code using the shared private key:

```shell
# Windows
python scan_and_decrypt_shared.py --qr encrypted_shared.qr.png --private-key keys/system_private.pem --out-json recovered.json --passphrase mysecret

# --qr → QR code image to decrypt.
# --private-key → path to the shared RSA private key.
# --out-json → output file for the decrypted JSON.
# --passphrase → password for the private key (if encrypted).

# Simpler example (no passphrase):
# python scan_and_decrypt_shared.py --qr encrypted_shared.qr.png --out-json recovered.json
```

- This will:
  -- Read the QR code and extract the JSON envelope { encrypted_aes_key, iv, ciphertext }.
  -- Decrypt the AES key using the shared RSA private key (RSA-OAEP, SHA-256).
  -- Use the AES key + IV to decrypt the ciphertext (AES-GCM).
  -- Decompress the result with zlib to obtain the original JSON.
  -- Save the recovered JSON as recovered.json.
