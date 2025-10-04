# import json, zlib, base64, argparse
# from pathlib import Path
# from PIL import Image
# from pyzbar.pyzbar import decode as qr_decode
# from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives import hashes, serialization

# def b64u_decode(s: str) -> bytes:
#     # add padding if needed
#     return base64.urlsafe_b64decode(s + "===")

# def read_qr_text(png_path: Path) -> str:
#     img = Image.open(png_path)
#     res = qr_decode(img)
#     if not res:
#         raise ValueError("No QR found or unreadable.")
#     return res[0].data.decode()

# def load_private_key(pem_path: Path, passphrase: str | None):
#     with open(pem_path, "rb") as f:
#         return serialization.load_pem_private_key(
#             f.read(),
#             password=(passphrase.encode() if passphrase else None),
#         )

# def decrypt_envelope(env: dict, rsa_priv) -> bytes:
#     # Validate fields
#     for k in ("v","alg","z","cty","ek","iv","ct"):
#         if k not in env:
#             raise ValueError(f"Envelope missing field: {k}")
#     if env["alg"] != "RSA-OAEP256+AES-256-GCM":
#         raise ValueError("Unsupported 'alg'")

#     enc_key = b64u_decode(env["ek"])
#     nonce   = b64u_decode(env["iv"])
#     ct      = b64u_decode(env["ct"])

#     # RSA-OAEP unwrap
#     aes_key = rsa_priv.decrypt(
#         enc_key,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )

#     # AES-GCM decrypt (+integrity check)
#     aesgcm = AESGCM(aes_key)
#     comp = aesgcm.decrypt(nonce, ct, None)

#     # Decompress
#     raw = zlib.decompress(comp)
#     return raw

# def main():
#     ap = argparse.ArgumentParser(description="Scan QR and decrypt JSON (shared private key)")
#     ap.add_argument("--private-key", default="keys/system_private.pem", help="Path to shared private PEM")
#     ap.add_argument("--qr", required=True, help="QR PNG path")
#     ap.add_argument("--out-json", default="recovered.json", help="Output JSON file")
#     ap.add_argument("--passphrase", default=None, help="Passphrase for private key (if protected)")
#     args = ap.parse_args()

#     rsa_priv = load_private_key(Path(args.private_key), args.passphrase)
#     payload_text = read_qr_text(Path(args.qr))
#     env = json.loads(payload_text)

#     raw = decrypt_envelope(env, rsa_priv)
#     obj = json.loads(raw.decode("utf-8"))

#     Path(args.out_json).write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
#     print(f"Decrypted JSON → {args.out_json}")

# if __name__ == "__main__":
#     main()

import json, zlib, base64, argparse, mimetypes
from pathlib import Path
from PIL import Image
from pyzbar.pyzbar import decode as qr_decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization


def b64u_decode(s: str) -> bytes:
    """Base64URL decode with padding fix."""
    return base64.urlsafe_b64decode(s + "===")


def read_qr_text(input_path_or_text: str) -> str:
    """Read QR text from an image or directly from a string/file."""
    path = Path(input_path_or_text)
    if path.exists():
        mime, _ = mimetypes.guess_type(path)
        # If it's an image, decode QR
        if mime and mime.startswith("image/"):
            img = Image.open(path)
            res = qr_decode(img)
            if not res:
                raise ValueError("No QR code found or unreadable in the image.")
            return res[0].data.decode()
        else:
            # Treat as a text file
            return path.read_text(encoding="utf-8").strip()
    else:
        # Treat the argument as direct QR text
        return input_path_or_text.strip()


def load_private_key(pem_path: Path, passphrase: str | None):
    with open(pem_path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=(passphrase.encode() if passphrase else None),
        )


def decrypt_envelope(env: dict, rsa_priv) -> bytes:
    required = ("v", "alg", "z", "cty", "ek", "iv", "ct")
    for k in required:
        if k not in env:
            raise ValueError(f"Envelope missing field: {k}")
    if env["alg"] != "RSA-OAEP256+AES-256-GCM":
        raise ValueError("Unsupported encryption algorithm")

    enc_key = b64u_decode(env["ek"])
    nonce   = b64u_decode(env["iv"])
    ct      = b64u_decode(env["ct"])

    aes_key = rsa_priv.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    aesgcm = AESGCM(aes_key)
    comp = aesgcm.decrypt(nonce, ct, None)
    return zlib.decompress(comp)


def main():
    ap = argparse.ArgumentParser(description="Decrypt QR payload (image or text) using private key")
    ap.add_argument("--private-key", default="keys/system_private.pem", help="Path to private PEM key")
    ap.add_argument("--qr", required=True, help="QR input: image path, text file, or direct string")
    ap.add_argument("--out-file", default="recovered.bin", help="Output file (auto-detect type if JSON)")
    ap.add_argument("--passphrase", default=None, help="Private key passphrase (if needed)")
    args = ap.parse_args()

    rsa_priv = load_private_key(Path(args.private_key), args.passphrase)
    payload_text = read_qr_text(args.qr)

    try:
        env = json.loads(payload_text)
    except json.JSONDecodeError:
        raise ValueError("QR data is not a valid JSON envelope")

    raw = decrypt_envelope(env, rsa_priv)

    # Try to detect if decrypted content is JSON
    try:
        obj = json.loads(raw.decode("utf-8"))
        Path(args.out_file).write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Decrypted JSON → {args.out_file}")
    except Exception:
        Path(args.out_file).write_bytes(raw)
        print(f"Decrypted binary data → {args.out_file}")


if __name__ == "__main__":
    main()
