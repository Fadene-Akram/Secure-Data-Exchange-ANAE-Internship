import json, zlib, base64, argparse
from pathlib import Path
from PIL import Image
from pyzbar.pyzbar import decode as qr_decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def b64u_decode(s: str) -> bytes:
    # add padding if needed
    return base64.urlsafe_b64decode(s + "===")

def read_qr_text(png_path: Path) -> str:
    img = Image.open(png_path)
    res = qr_decode(img)
    if not res:
        raise ValueError("No QR found or unreadable.")
    return res[0].data.decode()

def load_private_key(pem_path: Path, passphrase: str | None):
    with open(pem_path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=(passphrase.encode() if passphrase else None),
        )

def decrypt_envelope(env: dict, rsa_priv) -> bytes:
    # Validate fields
    for k in ("v","alg","z","cty","ek","iv","ct"):
        if k not in env:
            raise ValueError(f"Envelope missing field: {k}")
    if env["alg"] != "RSA-OAEP256+AES-256-GCM":
        raise ValueError("Unsupported 'alg'")

    enc_key = b64u_decode(env["ek"])
    nonce   = b64u_decode(env["iv"])
    ct      = b64u_decode(env["ct"])

    # RSA-OAEP unwrap
    aes_key = rsa_priv.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # AES-GCM decrypt (+integrity check)
    aesgcm = AESGCM(aes_key)
    comp = aesgcm.decrypt(nonce, ct, None)

    # Decompress
    raw = zlib.decompress(comp)
    return raw

def main():
    ap = argparse.ArgumentParser(description="Scan QR and decrypt JSON (shared private key)")
    ap.add_argument("--private-key", default="keys/system_private.pem", help="Path to shared private PEM")
    ap.add_argument("--qr", required=True, help="QR PNG path")
    ap.add_argument("--out-json", default="recovered.json", help="Output JSON file")
    ap.add_argument("--passphrase", default=None, help="Passphrase for private key (if protected)")
    args = ap.parse_args()

    rsa_priv = load_private_key(Path(args.private_key), args.passphrase)
    payload_text = read_qr_text(Path(args.qr))
    env = json.loads(payload_text)

    raw = decrypt_envelope(env, rsa_priv)
    obj = json.loads(raw.decode("utf-8"))

    Path(args.out_json).write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Decrypted JSON → {args.out_json}")

if __name__ == "__main__":
    main()
