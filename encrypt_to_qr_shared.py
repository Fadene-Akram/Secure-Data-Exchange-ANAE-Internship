import os, json, zlib, base64, argparse
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import qrcode
from qrcode.constants import ERROR_CORRECT_Q

def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")
 
def load_public_key(pem_path: Path):
    with open(pem_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def make_envelope(plaintext_json_bytes: bytes, rsa_pub) -> dict:
    # 1) Compress
    comp = zlib.compress(plaintext_json_bytes, level=9)

    # 2) AES-256-GCM
    aes_key = os.urandom(32)
    nonce   = os.urandom(12)   # 96-bit
    aesgcm  = AESGCM(aes_key)
    ct      = aesgcm.encrypt(nonce, comp, None)  # ciphertext || tag

    # 3) RSA-OAEP(SHA-256) wrap the AES key
    enc_key = rsa_pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 4) Envelope (compact, QR-safe after JSON stringify)
    env = {
        "v": 1,
        "alg": "RSA-OAEP256+AES-256-GCM",
        "z": "zlib",
        "cty": "application/json",
        "ek": b64u_encode(enc_key),   # encrypted AES key
        "iv": b64u_encode(nonce),     # GCM nonce
        "ct": b64u_encode(ct),        # ciphertext incl. tag
    }
    return env

def generate_qr(text: str, out_png: Path):
    qr = qrcode.QRCode(
        version=None,
        error_correction=ERROR_CORRECT_Q,  # robust for print/scans
        box_size=10,
        border=4
    )
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(out_png)

def main():
    ap = argparse.ArgumentParser(description="Encrypt JSON and output a QR (shared public key)")
    ap.add_argument("--public-key", default="keys/system_public.pem", help="Path to shared public PEM")
    ap.add_argument("--in-json", required=True, help="Input JSON file")
    ap.add_argument("--out-png", required=True, help="Output QR PNG")
    ap.add_argument("--out-envelope", help="(Optional) also save the envelope JSON")
    args = ap.parse_args()

    rsa_pub = load_public_key(Path(args.public_key))
    raw = Path(args.in_json).read_bytes()
    # sanity: ensure valid JSON
    json.loads(raw.decode("utf-8"))

    env = make_envelope(raw, rsa_pub)
    payload = json.dumps(env, separators=(",",":"))

    generate_qr(payload, Path(args.out_png))
    print(f"QR saved → {args.out_png}")
    print(f"Payload size: {len(payload.encode())/1024:.2f} KiB (consider chunking if > ~3 KiB)")

    if args.out_envelope:
        Path(args.out_envelope).write_text(payload, encoding="utf-8")
        print(f"Envelope JSON → {args.out_envelope}")

if __name__ == "__main__":
    main()
