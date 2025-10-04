import os, json, zlib, base64, argparse, mimetypes
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


def make_envelope(file_bytes: bytes, rsa_pub, content_type: str) -> dict:
    # 1) Compress
    comp = zlib.compress(file_bytes, level=9)

    # 2) AES-256-GCM
    aes_key = os.urandom(32)
    nonce   = os.urandom(12)
    aesgcm  = AESGCM(aes_key)
    ct      = aesgcm.encrypt(nonce, comp, None)

    # 3) Encrypt AES key with RSA-OAEP(SHA-256)
    enc_key = rsa_pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 4) Build envelope
    env = {
        "v": 1,
        "alg": "RSA-OAEP256+AES-256-GCM",
        "z": "zlib",
        "cty": content_type or "application/octet-stream",
        "ek": b64u_encode(enc_key),
        "iv": b64u_encode(nonce),
        "ct": b64u_encode(ct),
    }
    return env


def generate_qr(text: str, out_png: Path):
    qr = qrcode.QRCode(
        version=None,
        error_correction=ERROR_CORRECT_Q,
        box_size=10,
        border=4
    )
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(out_png)


def main():
    ap = argparse.ArgumentParser(description="Encrypt any file and output a QR code (using a public key)")
    ap.add_argument("--public-key", default="keys/system_public.pem", help="Path to public PEM key")
    ap.add_argument("--input-file", required=True, help="Path to input file (any format)")
    ap.add_argument("--out-png", required=True, help="Output QR PNG")
    ap.add_argument("--out-envelope", help="Optional: also save the envelope JSON")
    args = ap.parse_args()

    rsa_pub = load_public_key(Path(args.public_key))
    raw = Path(args.input_file).read_bytes()

    # Detect MIME type
    mime_type, _ = mimetypes.guess_type(args.input_file)
    if mime_type is None:
        mime_type = "application/octet-stream"

    env = make_envelope(raw, rsa_pub, mime_type)
    payload = json.dumps(env, separators=(",", ":"))

    generate_qr(payload, Path(args.out_png))
    print(f"QR saved → {args.out_png}")
    print(f"Detected MIME type: {mime_type}")
    print(f"Payload size: {len(payload.encode()) / 1024:.2f} KiB")

    if args.out_envelope:
        Path(args.out_envelope).write_text(payload, encoding="utf-8")
        print(f"Envelope JSON → {args.out_envelope}")


if __name__ == "__main__":
    main()
