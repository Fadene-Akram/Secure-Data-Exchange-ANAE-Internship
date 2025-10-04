from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import argparse
from pathlib import Path
import getpass

def main():
    ap = argparse.ArgumentParser(description="Generate one shared RSA key pair")
    ap.add_argument("--out-dir", default="keys", help="Directory to store keys")
    ap.add_argument("--bits", type=int, default=3072, help="RSA key size (2048/3072/4096)")
    ap.add_argument("--encrypt-private", action="store_true",
                    help="Protect private key PEM with a passphrase")
    args = ap.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    if args.encrypt_private:
        pw = getpass.getpass("Enter passphrase for private key: ").encode()
        enc_alg = serialization.BestAvailableEncryption(pw)
    else:
        enc_alg = serialization.NoEncryption()

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=args.bits)
    public_key = private_key.public_key()

    priv_path = out / "system_private.pem"
    pub_path  = out / "system_public.pem"

    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_alg,
        ))

    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    print(f"Wrote:\n  {priv_path}\n  {pub_path}\n"
          f"KEEP system_private.pem SECRET. Share system_public.pem.")

if __name__ == "__main__":
    main()
