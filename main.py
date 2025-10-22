from fastapi import FastAPI, UploadFile, Form
from fastapi.responses import FileResponse, JSONResponse
import tempfile
from pathlib import Path
import json
import mimetypes
from encrypt_to_qr_shared import load_public_key, make_envelope, generate_qr
from decrypt_from_qr_shared import load_private_key, decrypt_envelope, read_qr_text


app = FastAPI(
    title="Secure Data Exchange API",
    description="APIs for encrypting and decrypting files via QR code using RSA + AES-GCM + zlib compression",
    version="1.0"
)


@app.post("/encrypt")
async def encrypt_file(
    file: UploadFile,
    public_key_path: str = Form("keys/system_public.pem"),
    save_envelope: bool = Form(False)
):
    """
    Encrypt a file using the same logic as encrypt_to_qr_shared.py.
    Generates a QR code (and optionally a JSON envelope).
    """
    try:
        rsa_pub = load_public_key(Path(public_key_path))
        file_bytes = await file.read()

        mime_type, _ = mimetypes.guess_type(file.filename)
        mime_type = mime_type or "application/octet-stream"

        envelope = make_envelope(file_bytes, rsa_pub, mime_type)
        payload = json.dumps(envelope, separators=(",", ":"))

        temp_qr = Path(tempfile.gettempdir()) / f"{file.filename}_encrypted.png"
        generate_qr(payload, temp_qr)

        if save_envelope:
            json_path = Path(tempfile.gettempdir()) / f"{file.filename}_envelope.json"
            json_path.write_text(payload, encoding="utf-8")
            return JSONResponse({
                "message": "File encrypted successfully.",
                "qr_image": str(temp_qr),
                "envelope_json": str(json_path)
            })

        return FileResponse(temp_qr, media_type="image/png", filename="encrypted_qr.png")

    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/decrypt")
async def decrypt_file(
    qr_input: UploadFile,
    private_key_path: str = Form("keys/system_private.pem"),
    passphrase: str | None = Form(None)
):
    """
    Decrypt from QR image or JSON file using the same logic as decrypt_from_qr_shared.py.
    """
    try:
        try:
            rsa_priv = load_private_key(Path(private_key_path), passphrase)
        except TypeError as e:
            if "Password was given but private key is not encrypted" in str(e):
                rsa_priv = load_private_key(Path(private_key_path), None)
            else:
                raise
        temp_input = Path(tempfile.gettempdir()) / qr_input.filename
        temp_input.write_bytes(await qr_input.read())

        mime, _ = mimetypes.guess_type(temp_input)
        if mime and mime.startswith("image/"):
            payload_text = read_qr_text(str(temp_input))
        else:
            payload_text = temp_input.read_text(encoding="utf-8")

        env = json.loads(payload_text)
        raw = decrypt_envelope(env, rsa_priv)

        # Try JSON output
        try:
            obj = json.loads(raw.decode("utf-8"))
            return JSONResponse({
                "message": "Decryption successful (JSON detected).",
                "data": obj
            })
        except Exception:
            temp_out = Path(tempfile.gettempdir()) / "recovered.bin"
            temp_out.write_bytes(raw)
            return FileResponse(temp_out, media_type="application/octet-stream", filename="recovered.bin")

    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
 # uvicorn main:app --reload --host 127.0.0.1 --port 8000