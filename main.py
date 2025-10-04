from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import FileResponse, JSONResponse
from pathlib import Path
import json, tempfile

from encrypt_to_qr_shared import load_public_key, make_envelope, generate_qr
from decrypt_from_qr_shared import load_private_key, read_qr_text, decrypt_envelope

app = FastAPI()

PUBLIC_KEY_PATH = Path("mykeys/system_public.pem")
PRIVATE_KEY_PATH = Path("mykeys/system_private.pem")


@app.post("/encrypt-json")
async def encrypt_json(file: UploadFile = File(...)):
    """Takes a JSON file and returns a QR PNG"""
    try:
        raw = await file.read()
        data = json.loads(raw.decode("utf-8"))  # validate JSON

        rsa_pub = load_public_key(PUBLIC_KEY_PATH)
        env = make_envelope(raw, rsa_pub)
        payload = json.dumps(env, separators=(",", ":"))

        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
            generate_qr(payload, Path(tmp.name))
            return FileResponse(tmp.name, media_type="image/png", filename="encrypted_qr.png")

    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)


@app.post("/decrypt-qr")
async def decrypt_qr(file: UploadFile = File(...), passphrase: str | None = Form(None)):
    """Takes a QR PNG and returns the original JSON"""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
            tmp.write(await file.read())
            tmp.flush()

            rsa_priv = load_private_key(PRIVATE_KEY_PATH, passphrase)
            payload_text = read_qr_text(Path(tmp.name))
            env = json.loads(payload_text)
            raw = decrypt_envelope(env, rsa_priv)
            obj = json.loads(raw.decode("utf-8"))

        return JSONResponse(content=obj, status_code=200)

    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)


# uvicorn main:app --reload --host 127.0.0.1 --port 8000
# http://127.0.0.1:8000/docs
# test then the two apis