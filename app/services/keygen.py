import io
import os

import paramiko

from app.debug_log import debug


def generate_keypair(key_type, out_path, passphrase, username):
    try:
        from cryptography.hazmat.primitives import serialization
        if not out_path:
            return {"ok": False, "error": "Choose where to save the private key."}
        enc = (serialization.BestAvailableEncryption(passphrase.encode())
               if passphrase else serialization.NoEncryption())
        if (key_type or "").startswith("Ed25519"):
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            k = Ed25519PrivateKey.generate()
            priv = k.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.OpenSSH, enc)
            pub = k.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                               serialization.PublicFormat.OpenSSH)
        else:
            key = paramiko.RSAKey.generate(4096)
            buf = io.StringIO()
            key.write_private_key(buf, password=passphrase or None)
            priv = buf.getvalue().encode()
            pub = f"ssh-rsa {key.get_base64()}".encode()
        with open(out_path, "wb") as f:
            f.write(priv)
        try:
            os.chmod(out_path, 0o600)
        except OSError:
            pass
        label = f"{username}@simple-sftp-server" if username else "simple-sftp-server"
        pubtext = pub.decode().strip() + " " + label
        with open(out_path + ".pub", "w", encoding="utf-8") as f:
            f.write(pubtext + "\n")
        debug.log("KEYGEN", {"type": key_type, "path": out_path})
        return {"ok": True, "public": pubtext, "private_path": out_path}
    except PermissionError:
        return {"ok": False, "error": "Couldn't write there (permission denied). Pick a folder you can write to."}
    except Exception:
        return {"ok": False, "error": "Key generation failed. Check the type and passphrase."}
