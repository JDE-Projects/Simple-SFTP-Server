import io
import os
import uuid

import paramiko

from app.debug_log import debug


def generate_keypair(key_type, out_path, passphrase, username, overwrite=False):
    try:
        from cryptography.hazmat.primitives import serialization
        if not out_path:
            return {"ok": False, "error": "Choose where to save the private key."}
        pub_path = out_path + ".pub"
        if not overwrite and (os.path.exists(out_path) or os.path.exists(pub_path)):
            return {"ok": False, "exists": True,
                    "error": "A key already exists at that path. Choose Replace to overwrite it, or pick a different name."}
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
        label = f"{username}@simple-sftp-server" if username else "simple-sftp-server"
        pubtext = pub.decode().strip() + " " + label
        priv_tmp = out_path + f".tmp-{os.getpid()}-{uuid.uuid4().hex}"
        pub_tmp = pub_path + f".tmp-{os.getpid()}-{uuid.uuid4().hex}"
        priv_backup = None
        try:
            with open(priv_tmp, "wb") as f:
                f.write(priv)
            try:
                os.chmod(priv_tmp, 0o600)
            except OSError:
                pass
            with open(pub_tmp, "w", encoding="utf-8") as f:
                f.write(pubtext + "\n")

            if os.path.exists(out_path):
                priv_backup = out_path + f".tmp-{os.getpid()}-{uuid.uuid4().hex}"
                os.replace(out_path, priv_backup)
            try:
                os.replace(priv_tmp, out_path)
                os.replace(pub_tmp, pub_path)
            except Exception:
                try:
                    if priv_backup:
                        os.replace(priv_backup, out_path)
                    else:
                        os.remove(out_path)
                except Exception:
                    debug.log("KEYGEN", {
                        "restore_failed": True,
                        "private_path": out_path,
                        "backup_path": priv_backup,
                        "public_path": pub_path,
                    })
                    # The backup is now the only copy of the old private
                    # key, so it must survive the cleanup below.
                    priv_backup = None
                raise
        finally:
            for path in (priv_tmp, pub_tmp, priv_backup):
                if path and os.path.exists(path):
                    try:
                        os.remove(path)
                    except OSError:
                        pass
        debug.log("KEYGEN", {"type": key_type, "path": out_path})
        return {"ok": True, "public": pubtext, "private_path": out_path}
    except PermissionError:
        return {"ok": False, "error": "Couldn't write there (permission denied). Pick a folder you can write to."}
    except Exception:
        return {"ok": False, "error": "Key generation failed. Check the type and passphrase."}
