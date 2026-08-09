"""Wholly fictional data used by the README screenshot generator."""

USERS = [
    {
        "username": "archive-sync",
        "home": r"C:\SFTP-Demo\archive-sync",
        "auth": "both",
        "has_password": True,
        "key_count": 1,
        "permissions": {"list": True, "download": True, "upload": True,
                        "delete": False, "rename_file": True, "rename_dir": False,
                        "mkdir": True, "delete_dir": False},
    },
    {
        "username": "vendor-drop",
        "home": r"C:\SFTP-Demo\vendor-drop",
        "auth": "key",
        "has_password": False,
        "key_count": 2,
        "permissions": {"list": True, "download": False, "upload": True,
                        "delete": False, "rename_file": False, "rename_dir": False,
                        "mkdir": False, "delete_dir": False},
    },
]

STATUS = {
    "running": True,
    "quick": False,
    "port": 2222,
    "lan": "10.42.18.24",
    "fingerprint": "SHA256:7dQ7D8KQh3Y5L6HNMzQecZ9xy3k3O5B4WqC6aR2mH4s",
    "connections": [
        {"user": "archive-sync", "ip": "10.42.18.61", "active": 1, "since": 834},
        {"user": "vendor-drop", "ip": "10.42.19.18", "active": 0, "since": 214},
    ],
    "locked": [{"ip": "10.42.19.77", "remaining": 412}],
    "quick_folder": "",
    "firewall": "allowed",
}
