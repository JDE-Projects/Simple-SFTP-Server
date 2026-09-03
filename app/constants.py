APP_VERSION = "1.5.0"
GITHUB_REPO = "JDE-Projects/Simple-SFTP-Server"
DEFAULT_PORT = 2222

DISABLED_ALGORITHMS = {
    "kex": ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1"],
    "ciphers": ["3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
                "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128", "arcfour256"],
    "macs": ["hmac-md5", "hmac-md5-96", "hmac-sha1-96", "hmac-sha1"],
    "keys": ["ssh-dss"],
}

LOCKOUT_THRESHOLD = 5
LOCKOUT_SECONDS = 15 * 60

FAIL_RECORD_TTL_SECONDS = 15 * 60  # a fail count is forgotten after this long with no new failure from that address
MAX_TRACKED_IPS = 4096             # hard ceiling on how many addresses the lockout table holds at once
LOCKOUT_PRUNE_INTERVAL = 60        # a full sweep runs at most this often on normal calls

MAX_TOTAL_CONNECTIONS = 100  # total simultaneous live connections, handshaking + established
MAX_PER_IP_CONNECTIONS = 10  # simultaneous live connections from one source address
