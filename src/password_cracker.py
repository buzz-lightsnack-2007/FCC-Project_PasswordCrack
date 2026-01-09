import hashlib
from files.records import ReadHash

def crack_sha1_hash(hash, use_salts = False):
    mgmt: ReadHash = ReadHash()
    mgmt.salted = use_salts

    matching: set[str] = mgmt[hash]
    mgmt.__del__()

    return matching or "Password not in database".upper()
