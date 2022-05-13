from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def hashPassword(password):
    """
    Hash password using non-random salt
    """
    salt = "a0a4310f19"
    kdf = Scrypt(salt=salt.encode("utf-8"), length=32, n=2 ** 14, r=8, p=1)
    password_bytes = bytes(password, "utf-8")
    hashed_password = kdf.derive(password_bytes).hex()

    return hashed_password
