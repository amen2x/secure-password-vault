from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import os
import getpass

SALT_FILE = "salt.bin"
DATA_FILE = "passwor.txt"
CHECK_FILE = "check.token"


def get_or_create_salt() -> bytes:
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            return f.read()

    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
    return salt


def derive_fernet_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def get_fernet_from_master_password() -> Fernet:
    salt = get_or_create_salt()
    master_pwd = getpass.getpass("Master password: ")
    key = derive_fernet_key_from_password(master_pwd, salt)
    return Fernet(key)


def verify_master_password(fer: Fernet) -> bool:
    """
    We store an encrypted check value once.
    On later runs, if the master password is wrong,
    decrypt will fail (InvalidToken).
    """
    if not os.path.exists(CHECK_FILE):
        token = fer.encrypt(b"vault-check")
        with open(CHECK_FILE, "wb") as f:
            f.write(token)
        return True

    with open(CHECK_FILE, "rb") as f:
        token = f.read()

    try:
        return fer.decrypt(token) == b"vault-check"
    except InvalidToken:
        return False


def view(fer: Fernet) -> None:
    try:
        with open(DATA_FILE, "r") as f:
            for line in f:
                data = line.strip()
                if "|" not in data:
                    continue

                user, token = data.split("|", 1)
                try:
                    pwd = fer.decrypt(token.encode()).decode()
                    print(f"User: {user} | Password: {pwd}")
                except InvalidToken:
                    print(f"User: {user} | Password: [can't decrypt]")
    except FileNotFoundError:
        print("No passwords saved yet. Add one first.")


def add(fer: Fernet) -> None:
    name = input("Account Name: ").strip()
    pwd = getpass.getpass("Password: ")
    token = fer.encrypt(pwd.encode()).decode()

    with open(DATA_FILE, "a") as f:
        f.write(name + "|" + token + "\n")


def main():
    fer = get_fernet_from_master_password()

    if not verify_master_password(fer):
        print("Wrong master password.")
        return

    while True:
        mode = input(
            "Would you like to add a new password or view existing ones (view, add, q to quit): "
        ).strip().lower()

        if mode == "q":
            break
        elif mode == "view":
            view(fer)
        elif mode == "add":
            add(fer)
        else:
            print("Invalid mode.")


if __name__ == "__main__":
    main()
