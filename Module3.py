import hashlib
import argparse
import subprocess

# -------------------------
# SHA-256 functions
# -------------------------
def hash_string(text):
    return hashlib.sha256(text.encode()).hexdigest()

def hash_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

# -------------------------
# Caesar cipher
# -------------------------
def caesar_encrypt(text, shift):
    result = ""
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result += chr((ord(c) - base + shift) % 26 + base)
        else:
            result += c
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# -------------------------
# Digital signatures (OpenSSL)
# -------------------------
def sign_file(private_key, infile, outfile):
    subprocess.run(["openssl", "dgst", "-sha256", "-sign",
                    private_key, "-out", outfile, infile], check=True)

def verify_signature(public_key, infile, sigfile):
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", public_key,
         "-signature", sigfile, infile],
        stdout=subprocess.PIPE,
        text=True
    )
    return "Verified OK" in result.stdout

# -------------------------
# CLI
# -------------------------
def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")

    s = sub.add_parser("hash-string")
    s.add_argument("text")

    f = sub.add_parser("hash-file")
    f.add_argument("path")

    c = sub.add_parser("caesar")
    c.add_argument("mode", choices=["encrypt", "decrypt"])
    c.add_argument("text")
    c.add_argument("shift", type=int)

    g = sub.add_parser("sign")
    g.add_argument("private")
    g.add_argument("infile")
    g.add_argument("outfile")

    v = sub.add_parser("verify")
    v.add_argument("public")
    v.add_argument("infile")
    v.add_argument("sig")

    args = parser.parse_args()

    if args.cmd == "hash-string":
        print(hash_string(args.text))

    elif args.cmd == "hash-file":
        print(hash_file(args.path))

    elif args.cmd == "caesar":
        if args.mode == "encrypt":
            print(caesar_encrypt(args.text, args.shift))
        else:
            print(caesar_decrypt(args.text, args.shift))

    elif args.cmd == "sign":
        sign_file(args.private, args.infile, args.outfile)
        print("Signed!")

    elif args.cmd == "verify":
        print("OK" if verify_signature(args.public, args.infile, args.sig) else "FAILED")

if __name__ == "__main__":
    main()
