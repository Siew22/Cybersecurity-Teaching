"""
Lab 3 - Task 3: Forensic Decryption & Analysis Utility (Student Tool)
File: decrypt_payload.py
Hardware: 100% CPU and RAM (No GPU required).
Usage:
    python3 decrypt_payload.py <target_file> <passphrase_or_key> <expected_sha256>
"""

import sys
import json
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken


def resolve_fernet_key(key_input: str) -> bytes:
    key_bytes = key_input.strip().encode("utf-8")
    try:
        decoded = base64.urlsafe_b64decode(key_bytes)
        if len(decoded) == 32:
            return key_bytes
    except Exception:
        pass
    digest = hashlib.sha256(key_bytes).digest()
    return base64.urlsafe_b64encode(digest)


def main():
    if len(sys.argv) != 4:
        print("\n[!] Usage: python3 decrypt_payload.py <target_file> <passphrase_or_key> <expected_sha256>")
        print("Example:")
        print("  python3 decrypt_payload.py ./subgroup_gamma/system/telemetry/active/telemetry_0417.enc \"TeacherPassword\" <EXPECTED_HASH>\n")
        sys.exit(1)

    filepath = sys.argv[1]
    raw_key_input = sys.argv[2]
    expected_hash = sys.argv[3].strip().lower()

    try:
        with open(filepath, "rb") as f:
            ciphertext_blob = f.read()
    except FileNotFoundError:
        print(f"[!] Error: File '{filepath}' not found.")
        sys.exit(1)

    actual_hash = hashlib.sha256(ciphertext_blob).hexdigest().lower()
    print("=" * 60)
    print(" FORENSIC INTEGRITY VERIFICATION (CPU MODE)")
    print("=" * 60)
    print(f"Target   : {filepath}")
    print(f"Expected : {expected_hash}")
    print(f"Actual   : {actual_hash}")

    if actual_hash != expected_hash:
        print("\n[-] FAIL: Hash mismatch! This is a DECOY or corrupted file.")
        print("[-] Action aborted: Do not analyze unauthorized/decoy files.")
        sys.exit(1)

    print("[+] OK: Hash matched! Genuine IOC target confirmed.")

    fernet_key = resolve_fernet_key(raw_key_input)
    try:
        cipher = Fernet(fernet_key)
        decrypted_json_bytes = cipher.decrypt(ciphertext_blob)
        payload = json.loads(decrypted_json_bytes.decode("utf-8"))
    except InvalidToken:
        print("\n[-] FAIL: Decryption failed! Invalid passphrase/key for this token.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] FAIL: JSON parse error: {e}")
        sys.exit(1)

        output_json_file = "extracted_malicious_context.json"
    with open(output_json_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"[+] Forensic Evidence successfully exported to '{output_json_file}'")

    print("\n" + "=" * 60)
    print(" DECRYPTED MALICIOUS CONTEXT PAYLOAD")
    print("=" * 60)
    print(json.dumps(payload, indent=2))
    print("=" * 60)
    print(f"[!] INJECTED DIRECTIVE: {payload.get('payload_directive', 'N/A')}\n")


if __name__ == "__main__":
    main()