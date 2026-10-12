"""
Lab 3 - Task 1: Cryptographic Hash Avalanche Effect Quantification
File: task1_avalanche_effect.py
Description: Quantifies the bit-level flipping ratio of hash functions
             when input changes by exactly ONE bit ('S' -> 's').
Dependencies: Python standard library only.
"""

import hashlib


def count_bit_differences(hex_hash1: str, hex_hash2: str) -> int:
    """Calculate the Hamming distance (differing bit count) between two hex strings."""
    val1 = int(hex_hash1, 16)
    val2 = int(hex_hash2, 16)
    xor_diff = val1 ^ val2
    return bin(xor_diff).count("1")


def main():
    print("=" * 68)
    print(" TASK 1: QUANTIFYING THE AVALANCHE EFFECT ACROSS THE SHA FAMILY")
    print("=" * 68)

    # Input 'S' (ASCII: 01010011) vs 's' (ASCII: 01110011) differs by exactly 1 bit
    msg1 = b"Hello Security"
    msg2 = b"Hello security"

    print(f"Input Message 1 : '{msg1.decode()}'")
    print(f"Input Message 2 : '{msg2.decode()}'")
    print("Input Bit Diff  : Exactly 1 bit changed ('S' -> 's')\n")
    print(f"{'Algorithm':<12} | {'Digest Bits':<11} | {'Flipped Bits':<12} | {'Flip Ratio (%)':<15} | {'Security Status'}")
    print("-" * 68)

    algorithms = [
        ("sha1", "SHA-1 (Broken Collision Resistance)"),
        ("sha256", "SHA-256 (Industry Gold Standard)"),
        ("sha512", "SHA-512 (High Performance 64-bit)"),
        ("sha3_256", "SHA3-256 (Keccak Sponge Structure)")
    ]

    for algo_id, note in algorithms:
        h1 = hashlib.new(algo_id, msg1).hexdigest()
        h2 = hashlib.new(algo_id, msg2).hexdigest()

        digest_bit_length = len(h1) * 4
        flipped_bits = count_bit_differences(h1, h2)
        ratio = (flipped_bits / digest_bit_length) * 100.0

        print(f"{algo_id.upper():<12} | {digest_bit_length:<11} | {flipped_bits:<12} | {ratio:>6.2f}%         | {note.split(' ')[0]}")

    print("-" * 68)
    print("\n[Student Observation Point]:")
    print("1. All modern cryptographic hash functions exhibit an approximate 50% bit flip ratio.")
    print("2. SHA-1 was deprecated NOT because of poor avalanche diffusion, but due to collision attacks.\n")


if __name__ == "__main__":
    main()