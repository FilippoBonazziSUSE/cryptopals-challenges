#!python3

import argparse
import base64
import collections
import random


english_freq_table = {"e": 0.1202,
                      "t": 0.0910,
                      "a": 0.0812,
                      "o": 0.0768,
                      "i": 0.0731,
                      "n": 0.0695,
                      "s": 0.0628,
                      "r": 0.0602,
                      "h": 0.0592,
                      "d": 0.0432,
                      "l": 0.0398,
                      "u": 0.0288,
                      "c": 0.0271,
                      "m": 0.0261,
                      "f": 0.0230,
                      "y": 0.0211,
                      "w": 0.0209,
                      "g": 0.0203,
                      "p": 0.0182,
                      "b": 0.0149,
                      "v": 0.0111,
                      "k": 0.0069,
                      "x": 0.0017,
                      "q": 0.0011,
                      "j": 0.0010,
                      "z": 0.0007}


# From https://alexwlchan.net/2018/ascii-bar-charts/
def print_bar_chart(data: {str, float}):
    max_value = max(count for _, count in data)
    increment = max_value / 25

    longest_label_length = max(len(label) for label, _ in data)

    for label, count in data:
        # The ASCII block elements come in chunks of 8, so we work out how
        # many fractions of 8 we need.
        # https://en.wikipedia.org/wiki/Block_Elements
        bar_chunks, remainder = divmod(int(count * 8 / increment), 8)

        # First draw the full width chunks
        bar = '█' * bar_chunks

        # Then add the fractional part.  The Unicode code points for
        # block elements are (8/8), (7/8), (6/8), ... , so we need to
        # work backwards.
        if remainder > 0:
            bar += chr(ord('█') + (8 - remainder))

        # If the bar is empty, add a left one-eighth block
        bar = bar or '▏'

        print(f'{label.rjust(longest_label_length)} ▏ {count:5.2f} {bar}')


# cryptopals challenges set 1, challenge 1
# Convert hex to base64
def hex_to_base64(s: str) -> str:
    b = bytes.fromhex(s)
    o = base64.b64encode(b)
    return o.decode('utf-8')


# cryptopals challenges set 1, challenge 2
# Fixed XOR
def fixed_xor(x: str, y: str) -> str:
    x_b = bytes.fromhex(x)
    y_b = bytes.fromhex(y)

    o = bytes(a ^ b for (a, b) in zip(x_b, y_b))
    return o.hex()


# cryptopals challenges set 1, challenge 3
# Single-byte XOR cipher
# Analyse character frequency in supplied plaintext, compare it against English
# character frequency and return the correlation of the two distributions
def compare_frequency(b: bytes) -> float:
    counts = {}
    # Count occurrences of letters in plaintext
    for e in b:
        if ((e >= ord("a") and e <= ord("z"))
           or (e >= ord("A") and e <= ord("Z"))):
            c = chr(e).lower()
            if c not in counts:
                counts[c] = 0
            counts[c] += 1
    # Compute frequency table
    freq_table = {}
    for k in english_freq_table.keys():
        if k in counts:
            freq_table[k] = counts[k] / len(b)
        else:
            freq_table[k] = 0
    # Compute correlation of frequency tables
    corr = sum([freq_table[i] * (english_freq_table[i] / 100) for i in english_freq_table.keys()])

    return corr, freq_table


def decrypt_bytewise(c: bytes, k: int) -> bytes:
    return bytes(c_n ^ k for c_n in c)


def crack_ciphertext(c: str) -> str:
    b = bytes.fromhex(c)

    key_scores = {}
    plaintexts = {}
    freq_tables = {}
    best_key = None

    print("English text distribution")
    print_bar_chart(sorted(english_freq_table.items()))

    for k in range(0, 256):
        p = decrypt_bytewise(b, k)
        plaintexts[k] = p

        key_scores[k], freq_tables[k] = compare_frequency(p)
        # Keep track of best key
        if best_key is None or key_scores[k] > key_scores[best_key]:
            best_key = k

    best_key = 88
    print(f"Key: {best_key} ({best_key.to_bytes()}), corr {key_scores[best_key]}")
    print(plaintexts[best_key])
    print_bar_chart(sorted(freq_tables[best_key].items()))
    print(sorted(key_scores.items(), key=lambda x:x[1], reverse=True)[:5])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('x')
    args = parser.parse_args()

    crack_ciphertext(args.x)
