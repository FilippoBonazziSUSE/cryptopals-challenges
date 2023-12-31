#!python3

import argparse
import base64
import collections
import itertools
import math
import statistics
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


# Compute cross correlation of frequency tables of equal size
# https://anomaly.io/understand-auto-cross-correlation-normalized-shift/
def cross_correlation(a: dict, b: dict, normalised=True) -> float:
    # Skip empty tables
    if all(v == 0 for v in a.values()) or all(v == 0 for v in a.values()):
        return 0
    c = sum([a[i] * b[i] for i in b.keys()])
    if normalised:
        c /= math.sqrt(
                sum([a[i] ** 2 for i in a.keys()]) *
                sum([b[i] ** 2 for i in b.keys()]))
    return c


def hellinger_distance(a: dict, b: dict, normalised=True) -> float:
    h = math.sqrt(sum((math.sqrt(a[i]) - math.sqrt(b[i])) ** 2 for i in a.keys()))
    if normalised:
        h /= math.sqrt(2)
    return h


def kl_divergence(a: dict, b: dict) -> float:
    d = sum(b[i] * math.log(b[i] / a[i]) for i in b.keys())
    return d


def bhattacharyya_coefficient(a: dict, b: dict) -> float:
    d = sum(math.sqrt(a[i] * b[i]) for i in b.keys())
    return d


def chi_square(a: dict, b: dict) -> float:
    x = sum(((a[i] - b[i]) ** 2) / b[i] for i in b.keys())
    return x


# Analyse character frequency in supplied plaintext, compare it against English
# character frequency and return a score
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
            # Should we normalize the frequency over all characters (letter
            # frequencies won't add up to 1) or only over letters?
            # freq_table[k] = counts[k] / sum(counts.values())
            freq_table[k] = counts[k] / len(b)
        else:
            freq_table[k] = 0

    # Cross correlation is kind of a meaningless measure, turns out, as it
    # only gives us the cos of the angle between the two n-dimensional vectors
    # score = cross_correlation(freq_table, english_freq_table)
    # The arccos of the dot product gives us the angle between the two
    # n-dimensional vectors. Turns out this is not good either
    # score = 1 - (math.acos(cross_correlation(freq_table, english_freq_table)) / math.pi)
    # Hellinger distance is already pretty good
    # score = 1 - hellinger_distance(freq_table, english_freq_table)
    # Kullback-Leibler divergence does not apply because both distributions
    # could conceivably contain zeroes
    # score = kl_divergence(freq_table, english_freq_table)
    # The Bhattacharyya coefficient has a striking resemblance to
    # cross-correlation, except the square root is applied to each sum element.
    # It is actually related to the Hellinger distance: H(P,Q) = sqrt(1 - BC(P-Q)
    score = bhattacharyya_coefficient(freq_table, english_freq_table)
    # chi-squared might not be meaningful but it works quite well
    #score = 1 / chi_square(freq_table, english_freq_table)

    return score, freq_table


def bytewise_xor(c: bytes, k: bytes) -> bytes:
    return bytes(c_n ^ k_n for c_n, k_n in zip(c, itertools.cycle(k)))


def crack_ciphertext_single_byte_key(b: bytes) -> str:
    key_scores = {}
    plaintexts = {}
    freq_tables = {}
    best_key = None
    DEBUG = False

    if DEBUG:
        print(f"Ciphertext: {c}")
        print(b)
        # print("English text distribution")
        # print_bar_chart(sorted(english_freq_table.items()))

    for k in range(0, 256):
        plaintexts[k] = bytewise_xor(b, k.to_bytes())

        # Summarily discard strings which contain non-utf characters
        try:
            plaintexts[k].decode('utf-8')
        except UnicodeDecodeError:
            continue
        # Summarily discard strings which contain non printable characters
        # (except newline)
        if not plaintexts[k].decode().replace('\n', ' ').isprintable():
            continue

        key_scores[k], freq_tables[k] = compare_frequency(plaintexts[k])
        # Keep track of best key
        if best_key is None or key_scores[k] > key_scores[best_key]:
            best_key = k

    if best_key is None:
        raise ValueError("Nothing found")

    if DEBUG:
        print(f"Key:       {best_key} ({best_key.to_bytes()}), score {key_scores[best_key]}")
        print(f"Plaintext: {plaintexts[best_key].decode()}")
        print_bar_chart(sorted(freq_tables[best_key].items()))
        print(sorted(key_scores.items(), key=lambda x:x[1], reverse=True)[:5])
    return plaintexts[best_key], best_key, key_scores[best_key]


# cryptopals challenges set 1, challenge 4
# Detect single-character XOR
def detect_ciphertext(filename: str):
    with open(filename) as f:
        lines = f.read().splitlines()

    scores = {}
    plaintexts = {}
    keys = {}
    best_line = None

    for e in lines:
        try:
            plaintexts[e], keys[e], scores[e] = crack_ciphertext_single_byte_key(bytes.fromhex(e))
        except ValueError as err:
            continue
        # Keep track of best line
        if best_line is None or scores[e] > scores[best_line]:
            best_line = e

    print(f"Ciphertext: {e} ({lines.index(e)})")
    print(f"Key:        {keys[best_line]} ({keys[best_line].to_bytes()}), score {scores[best_line]}")
    print(f"Plaintext:  {plaintexts[best_line].decode()}")


# cryptopals challenges set 1, challenge 5
# Implement repeating-key XOR
def encrypt_xor(p: str, k: str) -> str:
    c_b = bytewise_xor(bytes(p, 'utf-8'), bytes(k, 'utf-8'))
    return c_b.hex()


# cryptopals challenges set 1, challenge 6
# Break repeating-key XOR

def hamming_distance(a, b) -> int:
    if len(a) == len(b):
        return sum(char1 != char2 for char1, char2 in zip(a, b))
    else:
        return None


# Check for 1's in a binary string using Brian Kernighan's Algorithm
def bitwise_hamming_distance(a: bytes, b: bytes) -> int:
    if len(a) == len(b):
        count = 0
        for i in range(len(a)):
            x = a[i] ^ b[i]
            while (x):
                x = x & (x - 1)
                count += 1
        return count
    else:
        return None


# Compute the key size by finding the smallest key size with an outlier IC
# (index of coincidence). The index of coincidence is significantly higher
# in natural language strings than random text. This property is not altered by
# simple character substitution, such as XORing text with a fixed value.
# Repeating-key XOR using an N-byte key will encrypt every N-th character with
# the same key byte, thus preserving statistical markers of natural text (such
# as IC) in encrypted text sampled at periodicity N. Finding a significantly
# high IC in text sampled at periodicity M suggests that M is a multiple of N.
# The smallest M with the highest IC is probably N.
def compute_ks(b: bytes, max_size=0):
    DEBUG = False
    ic = {}

    if max_size == 0:
        max_size = len(b)

    for step in range(1, max_size):
        match = 0
        total = 0
        for i in range(len(b)):
            for j in range(i + step, len(b), step):
                total += 1
                if b[i] == b[j]:
                    match += 1
        ic[step] = match / total

    ic_mean = statistics.mean(ic.values())
    ic_stdv = statistics.pstdev(ic.values())

    best_ic_step = 0
    for k, v in ic.items():
        if v > ic_mean + (2 * ic_stdv):
            best_ic_step = k
            break
    if DEBUG:
        print("Key size (IC)")
        print_bar_chart([(str(k), v) for k, v in ic.items()])
        print(f"mean: {ic_mean}, stdev: {ic_stdv}")
        print(f"Best IC step: {best_ic_step} ({ic[best_ic_step]})")
    return best_ic_step, ic[best_ic_step]


def vsplit(b: bytes, n: int) -> list[bytes]:
    return [bytes(b[i::n]) for i in range(n)]


def vjoin(c: list[bytes]) -> bytes:
    return bytes(x for x in itertools.chain.from_iterable(itertools.zip_longest(*c)) if x)


def crack_ciphertext(c: str) -> str:
    b = base64.b64decode(c)

    # Guess key size
    k_s, _ = compute_ks(b, 100)

    # Obtain a list of cyphertext byte arrays encrypted with the same key byte
    # (split the cyphertext into columns by key byte)
    columns = vsplit(b, k_s)

    plaintexts = {}
    keys = {}
    for i in range(len(columns)):
        plaintexts[i], keys[i], _ = crack_ciphertext_single_byte_key(columns[i])

    plaintext = vjoin(plaintexts.values())
    key = bytes(keys.values())
    print(f"Key: {key.decode()}")
    print(plaintext.decode())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('x')
    args = parser.parse_args()

    TEST5 = False
    TEST6 = True

    if TEST5:
        pl = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
        k = "ICE"
        print(encrypt_xor(pl, k))

    if TEST6:
        with open(args.x) as f:
            crack_ciphertext(f.read().replace('\n', ''))
