#!/usr/bin/env python3
"""
HashCracker - Hash Identification & Cracking Tool
For authorized security auditing only.
"""

import argparse
import hashlib
import sys
import os
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = MAGENTA = RESET = ""
    class Style:
        RESET_ALL = ""

VERSION = "1.0.0"

HASH_PATTERNS = {
    "MD5": (r'^[a-fA-F0-9]{32}$', 32),
    "SHA1": (r'^[a-fA-F0-9]{40}$', 40),
    "SHA224": (r'^[a-fA-F0-9]{56}$', 56),
    "SHA256": (r'^[a-fA-F0-9]{64}$', 64),
    "SHA384": (r'^[a-fA-F0-9]{96}$', 96),
    "SHA512": (r'^[a-fA-F0-9]{128}$', 128),
    "NTLM": (r'^[a-fA-F0-9]{32}$', 32),
    "MySQL5": (r'^\*[a-fA-F0-9]{40}$', 41),
    "bcrypt": (r'^\$2[aby]?\$\d{1,2}\$[./A-Za-z0-9]{53}$', 60),
    "SHA512crypt": (r'^\$6\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{86}$', None),
    "MD5crypt": (r'^\$1\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{22}$', None),
}


def identify_hash(hash_str):
    """Identify possible hash types."""
    hash_str = hash_str.strip()
    possible = []

    for name, (pattern, length) in HASH_PATTERNS.items():
        if re.match(pattern, hash_str):
            possible.append(name)

    # MD5 and NTLM have same length - both shown
    if not possible:
        # Try length-based identification
        hlen = len(hash_str)
        length_map = {32: ["MD5", "NTLM"], 40: ["SHA1"], 56: ["SHA224"],
                      64: ["SHA256"], 96: ["SHA384"], 128: ["SHA512"]}
        possible = length_map.get(hlen, [])

    return possible


def hash_word(word, algorithm, salt=""):
    """Hash a word with the given algorithm."""
    data = (salt + word).encode('utf-8') if salt else word.encode('utf-8')

    algorithms = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
        'ntlm': lambda d: hashlib.new('md4', word.encode('utf-16-le')),
    }

    if algorithm in algorithms:
        return algorithms[algorithm](data).hexdigest()
    return None


def apply_rules(word, rules):
    """Apply mutation rules to generate word variants."""
    variants = {word}

    for rule in rules:
        if rule == "upper":
            variants.add(word.upper())
        elif rule == "lower":
            variants.add(word.lower())
        elif rule == "capitalize":
            variants.add(word.capitalize())
        elif rule == "reverse":
            variants.add(word[::-1])
        elif rule == "leetspeak":
            leet = word.replace('a', '4').replace('e', '3').replace('i', '1')
            leet = leet.replace('o', '0').replace('s', '5').replace('t', '7')
            variants.add(leet)
        elif rule == "append_numbers":
            for i in range(100):
                variants.add(f"{word}{i}")
        elif rule == "prepend_numbers":
            for i in range(100):
                variants.add(f"{i}{word}")

    return variants


class HashCracker:
    def __init__(self, algorithm, wordlist, threads=4, salt="", rules=None):
        self.algorithm = algorithm
        self.wordlist = wordlist
        self.threads = threads
        self.salt = salt
        self.rules = rules or []
        self.found = {}
        self.attempts = 0
        self.start_time = None
        self.total_words = 0
        self.lock = threading.Lock()

    def load_hashes(self, hash_input):
        """Load target hashes."""
        if os.path.isfile(hash_input):
            with open(hash_input) as f:
                return [line.strip().lower() for line in f if line.strip()]
        return [h.strip().lower() for h in hash_input.split(",")]

    def count_words(self):
        """Count total words in wordlist."""
        try:
            with open(self.wordlist, 'rb') as f:
                return sum(1 for _ in f)
        except:
            return 0

    def crack(self, target_hashes):
        """Crack hashes using dictionary attack."""
        targets = {h.lower(): None for h in target_hashes}
        self.total_words = self.count_words()
        self.start_time = time.time()

        print(f"\n{Fore.CYAN}[*] Algorithm: {self.algorithm.upper()}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Wordlist: {self.wordlist} ({self.total_words:,} words){Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Target hashes: {len(targets)}{Style.RESET_ALL}")
        if self.rules:
            print(f"{Fore.CYAN}[*] Rules: {', '.join(self.rules)}{Style.RESET_ALL}")
        print()

        with open(self.wordlist, 'r', errors='ignore') as f:
            for line in f:
                word = line.strip()
                if not word:
                    continue

                words_to_try = {word}
                if self.rules:
                    words_to_try = apply_rules(word, self.rules)

                for w in words_to_try:
                    h = hash_word(w, self.algorithm, self.salt)
                    if h and h.lower() in targets and targets[h.lower()] is None:
                        targets[h.lower()] = w
                        print(f"  {Fore.GREEN}[+] CRACKED: {h} => {w}{Style.RESET_ALL}")

                    with self.lock:
                        self.attempts += 1

                # Progress update every 100k attempts
                if self.attempts % 100000 == 0 and self.attempts > 0:
                    elapsed = time.time() - self.start_time
                    rate = self.attempts / elapsed
                    remaining = (self.total_words - self.attempts) / rate if rate > 0 else 0
                    cracked = sum(1 for v in targets.values() if v is not None)
                    print(f"  {Fore.YELLOW}[*] {self.attempts:,} attempts | "
                          f"{rate:,.0f}/sec | {cracked}/{len(targets)} cracked | "
                          f"ETA: {timedelta(seconds=int(remaining))}{Style.RESET_ALL}")

                # Stop if all cracked
                if all(v is not None for v in targets.values()):
                    break

        elapsed = time.time() - self.start_time
        self.found = {k: v for k, v in targets.items() if v is not None}

        print(f"\n{Fore.CYAN}{'='*50}")
        print(f"  RESULTS")
        print(f"{'='*50}{Style.RESET_ALL}")
        print(f"  Total attempts: {self.attempts:,}")
        print(f"  Time elapsed: {elapsed:.1f}s")
        print(f"  Speed: {self.attempts/elapsed:,.0f} hashes/sec")
        print(f"  Cracked: {len(self.found)}/{len(target_hashes)}")

        if self.found:
            print(f"\n  {Fore.GREEN}Cracked Hashes:{Style.RESET_ALL}")
            for h, w in self.found.items():
                print(f"    {h} => {Fore.GREEN}{w}{Style.RESET_ALL}")

        unc = [h for h, v in targets.items() if v is None]
        if unc:
            print(f"\n  {Fore.RED}Uncracked: {len(unc)}{Style.RESET_ALL}")

        return self.found

    def generate(self, word, algorithm, salt=""):
        """Generate hash for a word."""
        h = hash_word(word, algorithm, salt)
        if h:
            print(f"\n  {Fore.CYAN}Algorithm:{Style.RESET_ALL} {algorithm.upper()}")
            if salt:
                print(f"  {Fore.CYAN}Salt:{Style.RESET_ALL} {salt}")
            print(f"  {Fore.CYAN}Input:{Style.RESET_ALL}  {word}")
            print(f"  {Fore.CYAN}Hash:{Style.RESET_ALL}   {h}")
            return h
        else:
            print(f"{Fore.RED}[!] Unsupported algorithm: {algorithm}{Style.RESET_ALL}")
            return None


def main():
    parser = argparse.ArgumentParser(
        description="HashCracker - Hash Identification & Cracking Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s identify 5d41402abc4b2a76b9719d911017c592
  %(prog)s crack 5d41402abc4b2a76b9719d911017c592 -w wordlist.txt -t md5
  %(prog)s crack -f hashes.txt -w wordlist.txt -t md5 --rules
  %(prog)s generate "password123" -t sha256
        """
    )

    sub = parser.add_subparsers(dest="command")

    # identify
    ident = sub.add_parser("identify", help="Identify hash type")
    ident.add_argument("hash", help="Hash string to identify")

    # crack
    crack = sub.add_parser("crack", help="Crack hash(es)")
    crack.add_argument("hash", nargs="?", help="Hash to crack")
    crack.add_argument("-f", "--file", help="File containing hashes")
    crack.add_argument("-w", "--wordlist", required=True, help="Wordlist file")
    crack.add_argument("-t", "--type", default="md5",
                       choices=["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "ntlm"],
                       help="Hash algorithm")
    crack.add_argument("-s", "--salt", default="", help="Salt for hashing")
    crack.add_argument("--threads", type=int, default=4, help="Thread count")
    crack.add_argument("--rules", action="store_true", help="Apply word mutation rules")
    crack.add_argument("--output", help="Save results to file")

    # generate
    gen = sub.add_parser("generate", help="Generate hash")
    gen.add_argument("word", help="Word to hash")
    gen.add_argument("-t", "--type", default="md5",
                     choices=["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "ntlm"],
                     help="Hash algorithm")
    gen.add_argument("-s", "--salt", default="", help="Salt for hashing")

    args = parser.parse_args()

    print(f"\n{Fore.CYAN}╔══════════════════════════════════╗")
    print(f"║    HashCracker v{VERSION}          ║")
    print(f"╚══════════════════════════════════╝{Style.RESET_ALL}")

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "identify":
        possible = identify_hash(args.hash)
        print(f"\n  {Fore.CYAN}Hash:{Style.RESET_ALL} {args.hash}")
        print(f"  {Fore.CYAN}Length:{Style.RESET_ALL} {len(args.hash)}")
        if possible:
            print(f"  {Fore.GREEN}Possible types:{Style.RESET_ALL}")
            for h in possible:
                print(f"    - {h}")
        else:
            print(f"  {Fore.RED}Could not identify hash type{Style.RESET_ALL}")

    elif args.command == "crack":
        rules = ["capitalize", "upper", "leetspeak", "append_numbers"] if args.rules else []
        cracker = HashCracker(args.type, args.wordlist, args.threads, args.salt, rules)

        if args.file:
            hashes = cracker.load_hashes(args.file)
        elif args.hash:
            hashes = [args.hash]
        else:
            print(f"{Fore.RED}[!] Provide hash with -f or as argument{Style.RESET_ALL}")
            sys.exit(1)

        results = cracker.crack(hashes)

        if args.output:
            with open(args.output, 'w') as f:
                for h, w in results.items():
                    f.write(f"{h}:{w}\n")
            print(f"\n{Fore.GREEN}[+] Results saved to {args.output}{Style.RESET_ALL}")

    elif args.command == "generate":
        cracker = HashCracker(args.type, "", salt=args.salt)
        cracker.generate(args.word, args.type, args.salt)


if __name__ == "__main__":
    main()
