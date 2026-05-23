# HashCracker - Hash Identification & Cracking Tool

A multi-algorithm hash identifier and dictionary-based password recovery tool for security auditing. Supports MD5, SHA1, SHA256, SHA512, NTLM, and bcrypt.

## Features

- Automatic hash type identification
- Dictionary-based password cracking
- Multi-threaded processing
- Support for 15+ hash algorithms
- Salted hash support
- Progress tracking and ETA
- Rule-based word mutations

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/hash-cracker.git
cd hash-cracker
pip3 install -r requirements.txt
chmod +x hashcracker.py
```

## Usage

### Identify Hash Type
```bash
python3 hashcracker.py identify 5d41402abc4b2a76b9719d911017c592
python3 hashcracker.py identify '$2b$12$LJ3m4ys3Lz0YBNOURq0Y3OjCfKJmKPOJYqDTPVCKpOLHSJqO9WOea'
```

### Crack Hash with Dictionary
```bash
# Single hash
python3 hashcracker.py crack 5d41402abc4b2a76b9719d911017c592 -w wordlist.txt -t md5

# Multiple hashes from file
python3 hashcracker.py crack -f hashes.txt -w wordlist.txt -t md5

# With specific algorithm
python3 hashcracker.py crack hash.txt -w wordlist.txt -t sha256

# NTLM cracking
python3 hashcracker.py crack hash.txt -w wordlist.txt -t ntlm

# With rules (word mutations)
python3 hashcracker.py crack hash.txt -w wordlist.txt -t md5 --rules
```

### Generate Hash
```bash
python3 hashcracker.py generate "password123" -t md5
python3 hashcracker.py generate "password123" -t sha256 --salt mysalt
```

### Supported Algorithms

| Algorithm | Hash Length | Example |
|-----------|-------------|---------|
| MD5       | 32 chars    | 5d41402abc4b2a76b9719d911017c592 |
| SHA1      | 40 chars    | aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d |
| SHA256    | 64 chars    | 2cf24dba5fb0a30e26e83b2ac5b9e29e... |
| SHA512    | 128 chars   | 9b71d224bd62f3785d96d46ad3ea3d73... |
| NTLM      | 32 chars    | a4f49c406510bdcab6824ee7c30fd852 |
| bcrypt    | 60 chars    | $2b$12$... |

### Wordlist Downloads

```bash
# Download SecLists wordlists
git clone https://github.com/danielmiessler/SecLists.git

# RockYou (common passwords)
# Available at /usr/share/wordlists/rockyou.txt on Kali Linux
```

## Legal Disclaimer

This tool is for authorized security auditing and educational purposes only. Do not use it to crack passwords you don't own or have authorization to test.

## License

MIT License
