# Hashcat Command Generator – CTF Edition

An interactive command-line tool that generates ready-to-paste
[hashcat](https://hashcat.net/hashcat/) commands for CTF competitions.
No more memorising hash-mode numbers or flag syntax – just answer the prompts
and copy the command.

---

## Features

- **Hash-type search** – type a keyword (e.g. `md5`, `sha256`, `ntlm`, `wpa`)
  or enter the mode number directly; the tool finds the right `-m` value for you.
- **All attack modes** – dictionary (0), combination (1), brute-force/mask (3),
  and both hybrid modes (6 & 7).
- **Built-in suggestions** – common wordlists, rule files, and mask patterns are
  shown as numbered choices so you can select them without typing long paths.
- **Extra flags** – add `--force`, `--status`, workload profile (`-w`), mask
  increment options, and any other raw hashcat flag.
- **Output file** – optionally set an `-o` path so cracked hashes are saved.
- Paths with spaces are automatically shell-quoted.

---

## Requirements

- Python 3.10 or later (uses built-in modules only – no `pip install` needed)

---

## Usage

```bash
python3 hashcat_generator.py
```

Follow the interactive prompts:

1. **Hash input** – paste the hash value directly, or enter the path to a hash file.
2. **Hash type** – search by name or enter the mode number (e.g. `1400` for SHA2-256).
3. **Attack mode** – choose dictionary, combination, brute-force, or hybrid.
4. **Attack options** – pick a wordlist, mask, and/or rule files from the numbered
   suggestions, or enter custom paths.
5. **Extra options** – add an output file and any additional flags.
6. **Copy** the generated command and paste it into your terminal.

### Example session

```
======================================================================
              HASHCAT COMMAND GENERATOR  –  CTF EDITION
======================================================================

  Step 1 – Hash input
  Hash file / hash value: hashes.txt

  Step 2 – Hash type
  Search / mode number: ntlm
  Matches for 'ntlm' (3 found):
   1. [ 1000]  NTLM
   2. [ 1100]  Domain Cached Credentials (DCC / MS Cache)
   3. [ 5500]  NetNTLMv1
  Enter number to select, or a new search term: 1

  Step 3 – Attack mode
  Attack mode [0]: 0

  Step 4 – Attack options
  Select or enter path for primary wordlist: 1   ← rockyou.txt
  Add rule file(s)? (y/N): y
  Add rule file (Enter to skip/finish): 1        ← best64.rule
  Add rule file (Enter to skip/finish):

  Step 5 – Extra options
  Output file for cracked hashes (-o): cracked.txt
  Add flag (Enter to finish): --force
  Add flag (Enter to finish):

  Generated command
  hashcat -m 1000 -a 0 -o cracked.txt hashes.txt \
      /usr/share/wordlists/rockyou.txt \
      -r /usr/share/hashcat/rules/best64.rule \
      --force
```

---

## Running the tests

```bash
python3 -m pytest tests/ -v
```

---

## Supported hash modes (selection)

| Mode  | Hash type                              |
|-------|----------------------------------------|
| 0     | MD5                                    |
| 100   | SHA1                                   |
| 1000  | NTLM                                   |
| 1400  | SHA2-256                               |
| 1700  | SHA2-512                               |
| 1800  | sha512crypt \$6\$ (SHA512 Unix)        |
| 3200  | bcrypt \$2\*\$                         |
| 5600  | NetNTLMv2                              |
| 13100 | Kerberos 5 TGS-REP etype 23 (RC4)     |
| 17400 | SHA3-256                               |
| 22000 | WPA-PBKDF2-PMKID+EAPOL (WPA/WPA2)     |

The tool knows **80+ hash modes** in total. Use the search prompt to find any of them.