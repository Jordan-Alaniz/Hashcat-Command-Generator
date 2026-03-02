#!/usr/bin/env python3
"""Hashcat Command Generator - CTF Edition

Interactively builds a hashcat command you can copy and paste,
covering hash type selection, attack modes, wordlists, masks, and rules.

Usage:
    python3 hashcat_generator.py
"""

import shlex
import sys

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

HASH_MODES: dict[int, str] = {
    # ── Raw / generic ─────────────────────────────────────────────────────────
    0:     "MD5",
    10:    "md5($pass.$salt)",
    20:    "md5($salt.$pass)",
    50:    "HMAC-MD5 (key = $pass)",
    60:    "HMAC-MD5 (key = $salt)",
    100:   "SHA1",
    110:   "sha1($pass.$salt)",
    120:   "sha1($salt.$pass)",
    150:   "HMAC-SHA1 (key = $pass)",
    160:   "HMAC-SHA1 (key = $salt)",
    900:   "MD4",
    1300:  "SHA2-224",
    1400:  "SHA2-256",
    1410:  "sha256($pass.$salt)",
    1420:  "sha256($salt.$pass)",
    1700:  "SHA2-512",
    1710:  "sha512($pass.$salt)",
    1720:  "sha512($salt.$pass)",
    10800: "SHA2-384",
    17300: "SHA3-224",
    17400: "SHA3-256",
    17500: "SHA3-384",
    17600: "SHA3-512",
    17700: "Keccak-224",
    17800: "Keccak-256",
    17900: "Keccak-384",
    18000: "Keccak-512",
    6000:  "RIPEMD-160",
    6100:  "Whirlpool",
    5100:  "Half MD5",
    # ── Unix / Linux ──────────────────────────────────────────────────────────
    500:   "md5crypt / MD5 (Unix) / Cisco-IOS $1$",
    1500:  "descrypt / DES (Unix)",
    7400:  "sha256crypt $5$ (SHA256 Unix)",
    1800:  "sha512crypt $6$ (SHA512 Unix)",
    3200:  "bcrypt $2*$ (Blowfish)",
    # ── Windows / Active Directory ────────────────────────────────────────────
    1000:  "NTLM",
    3000:  "LM",
    1100:  "Domain Cached Credentials (DCC / MS Cache)",
    5500:  "NetNTLMv1",
    5600:  "NetNTLMv2",
    13100: "Kerberos 5 TGS-REP etype 23 (RC4-HMAC)",
    19600: "Kerberos 5 TGS-REP etype 17 (AES-128)",
    19700: "Kerberos 5 TGS-REP etype 18 (AES-256)",
    18200: "Kerberos 5 AS-REP etype 23",
    19800: "Kerberos 5 AS-REQ Pre-Auth etype 17",
    19900: "Kerberos 5 AS-REQ Pre-Auth etype 18",
    # ── Web applications ──────────────────────────────────────────────────────
    400:   "phpBB3 / WordPress / Joomla (phpass)",
    10:    "md5($pass.$salt) – Django MD5",
    10000: "Django (PBKDF2-SHA256)",
    11:    "Joomla < 2.5.18",
    7900:  "Drupal7",
    300:   "MySQL4.1 / MySQL5+",
    200:   "MySQL3.23",
    11100: "PostgreSQL CRAM-MD5",
    11200: "MySQL CRAM-SHA1",
    12001: "Atlassian (PBKDF2-HMAC-SHA1)",
    16500: "JWT (JSON Web Token)",
    29100: "Flask Session Cookie",
    1600:  "Apache $apr1$ MD5",
    # ── Office / Archive / Document ───────────────────────────────────────────
    9400:  "MS Office 2007",
    9500:  "MS Office 2010",
    9600:  "MS Office 2013",
    25300: "MS Office 2016 – SheetProtection",
    31300: "MS Office 2019",
    13000: "RAR5",
    23700: "RAR3-p (Compressed)",
    11600: "7-Zip",
    13600: "WinZip",
    13400: "KeePass 1 (AES/Twofish) / KeePass 2 (AES)",
    10400: "PDF 1.1–1.3 (Acrobat 2–4)",
    10500: "PDF 1.4–1.6 (Acrobat 5–8)",
    # ── WiFi ──────────────────────────────────────────────────────────────────
    22000: "WPA-PBKDF2-PMKID+EAPOL (WPA/WPA2)",
    22001: "WPA-PMK-PMKID+EAPOL",
    # ── Crypto wallets / Blockchain ───────────────────────────────────────────
    11300: "Bitcoin/Litecoin wallet.dat",
    15600: "Ethereum Wallet PBKDF2-HMAC-SHA256",
    15700: "Ethereum Wallet SCRYPT",
    26600: "MetaMask Wallet",
    # ── Misc CTF-common ───────────────────────────────────────────────────────
    18100: "TOTP (HMAC-SHA1)",
    11500: "CRC32",
    27900: "CRC32C",
    6900:  "GOST R 34.11-94",
    8900:  "scrypt",
    12100: "PBKDF2-HMAC-SHA512",
    12000: "PBKDF2-HMAC-SHA1",
    11900: "PBKDF2-HMAC-MD5",
    5200:  "Password Safe v3",
    9200:  "Cisco-IOS $8$ (PBKDF2-SHA256)",
    9300:  "Cisco-IOS $9$ (scrypt)",
    2400:  "Cisco-PIX MD5",
    7000:  "FortiGate / FortiOS",
    16900: "Ansible Vault",
    22100: "BitLocker",
    32200: "LUKS v1 (AES-128, SHA1)",
    22400: "AES Crypt (SHA256)",
}

ATTACK_MODES: dict[int, str] = {
    0: "Straight (Dictionary Attack)",
    1: "Combination (two wordlists combined)",
    3: "Brute-force (Mask Attack)",
    6: "Hybrid – Wordlist + Mask",
    7: "Hybrid – Mask + Wordlist",
}

COMMON_WORDLISTS: list[str] = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/fasttrack.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt",
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt",
]

COMMON_RULES: list[str] = [
    "/usr/share/hashcat/rules/best64.rule",
    "/usr/share/hashcat/rules/rockyou-30000.rule",
    "/usr/share/hashcat/rules/dive.rule",
    "/usr/share/hashcat/rules/d3ad0ne.rule",
    "/usr/share/hashcat/rules/InsidePro-PasswordsPro.rule",
    "/usr/share/hashcat/rules/T0XlC.rule",
    "/usr/share/hashcat/rules/leetspeak.rule",
    "/usr/share/hashcat/rules/toggles5.rule",
]

MASK_CHARSETS: dict[str, str] = {
    "?l": "lowercase letters   (a-z)",
    "?u": "uppercase letters   (A-Z)",
    "?d": "digits              (0-9)",
    "?s": "special characters  (!@#$…)",
    "?a": "all printable ASCII (?l?u?d?s)",
    "?b": "all bytes           (0x00–0xff)",
    "?h": "hex lowercase       (0-9, a-f)",
    "?H": "hex uppercase       (0-9, A-F)",
}

COMMON_MASKS: list[tuple[str, str]] = [
    ("?d?d?d?d",           "4-digit PIN"),
    ("?d?d?d?d?d?d",       "6-digit PIN"),
    ("?d?d?d?d?d?d?d?d",   "8-digit number"),
    ("?l?l?l?l?l?l",       "6 lowercase letters"),
    ("?l?l?l?l?l?l?l?l",   "8 lowercase letters"),
    ("?u?l?l?l?l?l?l?d",   "Capital + 6 lower + digit  (8 chars)"),
    ("?l?l?l?l?d?d?d?d",   "4 lower + 4 digits"),
    ("?a?a?a?a?a?a",        "6 any printable chars"),
    ("?a?a?a?a?a?a?a?a",    "8 any printable chars"),
    ("?a?a?a?a?a?a?a?a?a?a", "10 any printable chars"),
]

# ──────────────────────────────────────────────────────────────────────────────
# Core logic (importable / testable)
# ──────────────────────────────────────────────────────────────────────────────

def search_hash_modes(query: str) -> list[tuple[int, str]]:
    """Return (mode, name) pairs whose mode number or name match *query*.

    The search is case-insensitive.  Results are sorted by mode number.
    """
    q = query.lower()
    return sorted(
        [
            (mode, name)
            for mode, name in HASH_MODES.items()
            if q in str(mode) or q in name.lower()
        ],
        key=lambda x: x[0],
    )


def build_command(options: dict) -> str:
    """Build and return a hashcat command string from *options*.

    Required keys:
        hash_input  (str) – path to hash file, or a raw hash value
        hash_mode   (int) – hashcat -m value
        attack_mode (int) – hashcat -a value (0, 1, 3, 6, 7)

    Optional keys (required for specific attack modes):
        wordlist  (str)       – wordlist path (modes 0, 6, 7)
        wordlist2 (str)       – second wordlist (mode 1)
        mask      (str)       – mask pattern   (modes 3, 6, 7)
        rules     (list[str]) – rule-file paths (mode 0)
        output_file (str)     – -o output file
        extra_flags (list[str]) – additional raw flags appended at the end
    """
    parts: list[str] = ["hashcat"]
    parts += ["-m", str(options["hash_mode"])]
    parts += ["-a", str(options["attack_mode"])]

    output_file = options.get("output_file", "")
    if output_file:
        parts += ["-o", shlex.quote(output_file)]

    parts.append(shlex.quote(options["hash_input"]))

    attack_mode = options["attack_mode"]

    if attack_mode == 0:
        wordlist = options.get("wordlist", "")
        if wordlist:
            parts.append(shlex.quote(wordlist))
        for rule in options.get("rules") or []:
            parts += ["-r", shlex.quote(rule)]

    elif attack_mode == 1:
        wordlist = options.get("wordlist", "")
        wordlist2 = options.get("wordlist2", "")
        if wordlist:
            parts.append(shlex.quote(wordlist))
        if wordlist2:
            parts.append(shlex.quote(wordlist2))
        for rule in options.get("rules") or []:
            parts += ["-r", shlex.quote(rule)]

    elif attack_mode == 3:
        mask = options.get("mask", "")
        if mask:
            parts.append(mask)

    elif attack_mode == 6:
        wordlist = options.get("wordlist", "")
        mask = options.get("mask", "")
        if wordlist:
            parts.append(shlex.quote(wordlist))
        if mask:
            parts.append(mask)
        for rule in options.get("rules") or []:
            parts += ["-r", shlex.quote(rule)]

    elif attack_mode == 7:
        mask = options.get("mask", "")
        wordlist = options.get("wordlist", "")
        if mask:
            parts.append(mask)
        if wordlist:
            parts.append(shlex.quote(wordlist))
        for rule in options.get("rules") or []:
            parts += ["-r", shlex.quote(rule)]

    for flag in options.get("extra_flags") or []:
        parts.append(flag)

    return " ".join(parts)


# ──────────────────────────────────────────────────────────────────────────────
# Display helpers
# ──────────────────────────────────────────────────────────────────────────────

WIDTH = 70


def _banner() -> None:
    print("=" * WIDTH)
    title = "HASHCAT COMMAND GENERATOR  –  CTF EDITION"
    print(title.center(WIDTH))
    print("=" * WIDTH)


def _section(title: str) -> None:
    print(f"\n{'─' * WIDTH}")
    print(f"  {title}")
    print(f"{'─' * WIDTH}")


def _numbered_list(items: list[str], start: int = 1) -> None:
    for i, item in enumerate(items, start):
        print(f"  {i:2d}. {item}")


def _prompt(label: str, default: str = "") -> str:
    """Print a prompt and return stripped input.  Returns *default* on empty."""
    hint = f" [{default}]" if default else ""
    try:
        value = input(f"  {label}{hint}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    return value if value else default


def _yes(label: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    answer = _prompt(f"{label} ({hint})")
    if not answer:
        return default
    return answer.lower().startswith("y")


# ──────────────────────────────────────────────────────────────────────────────
# Interactive prompts
# ──────────────────────────────────────────────────────────────────────────────

def prompt_hash_input() -> str:
    """Ask the user for the hash file path or raw hash value."""
    _section("Step 1 – Hash input")
    print("  Enter the path to your hash file, OR paste the hash directly.")
    while True:
        value = _prompt("Hash file / hash value")
        if value:
            return value
        print("  ✗  Input cannot be empty. Please try again.")


def prompt_hash_mode() -> int:
    """Interactively select a hashcat -m mode number."""
    _section("Step 2 – Hash type")
    print("  Type a search term (e.g. 'md5', 'sha256', 'ntlm', 'wpa')")
    print("  or enter the mode number directly.")
    while True:
        query = _prompt("Search / mode number")
        if not query:
            continue

        # Direct numeric input
        if query.isdigit():
            mode = int(query)
            name = HASH_MODES.get(mode, "(unknown – not in common list)")
            print(f"  → Mode {mode}: {name}")
            if _yes("Use this mode?", default=True):
                return mode
            continue

        # Text search
        results = search_hash_modes(query)
        if not results:
            print(f"  ✗  No modes found for '{query}'. Try again.")
            continue

        display = results[:20]
        print(f"\n  Matches for '{query}' ({len(results)} found"
              + (", showing first 20" if len(results) > 20 else "") + "):\n")
        for i, (mode, name) in enumerate(display, 1):
            print(f"  {i:2d}. [{mode:5d}]  {name}")

        choice = _prompt("\n  Enter number to select, or a new search term")
        if not choice:
            continue
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(display):
                return display[idx][0]
            # Treat as mode number if out of list range
            mode = int(choice)
            name = HASH_MODES.get(mode, "(unknown)")
            print(f"  → Mode {mode}: {name}")
            if _yes("Use this mode?", default=True):
                return mode
        # Otherwise treat as new search query (loop continues with query=choice)


def prompt_attack_mode() -> int:
    """Let the user pick an attack mode."""
    _section("Step 3 – Attack mode")
    for mode, desc in ATTACK_MODES.items():
        print(f"  [{mode}]  {desc}")
    while True:
        raw = _prompt("\n  Attack mode", default="0")
        if raw.isdigit() and int(raw) in ATTACK_MODES:
            return int(raw)
        print(f"  ✗  Please enter one of: {list(ATTACK_MODES.keys())}")


def _pick_wordlist(label: str = "Wordlist") -> str:
    """Show common wordlists and let the user pick one or enter a custom path."""
    print(f"\n  Common wordlists:")
    _numbered_list(COMMON_WORDLISTS)
    print(f"  {len(COMMON_WORDLISTS) + 1:2d}. Enter custom path")
    while True:
        raw = _prompt(f"  Select or enter path for {label}")
        if not raw:
            return ""
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(COMMON_WORDLISTS):
                return COMMON_WORDLISTS[idx]
            if idx == len(COMMON_WORDLISTS):
                path = _prompt("  Custom wordlist path")
                return path
        # Treat as a direct path
        return raw


def _pick_rules() -> list[str]:
    """Let the user choose zero or more rule files."""
    chosen: list[str] = []
    print("\n  Common rule files:")
    _numbered_list(COMMON_RULES)
    print(f"  {len(COMMON_RULES) + 1:2d}. Enter custom rule path")
    print("  (Press Enter with no input when done.)\n")
    while True:
        raw = _prompt("  Add rule file (Enter to skip/finish)")
        if not raw:
            break
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(COMMON_RULES):
                chosen.append(COMMON_RULES[idx])
                print(f"  ✓  Added: {COMMON_RULES[idx]}")
                continue
            if idx == len(COMMON_RULES):
                path = _prompt("  Custom rule path")
                if path:
                    chosen.append(path)
                continue
        # Direct path
        chosen.append(raw)
        print(f"  ✓  Added: {raw}")
    return chosen


def _pick_mask() -> str:
    """Show common masks and let the user choose or enter a custom one."""
    print("\n  Mask charset reference:")
    for cs, desc in MASK_CHARSETS.items():
        print(f"    {cs}  →  {desc}")
    print("\n  Common masks:")
    for i, (mask, desc) in enumerate(COMMON_MASKS, 1):
        print(f"  {i:2d}. {mask:<30s}  {desc}")
    print(f"  {len(COMMON_MASKS) + 1:2d}. Enter custom mask")
    while True:
        raw = _prompt("  Select or enter mask")
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(COMMON_MASKS):
                return COMMON_MASKS[idx][0]
            if idx == len(COMMON_MASKS):
                mask = _prompt("  Custom mask")
                return mask
        # Treat as direct mask
        if raw:
            return raw


def prompt_attack_options(attack_mode: int) -> dict:
    """Collect wordlist / mask / rules based on the chosen attack mode."""
    options: dict = {}

    _section(f"Step 4 – Attack options  (mode {attack_mode}: {ATTACK_MODES[attack_mode]})")

    if attack_mode == 0:
        print("\n  Dictionary attack: one wordlist, optional rules.")
        options["wordlist"] = _pick_wordlist("primary wordlist")
        if _yes("Add rule file(s)?", default=False):
            options["rules"] = _pick_rules()

    elif attack_mode == 1:
        print("\n  Combination attack: two wordlists are combined.")
        options["wordlist"] = _pick_wordlist("first wordlist")
        options["wordlist2"] = _pick_wordlist("second wordlist")
        if _yes("Add rule file(s)?", default=False):
            options["rules"] = _pick_rules()

    elif attack_mode == 3:
        print("\n  Brute-force / mask attack.")
        options["mask"] = _pick_mask()

    elif attack_mode == 6:
        print("\n  Hybrid attack: mask is appended to each wordlist entry.")
        options["wordlist"] = _pick_wordlist("wordlist")
        options["mask"] = _pick_mask()
        if _yes("Add rule file(s)?", default=False):
            options["rules"] = _pick_rules()

    elif attack_mode == 7:
        print("\n  Hybrid attack: mask is prefixed to each wordlist entry.")
        options["mask"] = _pick_mask()
        options["wordlist"] = _pick_wordlist("wordlist")
        if _yes("Add rule file(s)?", default=False):
            options["rules"] = _pick_rules()

    return options


def prompt_extra_options() -> dict:
    """Optionally gather output file and extra flags."""
    _section("Step 5 – Extra options  (all optional)")
    options: dict = {}

    out = _prompt("Output file for cracked hashes (-o)")
    if out:
        options["output_file"] = out

    extras: list[str] = []
    print("\n  Common extra flags:")
    print("    --force              ignore warnings (e.g. OpenCL not found)")
    print("    --status             enable automatic status screen updates")
    print("    --potfile-disable    do not use/write the .pot file")
    print("    -w 3                 workload profile  (1=min … 4=nightmare)")
    print("    --increment          enable incremental mask lengths")
    print("    --increment-min N    minimum mask length")
    print("    --increment-max N    maximum mask length")
    print("  (Press Enter with no input when done.)\n")
    while True:
        flag = _prompt("Add flag (Enter to finish)")
        if not flag:
            break
        extras.append(flag)
        print(f"  ✓  Added: {flag}")
    if extras:
        options["extra_flags"] = extras

    return options


# ──────────────────────────────────────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────────────────────────────────────

def run() -> None:
    """Interactive session that builds and prints the hashcat command."""
    _banner()

    hash_input = prompt_hash_input()
    hash_mode = prompt_hash_mode()
    attack_mode = prompt_attack_mode()
    attack_opts = prompt_attack_options(attack_mode)
    extra_opts = prompt_extra_options()

    options = {
        "hash_input": hash_input,
        "hash_mode": hash_mode,
        "attack_mode": attack_mode,
        **attack_opts,
        **extra_opts,
    }

    command = build_command(options)

    _section("Generated command")
    print()
    print(f"  {command}")
    print()
    print("  Copy the command above and paste it into your terminal.")
    print("=" * WIDTH)

    if _yes("\nGenerate another command?", default=False):
        print()
        run()


if __name__ == "__main__":
    run()
