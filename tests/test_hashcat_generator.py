"""Unit tests for hashcat_generator.py"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hashcat_generator import (
    HASH_MODES,
    ATTACK_MODES,
    build_command,
    search_hash_modes,
)


# ──────────────────────────────────────────────────────────────────────────────
# search_hash_modes
# ──────────────────────────────────────────────────────────────────────────────

class TestSearchHashModes:
    def test_search_by_name_case_insensitive(self):
        results = search_hash_modes("md5")
        names = [name.lower() for _, name in results]
        assert any("md5" in n for n in names)

    def test_search_by_exact_mode_number(self):
        results = search_hash_modes("1400")
        modes = [mode for mode, _ in results]
        assert 1400 in modes

    def test_search_returns_sorted_by_mode(self):
        results = search_hash_modes("sha")
        modes = [mode for mode, _ in results]
        assert modes == sorted(modes)

    def test_search_no_match_returns_empty(self):
        results = search_hash_modes("xyzzy_nonexistent_xyz")
        assert results == []

    def test_search_ntlm(self):
        results = search_hash_modes("ntlm")
        names = [name.lower() for _, name in results]
        assert any("ntlm" in n for n in names)

    def test_search_kerberos(self):
        results = search_hash_modes("kerberos")
        assert len(results) >= 1

    def test_search_returns_tuples(self):
        results = search_hash_modes("sha1")
        assert all(isinstance(mode, int) and isinstance(name, str)
                   for mode, name in results)


# ──────────────────────────────────────────────────────────────────────────────
# build_command – mode 0: dictionary
# ──────────────────────────────────────────────────────────────────────────────

class TestBuildCommandDictionary:
    BASE = {
        "hash_input": "hashes.txt",
        "hash_mode": 0,
        "attack_mode": 0,
        "wordlist": "/usr/share/wordlists/rockyou.txt",
    }

    def test_basic_dictionary_command(self):
        cmd = build_command(self.BASE)
        assert cmd == (
            "hashcat -m 0 -a 0 hashes.txt "
            "/usr/share/wordlists/rockyou.txt"
        )

    def test_with_output_file(self):
        opts = {**self.BASE, "output_file": "cracked.txt"}
        cmd = build_command(opts)
        assert "-o cracked.txt" in cmd

    def test_with_single_rule(self):
        opts = {**self.BASE, "rules": ["/usr/share/hashcat/rules/best64.rule"]}
        cmd = build_command(opts)
        assert "-r /usr/share/hashcat/rules/best64.rule" in cmd

    def test_with_multiple_rules(self):
        opts = {
            **self.BASE,
            "rules": [
                "/usr/share/hashcat/rules/best64.rule",
                "/usr/share/hashcat/rules/dive.rule",
            ],
        }
        cmd = build_command(opts)
        assert cmd.count("-r") == 2
        assert "/usr/share/hashcat/rules/best64.rule" in cmd
        assert "/usr/share/hashcat/rules/dive.rule" in cmd

    def test_with_extra_flags(self):
        opts = {**self.BASE, "extra_flags": ["--force", "-w", "3"]}
        cmd = build_command(opts)
        assert cmd.endswith("--force -w 3")

    def test_hash_input_with_spaces_is_quoted(self):
        opts = {**self.BASE, "hash_input": "my hashes.txt"}
        cmd = build_command(opts)
        assert "'my hashes.txt'" in cmd or '"my hashes.txt"' in cmd

    def test_output_file_with_spaces_is_quoted(self):
        opts = {**self.BASE, "output_file": "my output.txt"}
        cmd = build_command(opts)
        assert "'" in cmd or '"' in cmd

    def test_wordlist_with_spaces_is_quoted(self):
        opts = {**self.BASE, "wordlist": "/path with spaces/rockyou.txt"}
        cmd = build_command(opts)
        assert "'" in cmd or '"' in cmd


# ──────────────────────────────────────────────────────────────────────────────
# build_command – mode 1: combination
# ──────────────────────────────────────────────────────────────────────────────

class TestBuildCommandCombination:
    BASE = {
        "hash_input": "hashes.txt",
        "hash_mode": 100,
        "attack_mode": 1,
        "wordlist": "/usr/share/wordlists/names.txt",
        "wordlist2": "/usr/share/wordlists/dates.txt",
    }

    def test_combination_command(self):
        cmd = build_command(self.BASE)
        assert "-a 1" in cmd
        assert "/usr/share/wordlists/names.txt" in cmd
        assert "/usr/share/wordlists/dates.txt" in cmd

    def test_combination_wordlist_order(self):
        cmd = build_command(self.BASE)
        pos1 = cmd.index("names.txt")
        pos2 = cmd.index("dates.txt")
        assert pos1 < pos2

    def test_combination_with_single_rule(self):
        opts = {**self.BASE, "rules": ["/usr/share/hashcat/rules/best64.rule"]}
        cmd = build_command(opts)
        assert "-r /usr/share/hashcat/rules/best64.rule" in cmd

    def test_combination_with_multiple_rules(self):
        opts = {**self.BASE, "rules": ["/usr/share/hashcat/rules/best64.rule", "/usr/share/hashcat/rules/dive.rule"]}
        cmd = build_command(opts)
        assert cmd.count("-r") == 2
        assert "/usr/share/hashcat/rules/best64.rule" in cmd
        assert "/usr/share/hashcat/rules/dive.rule" in cmd

    def test_combination_with_custom_rule(self):
        opts = {**self.BASE, "rules": ["/home/user/my_custom.rule"]}
        cmd = build_command(opts)
        assert "-r /home/user/my_custom.rule" in cmd


# ──────────────────────────────────────────────────────────────────────────────
# build_command – mode 3: brute-force / mask
# ──────────────────────────────────────────────────────────────────────────────

class TestBuildCommandBruteforce:
    BASE = {
        "hash_input": "hashes.txt",
        "hash_mode": 1400,
        "attack_mode": 3,
        "mask": "?l?l?l?l?l?l?l?l",
    }

    def test_bruteforce_command(self):
        cmd = build_command(self.BASE)
        assert "-a 3" in cmd
        assert "?l?l?l?l?l?l?l?l" in cmd

    def test_bruteforce_with_digit_mask(self):
        opts = {**self.BASE, "mask": "?d?d?d?d?d?d"}
        cmd = build_command(opts)
        assert "?d?d?d?d?d?d" in cmd

    def test_bruteforce_with_extra_flags(self):
        opts = {**self.BASE, "extra_flags": ["--increment", "--increment-max", "8"]}
        cmd = build_command(opts)
        assert "--increment" in cmd
        assert "--increment-max" in cmd
        assert "8" in cmd


# ──────────────────────────────────────────────────────────────────────────────
# build_command – mode 6: hybrid wordlist + mask
# ──────────────────────────────────────────────────────────────────────────────

class TestBuildCommandHybridWL:
    BASE = {
        "hash_input": "hashes.txt",
        "hash_mode": 1000,
        "attack_mode": 6,
        "wordlist": "/usr/share/wordlists/rockyou.txt",
        "mask": "?d?d?d",
    }

    def test_hybrid_wl_mask_order(self):
        cmd = build_command(self.BASE)
        assert "-a 6" in cmd
        pos_wl = cmd.index("rockyou.txt")
        pos_mask = cmd.index("?d?d?d")
        assert pos_wl < pos_mask

    def test_hybrid_wl_with_single_rule(self):
        opts = {**self.BASE, "rules": ["/usr/share/hashcat/rules/best64.rule"]}
        cmd = build_command(opts)
        assert "-r /usr/share/hashcat/rules/best64.rule" in cmd

    def test_hybrid_wl_with_custom_rule(self):
        opts = {**self.BASE, "rules": ["/home/user/ctf.rule"]}
        cmd = build_command(opts)
        assert "-r /home/user/ctf.rule" in cmd

    def test_hybrid_wl_rule_after_mask(self):
        opts = {**self.BASE, "rules": ["/usr/share/hashcat/rules/best64.rule"]}
        cmd = build_command(opts)
        pos_mask = cmd.index("?d?d?d")
        pos_rule = cmd.index("-r")
        assert pos_mask < pos_rule


# ──────────────────────────────────────────────────────────────────────────────
# build_command – mode 7: hybrid mask + wordlist
# ──────────────────────────────────────────────────────────────────────────────

class TestBuildCommandHybridMask:
    BASE = {
        "hash_input": "hashes.txt",
        "hash_mode": 1000,
        "attack_mode": 7,
        "mask": "?d?d",
        "wordlist": "/usr/share/wordlists/rockyou.txt",
    }

    def test_hybrid_mask_wl_order(self):
        cmd = build_command(self.BASE)
        assert "-a 7" in cmd
        pos_mask = cmd.index("?d?d")
        pos_wl = cmd.index("rockyou.txt")
        assert pos_mask < pos_wl

    def test_hybrid_mask_with_single_rule(self):
        opts = {**self.BASE, "rules": ["/usr/share/hashcat/rules/best64.rule"]}
        cmd = build_command(opts)
        assert "-r /usr/share/hashcat/rules/best64.rule" in cmd

    def test_hybrid_mask_with_custom_rule(self):
        opts = {**self.BASE, "rules": ["/home/user/ctf.rule"]}
        cmd = build_command(opts)
        assert "-r /home/user/ctf.rule" in cmd

    def test_hybrid_mask_rule_after_wordlist(self):
        opts = {**self.BASE, "rules": ["/usr/share/hashcat/rules/best64.rule"]}
        cmd = build_command(opts)
        pos_wl = cmd.index("rockyou.txt")
        pos_rule = cmd.index("-r")
        assert pos_wl < pos_rule


# ──────────────────────────────────────────────────────────────────────────────
# build_command – general
# ──────────────────────────────────────────────────────────────────────────────

class TestBuildCommandGeneral:
    def test_command_starts_with_hashcat(self):
        opts = {
            "hash_input": "h.txt",
            "hash_mode": 0,
            "attack_mode": 0,
        }
        assert build_command(opts).startswith("hashcat")

    def test_mode_flag_present(self):
        opts = {
            "hash_input": "h.txt",
            "hash_mode": 1800,
            "attack_mode": 3,
            "mask": "?a?a?a?a?a?a",
        }
        cmd = build_command(opts)
        assert "-m 1800" in cmd

    def test_attack_mode_flag_present(self):
        opts = {
            "hash_input": "h.txt",
            "hash_mode": 0,
            "attack_mode": 3,
            "mask": "?d?d?d?d",
        }
        cmd = build_command(opts)
        assert "-a 3" in cmd

    def test_no_output_file_by_default(self):
        opts = {
            "hash_input": "h.txt",
            "hash_mode": 0,
            "attack_mode": 0,
            "wordlist": "list.txt",
        }
        assert "-o" not in build_command(opts)

    def test_raw_hash_value_as_input(self):
        opts = {
            "hash_input": "5d41402abc4b2a76b9719d911017c592",
            "hash_mode": 0,
            "attack_mode": 0,
            "wordlist": "rockyou.txt",
        }
        cmd = build_command(opts)
        assert "5d41402abc4b2a76b9719d911017c592" in cmd


# ──────────────────────────────────────────────────────────────────────────────
# Constants sanity checks
# ──────────────────────────────────────────────────────────────────────────────

class TestConstants:
    def test_hash_modes_not_empty(self):
        assert len(HASH_MODES) > 0

    def test_attack_modes_contains_required(self):
        for mode in (0, 1, 3, 6, 7):
            assert mode in ATTACK_MODES

    def test_common_modes_present(self):
        assert 0 in HASH_MODES      # MD5
        assert 100 in HASH_MODES    # SHA1
        assert 1000 in HASH_MODES   # NTLM
        assert 1400 in HASH_MODES   # SHA2-256
        assert 1700 in HASH_MODES   # SHA2-512
        assert 3200 in HASH_MODES   # bcrypt
        assert 22000 in HASH_MODES  # WPA

    def test_hash_modes_values_are_strings(self):
        assert all(isinstance(v, str) for v in HASH_MODES.values())

    def test_hash_modes_keys_are_ints(self):
        assert all(isinstance(k, int) for k in HASH_MODES.keys())
