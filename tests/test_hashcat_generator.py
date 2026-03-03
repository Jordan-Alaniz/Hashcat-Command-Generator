"""Unit tests for hashcat_generator.py"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hashcat_generator import (
    HASH_MODES,
    ATTACK_MODES,
    RULE_RECIPES,
    build_command,
    build_rule_lines,
    generate_rule_file,
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


# ──────────────────────────────────────────────────────────────────────────────
# build_rule_lines
# ──────────────────────────────────────────────────────────────────────────────

class TestBuildRuleLines:
    def test_leet_returns_one_line(self):
        assert build_rule_lines(["leet"]) == ["sa@ se3 si1 so0 ss$ st7"]

    def test_capitalize_returns_one_line(self):
        assert build_rule_lines(["capitalize"]) == ["c"]

    def test_uppercase_returns_one_line(self):
        assert build_rule_lines(["uppercase"]) == ["u"]

    def test_lowercase_returns_one_line(self):
        assert build_rule_lines(["lowercase"]) == ["l"]

    def test_reverse_returns_one_line(self):
        assert build_rule_lines(["reverse"]) == ["r"]

    def test_duplicate_returns_one_line(self):
        assert build_rule_lines(["duplicate"]) == ["d"]

    def test_toggle_case_returns_one_line(self):
        assert build_rule_lines(["toggle-case"]) == ["t"]

    def test_append_digit_returns_ten_lines(self):
        lines = build_rule_lines(["append-digit"])
        assert len(lines) == 10
        assert "$0" in lines
        assert "$9" in lines

    def test_append_two_digits_returns_100_lines(self):
        lines = build_rule_lines(["append-two-digits"])
        assert len(lines) == 100
        assert "$0$0" in lines
        assert "$9$9" in lines

    def test_append_special_returns_five_lines(self):
        lines = build_rule_lines(["append-special"])
        assert len(lines) == 5
        assert "$!" in lines

    def test_append_year_returns_six_lines(self):
        lines = build_rule_lines(["append-year"])
        assert len(lines) == 6
        assert "$2$0$2$0" in lines
        assert "$2$0$2$5" in lines

    def test_append_digit_bang_returns_ten_lines(self):
        lines = build_rule_lines(["append-digit-bang"])
        assert len(lines) == 10
        assert "$0$!" in lines
        assert "$9$!" in lines

    def test_prepend_digit_returns_ten_lines(self):
        lines = build_rule_lines(["prepend-digit"])
        assert len(lines) == 10
        assert "^0" in lines
        assert "^9" in lines

    def test_cap_append_digit_returns_ten_lines(self):
        lines = build_rule_lines(["cap-append-digit"])
        assert len(lines) == 10
        assert "c $0" in lines
        assert "c $9" in lines

    def test_leet_cap_returns_one_line(self):
        assert build_rule_lines(["leet-cap"]) == ["c sa@ se3 si1 so0 ss$ st7"]

    def test_combine_recipes_concatenates_lines(self):
        lines = build_rule_lines(["capitalize", "reverse"])
        assert "c" in lines
        assert "r" in lines
        assert len(lines) == 2

    def test_deduplication(self):
        lines = build_rule_lines(["capitalize", "capitalize"])
        assert lines.count("c") == 1

    def test_unknown_key_skipped(self):
        assert build_rule_lines(["nonexistent-recipe"]) == []

    def test_empty_input_returns_empty(self):
        assert build_rule_lines([]) == []

    def test_lines_are_strings(self):
        lines = build_rule_lines(["leet", "append-digit"])
        assert all(isinstance(line, str) for line in lines)


# ──────────────────────────────────────────────────────────────────────────────
# generate_rule_file
# ──────────────────────────────────────────────────────────────────────────────

class TestGenerateRuleFile:
    def test_returns_string_path(self):
        path = generate_rule_file(["capitalize"])
        assert isinstance(path, str)
        os.unlink(path)

    def test_file_exists_after_generation(self):
        path = generate_rule_file(["leet"])
        assert os.path.isfile(path)
        os.unlink(path)

    def test_file_contains_rule_lines(self):
        path = generate_rule_file(["capitalize", "reverse"])
        with open(path) as f:
            content = f.read()
        assert "c\n" in content
        assert "r\n" in content
        os.unlink(path)

    def test_custom_path(self):
        import tempfile as _tempfile
        with _tempfile.NamedTemporaryFile(suffix=".rule", delete=False) as f:
            tmp_path = f.name
        path = generate_rule_file(["uppercase"], path=tmp_path)
        assert path == tmp_path
        with open(path) as f:
            content = f.read()
        assert "u\n" in content
        os.unlink(path)

    def test_empty_recipes_raises(self):
        with pytest.raises(ValueError):
            generate_rule_file([])

    def test_invalid_recipe_raises(self):
        with pytest.raises(ValueError):
            generate_rule_file(["nonexistent"])


# ──────────────────────────────────────────────────────────────────────────────
# RULE_RECIPES constant
# ──────────────────────────────────────────────────────────────────────────────

class TestRuleRecipes:
    def test_rule_recipes_not_empty(self):
        assert len(RULE_RECIPES) > 0

    def test_rule_recipes_are_tuples_of_two_strings(self):
        for entry in RULE_RECIPES:
            assert isinstance(entry, tuple)
            assert len(entry) == 2
            assert all(isinstance(s, str) for s in entry)

    def test_all_recipe_keys_are_in_map(self):
        from hashcat_generator import _RULE_RECIPE_MAP
        for key, _ in RULE_RECIPES:
            assert key in _RULE_RECIPE_MAP, f"Recipe key '{key}' missing from _RULE_RECIPE_MAP"
