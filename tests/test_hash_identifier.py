"""Tests for hash_identifier module."""

from scripts.hash_identifier import HashType, format_results, identify_hash


class TestIdentifyHash:
    """Tests for the identify_hash function."""

    def test_md5_hash(self) -> None:
        """MD5 hashes are 32 hex characters."""
        result = identify_hash("5d41402abc4b2a76b9719d911017c592")
        names = [r.name for r in result]
        assert "MD5" in names

    def test_sha1_hash(self) -> None:
        """SHA-1 hashes are 40 hex characters."""
        result = identify_hash("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
        names = [r.name for r in result]
        assert "SHA-1" in names

    def test_sha256_hash(self) -> None:
        """SHA-256 hashes are 64 hex characters."""
        result = identify_hash("9eb7ee7f551d2f0ac684981bd1f1e2fa4a37590199636753efe614d4db30e8e1")
        names = [r.name for r in result]
        assert "SHA-256" in names

    def test_sha512_hash(self) -> None:
        """SHA-512 hashes are 128 hex characters."""
        hash_str = "a" * 128
        result = identify_hash(hash_str)
        names = [r.name for r in result]
        assert "SHA-512" in names

    def test_bcrypt_hash(self) -> None:
        """bcrypt hashes start with $2a$, $2b$, or $2y$."""
        result = identify_hash("$2a$06$7yoU3Ng8dHTXphAg913cyO6Bjs3K5lBnwq5FJyA6d01pMSrddr1ZG")
        assert len(result) == 1
        assert result[0].name == "bcrypt"
        assert result[0].hashcat_mode == 3200

    def test_sha512crypt_hash(self) -> None:
        """sha512crypt hashes start with $6$."""
        result = identify_hash("$6$GQXVvW4EuM$ehD6jWiMsfNorxy5SINsgdlxmAEl3.yif0/c3NqzGLa0P.S7KRD")
        assert len(result) == 1
        assert result[0].name == "sha512crypt"
        assert result[0].hashcat_mode == 1800

    def test_md5crypt_hash(self) -> None:
        """md5crypt hashes start with $1$."""
        result = identify_hash("$1$salt$hash")
        assert len(result) == 1
        assert result[0].name == "md5crypt"

    def test_ntlm_in_md5_results(self) -> None:
        """NTLM should be suggested alongside MD5 for 32-char hex strings."""
        result = identify_hash("b6b0d451bbf6fed658659a9e7e5598fe")
        names = [r.name for r in result]
        assert "NTLM" in names
        assert "MD5" in names

    def test_empty_string(self) -> None:
        """Empty strings should return no results."""
        result = identify_hash("")
        assert result == []

    def test_non_hex_string(self) -> None:
        """Non-hex strings that are 32 chars should not match MD5."""
        result = identify_hash("this_is_not_a_valid_hash_string!")
        # Should not identify as any standard hex-based hash
        hex_names = {"MD5", "SHA-1", "SHA-256", "SHA-512", "NTLM"}
        result_names = {r.name for r in result}
        assert not result_names.intersection(hex_names)

    def test_whitespace_handling(self) -> None:
        """Hashes with leading/trailing whitespace should still be identified."""
        result = identify_hash("  5d41402abc4b2a76b9719d911017c592  ")
        names = [r.name for r in result]
        assert "MD5" in names

    def test_uppercase_hex(self) -> None:
        """Uppercase hex characters should be recognized."""
        result = identify_hash("5D41402ABC4B2A76B9719D911017C592")
        names = [r.name for r in result]
        assert "MD5" in names

    def test_prefix_patterns_take_priority(self) -> None:
        """Prefix-based patterns should be returned before length-based ones."""
        result = identify_hash("$2b$12$WowwhatahashthisisnotREALbutitslongenoughfor")
        if result:
            assert result[0].name == "bcrypt"

    def test_yescrypt_hash(self) -> None:
        """yescrypt hashes start with $y$."""
        result = identify_hash("$y$j9T$saltsalt$hashhashhash")
        assert len(result) == 1
        assert result[0].name == "yescrypt"

    def test_cisco_ios_scrypt(self) -> None:
        """Cisco IOS type 9 hashes start with $9$."""
        result = identify_hash("$9$saltsalthashhashhash")
        assert len(result) == 1
        assert result[0].name == "Cisco IOS scrypt"


class TestFormatResults:
    """Tests for the format_results function."""

    def test_format_with_matches(self) -> None:
        """Results with matches should show hash type details."""
        results = [HashType("MD5", 0, "128-bit Message Digest")]
        output = format_results("abc123", results)
        assert "MD5" in output
        assert "abc123" in output

    def test_format_no_matches(self) -> None:
        """Results with no matches should indicate that."""
        output = format_results("xyz", [])
        assert "No matching hash type found" in output

    def test_format_multiple_matches(self) -> None:
        """Multiple matches should all be displayed."""
        results = [
            HashType("MD5", 0, "128-bit"),
            HashType("NTLM", 1000, "Windows NT"),
        ]
        output = format_results("abc", results)
        assert "MD5" in output
        assert "NTLM" in output
        assert "2 matches" in output
