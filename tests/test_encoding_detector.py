"""Tests for encoding_detector module."""

from scripts.encoding_detector import (
    detect_base32,
    detect_base64,
    detect_binary,
    detect_decimal,
    detect_encoding,
    detect_hex,
    detect_morse,
    detect_octal,
    detect_rot13,
    detect_url_encoding,
    format_results,
    is_printable_ascii,
)


class TestIsPrintableAscii:
    """Tests for the is_printable_ascii helper."""

    def test_printable_string(self) -> None:
        assert is_printable_ascii("Hello World") is True

    def test_empty_string(self) -> None:
        assert is_printable_ascii("") is False

    def test_mostly_non_printable(self) -> None:
        assert is_printable_ascii("\x00\x01\x02\x03") is False


class TestDetectBase64:
    """Tests for Base64 detection."""

    def test_valid_base64(self) -> None:
        """Standard Base64-encoded string should decode correctly."""
        # "ENcodeDEcode" in base64
        result = detect_base64("RU5jb2RlREVjb2RlCg==")
        assert result is not None
        assert result.encoding == "Base64"
        assert "ENcodeDEcode" in result.decoded

    def test_hello_world_base64(self) -> None:
        # "Hello World" in base64
        result = detect_base64("SGVsbG8gV29ybGQ=")
        assert result is not None
        assert "Hello World" in result.decoded

    def test_non_base64(self) -> None:
        result = detect_base64("This is not base64!!!")
        assert result is None


class TestDetectHex:
    """Tests for hexadecimal detection."""

    def test_valid_hex(self) -> None:
        # "Hello" in hex
        result = detect_hex("48656c6c6f")
        assert result is not None
        assert result.encoding == "Hexadecimal"
        assert result.decoded == "Hello"

    def test_hex_with_0x_prefix(self) -> None:
        result = detect_hex("0x48656c6c6f")
        assert result is not None
        assert result.decoded == "Hello"

    def test_hex_with_spaces(self) -> None:
        result = detect_hex("48 65 6c 6c 6f")
        assert result is not None
        assert result.decoded == "Hello"

    def test_odd_length_hex(self) -> None:
        """Odd number of hex digits should not match."""
        result = detect_hex("48656c6c6")
        assert result is None

    def test_non_hex(self) -> None:
        result = detect_hex("xyz123")
        assert result is None


class TestDetectRot13:
    """Tests for ROT13 detection."""

    def test_rot13_decode(self) -> None:
        # "Hello" ROT13 = "Uryyb"
        result = detect_rot13("Uryyb")
        assert result is not None
        assert result.encoding == "ROT13"
        assert result.decoded == "Hello"

    def test_rot13_sentence(self) -> None:
        result = detect_rot13("Guvf vf n grfg")
        assert result is not None
        assert result.decoded == "This is a test"

    def test_non_alpha_rejected(self) -> None:
        """Strings with numbers should not be detected as ROT13."""
        result = detect_rot13("Hello123")
        assert result is None


class TestDetectBinary:
    """Tests for binary encoding detection."""

    def test_valid_binary(self) -> None:
        # "Hi" in binary: H=01001000, i=01101001
        result = detect_binary("0100100001101001")
        assert result is not None
        assert result.encoding == "Binary"
        assert result.decoded == "Hi"

    def test_binary_with_spaces(self) -> None:
        result = detect_binary("01001000 01101001")
        assert result is not None
        assert result.decoded == "Hi"

    def test_non_binary(self) -> None:
        result = detect_binary("0123456789")
        assert result is None

    def test_wrong_length(self) -> None:
        """Binary strings not divisible by 8 should not match."""
        result = detect_binary("0100100")
        assert result is None


class TestDetectUrlEncoding:
    """Tests for URL encoding detection."""

    def test_valid_url_encoding(self) -> None:
        result = detect_url_encoding("Hello%20World")
        assert result is not None
        assert result.encoding == "URL Encoding"
        assert result.decoded == "Hello World"

    def test_no_percent(self) -> None:
        result = detect_url_encoding("Hello World")
        assert result is None

    def test_complex_url_encoding(self) -> None:
        result = detect_url_encoding("%3Cscript%3Ealert(1)%3C%2Fscript%3E")
        assert result is not None
        assert "<script>" in result.decoded


class TestDetectMorse:
    """Tests for Morse code detection."""

    def test_valid_morse(self) -> None:
        # "SOS" in Morse
        result = detect_morse("... --- ...")
        assert result is not None
        assert result.encoding == "Morse Code"
        assert result.decoded == "SOS"

    def test_morse_with_word_separator(self) -> None:
        # "HI" in Morse: H=...., I=..
        result = detect_morse(".... ..")
        assert result is not None
        assert result.decoded == "HI"

    def test_non_morse(self) -> None:
        result = detect_morse("Hello World")
        assert result is None


class TestDetectBase32:
    """Tests for Base32 detection."""

    def test_valid_base32(self) -> None:
        # "Hello" in Base32
        result = detect_base32("JBSWY3DP")
        assert result is not None
        assert result.encoding == "Base32"
        assert result.decoded == "Hello"


class TestDetectOctal:
    """Tests for octal detection."""

    def test_valid_octal(self) -> None:
        # "Hi" in octal: H=110, i=151
        result = detect_octal("110 151")
        assert result is not None
        assert result.encoding == "Octal"
        assert result.decoded == "Hi"


class TestDetectDecimal:
    """Tests for decimal ASCII detection."""

    def test_valid_decimal(self) -> None:
        # "Hi" in decimal ASCII: H=72, i=105
        result = detect_decimal("72 105")
        assert result is not None
        assert result.encoding == "Decimal (ASCII)"
        assert result.decoded == "Hi"


class TestDetectEncoding:
    """Integration tests for the main detect_encoding function."""

    def test_base64_detected(self) -> None:
        results = detect_encoding("SGVsbG8gV29ybGQ=")
        encodings = [r.encoding for r in results]
        assert "Base64" in encodings

    def test_hex_detected(self) -> None:
        results = detect_encoding("48656c6c6f")
        encodings = [r.encoding for r in results]
        assert "Hexadecimal" in encodings

    def test_empty_string(self) -> None:
        results = detect_encoding("")
        assert results == []

    def test_results_sorted_by_confidence(self) -> None:
        results = detect_encoding("SGVsbG8gV29ybGQ=")
        if len(results) > 1:
            confidence_order = {"high": 0, "medium": 1, "low": 2}
            for i in range(len(results) - 1):
                current = confidence_order[results[i].confidence]
                next_val = confidence_order[results[i + 1].confidence]
                assert current <= next_val


class TestFormatResults:
    """Tests for format_results function."""

    def test_format_with_results(self) -> None:
        from scripts.encoding_detector import DecodingResult

        results = [DecodingResult("Base64", "Hello World", "high")]
        output = format_results("SGVsbG8gV29ybGQ=", results)
        assert "Base64" in output
        assert "Hello World" in output

    def test_format_no_results(self) -> None:
        output = format_results("xyz", [])
        assert "No encoding detected" in output
