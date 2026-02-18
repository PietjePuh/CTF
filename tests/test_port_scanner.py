"""Tests for port_scanner module.

Uses mock sockets to avoid actual network connections during testing.
"""

import socket
from unittest.mock import patch, MagicMock

import pytest

from scripts.port_scanner import (
    parse_port_range,
    scan_port,
    scan_target,
    format_results,
    ScanResult,
    COMMON_SERVICES,
)


class TestParsePortRange:
    """Tests for port range parsing."""

    def test_single_port(self) -> None:
        assert parse_port_range("80") == [80]

    def test_port_range(self) -> None:
        result = parse_port_range("1-5")
        assert result == [1, 2, 3, 4, 5]

    def test_comma_separated(self) -> None:
        result = parse_port_range("22,80,443")
        assert result == [22, 80, 443]

    def test_mixed_format(self) -> None:
        result = parse_port_range("22,80-82,443")
        assert result == [22, 80, 81, 82, 443]

    def test_deduplication(self) -> None:
        """Overlapping ranges should be deduplicated."""
        result = parse_port_range("1-5,3-7")
        assert result == [1, 2, 3, 4, 5, 6, 7]

    def test_sorted_output(self) -> None:
        result = parse_port_range("443,22,80")
        assert result == [22, 80, 443]

    def test_invalid_port_zero(self) -> None:
        with pytest.raises(ValueError):
            parse_port_range("0")

    def test_invalid_port_too_high(self) -> None:
        with pytest.raises(ValueError):
            parse_port_range("70000")

    def test_invalid_reversed_range(self) -> None:
        with pytest.raises(ValueError):
            parse_port_range("100-50")

    def test_single_port_max(self) -> None:
        result = parse_port_range("65535")
        assert result == [65535]


class TestScanPort:
    """Tests for individual port scanning with mocked sockets."""

    @patch("scripts.port_scanner.socket.socket")
    def test_open_port(self, mock_socket_class: MagicMock) -> None:
        """Open port should return is_open=True."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_socket_class.return_value.__exit__ = MagicMock(return_value=False)
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.side_effect = socket.timeout()

        result = scan_port("127.0.0.1", 80, timeout=0.1)
        assert result.is_open is True
        assert result.port == 80

    @patch("scripts.port_scanner.socket.socket")
    def test_closed_port(self, mock_socket_class: MagicMock) -> None:
        """Closed port should return is_open=False."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_socket_class.return_value.__exit__ = MagicMock(return_value=False)
        mock_sock.connect_ex.return_value = 111  # Connection refused

        result = scan_port("127.0.0.1", 12345, timeout=0.1)
        assert result.is_open is False

    @patch("scripts.port_scanner.socket.socket")
    def test_timeout_port(self, mock_socket_class: MagicMock) -> None:
        """Timed-out connection should return is_open=False."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_socket_class.return_value.__exit__ = MagicMock(return_value=False)
        mock_sock.connect_ex.side_effect = socket.timeout()

        result = scan_port("127.0.0.1", 9999, timeout=0.1)
        assert result.is_open is False

    @patch("scripts.port_scanner.socket.socket")
    def test_banner_grab(self, mock_socket_class: MagicMock) -> None:
        """Open port with banner should capture the banner."""
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_socket_class.return_value.__exit__ = MagicMock(return_value=False)
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9"

        result = scan_port("127.0.0.1", 22, timeout=0.1)
        assert result.is_open is True
        assert "SSH" in result.banner

    def test_known_service_name(self) -> None:
        """Well-known ports should have service names."""
        assert COMMON_SERVICES[22] == "SSH"
        assert COMMON_SERVICES[80] == "HTTP"
        assert COMMON_SERVICES[443] == "HTTPS"
        assert COMMON_SERVICES[3306] == "MySQL"


class TestScanTarget:
    """Tests for multi-port scanning."""

    @patch("scripts.port_scanner.scan_port")
    def test_returns_only_open_ports(self, mock_scan: MagicMock) -> None:
        """scan_target should only return open ports."""
        mock_scan.side_effect = [
            ScanResult(22, True, "SSH", ""),
            ScanResult(23, False, "Telnet", ""),
            ScanResult(80, True, "HTTP", ""),
        ]

        results = scan_target("127.0.0.1", [22, 23, 80], timeout=0.1, max_threads=3)
        assert len(results) == 2
        assert results[0].port == 22
        assert results[1].port == 80

    @patch("scripts.port_scanner.scan_port")
    def test_sorted_by_port(self, mock_scan: MagicMock) -> None:
        """Results should be sorted by port number."""
        mock_scan.side_effect = [
            ScanResult(443, True, "HTTPS", ""),
            ScanResult(22, True, "SSH", ""),
            ScanResult(80, True, "HTTP", ""),
        ]

        results = scan_target("127.0.0.1", [443, 22, 80], timeout=0.1, max_threads=3)
        ports = [r.port for r in results]
        assert ports == [22, 80, 443]

    @patch("scripts.port_scanner.scan_port")
    def test_empty_result(self, mock_scan: MagicMock) -> None:
        """No open ports should return empty list."""
        mock_scan.return_value = ScanResult(80, False, "HTTP", "")
        results = scan_target("127.0.0.1", [80], timeout=0.1, max_threads=1)
        assert results == []


class TestFormatResults:
    """Tests for result formatting."""

    def test_format_with_open_ports(self) -> None:
        results = [
            ScanResult(22, True, "SSH", "SSH-2.0"),
            ScanResult(80, True, "HTTP", ""),
        ]
        output = format_results("target.com", results, 1024)
        assert "target.com" in output
        assert "1024" in output
        assert "SSH" in output
        assert "HTTP" in output
        assert "2 open port(s)" in output

    def test_format_no_open_ports(self) -> None:
        output = format_results("target.com", [], 1024)
        assert "No open ports found" in output
        assert "0 open port(s)" in output

    def test_format_includes_banner(self) -> None:
        results = [ScanResult(22, True, "SSH", "SSH-2.0-OpenSSH")]
        output = format_results("host", results, 1)
        assert "SSH-2.0-OpenSSH" in output
