"""scanner.py 单元测试"""
import pytest
from unittest import mock
from scanner import format_size, DiskScanner


class TestFormatSize:
    def test_bytes(self):
        assert format_size(0) == "0 B"
        assert format_size(512) == "512 B"
        assert format_size(1023) == "1023 B"

    def test_kb(self):
        assert format_size(1024) == "1.0 KB"
        assert format_size(1536) == "1.5 KB"

    def test_mb(self):
        assert format_size(1048576) == "1.0 MB"

    def test_gb(self):
        assert format_size(1073741824) == "1.00 GB"


class TestDiskScanner:
    def test_init(self):
        s = DiskScanner()
        assert s.total_scanned == 0
        assert s.scan_time_ms == 0
        assert len(s.results) == 5
        for i in range(5):
            assert s.results[i] == []

    def test_get_stats_empty(self):
        s = DiskScanner()
        stats = s.get_stats()
        assert stats["total_files"] == 0
        assert stats["cleanable_size"] == 0

    def test_execute_clean_empty(self):
        s = DiskScanner()
        result = s.execute_clean([])
        assert result["deleted"] == 0
        assert result["freed"] == 0
        assert result["failed"] == 0

    def test_execute_clean_nonexistent(self):
        s = DiskScanner()
        result = s.execute_clean([{"path": "/nonexistent/file.xyz", "size": 100}])
        assert result["failed"] >= 0  # 不应崩溃
