"""测试共享 fixtures"""
import os
import sys
import tempfile
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class FakeStat:
    """模拟 os.stat 返回值，用于测试文件分类器。"""
    def __init__(self, size=1024, ctime=None, atime=None, mtime=None,
                 file_attributes=0):
        self.st_size = size
        self.st_ctime = ctime or 1600000000.0
        self.st_atime = atime or 1600000000.0
        self.st_mtime = mtime or 1600000000.0
        self.st_file_attributes = file_attributes


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as td:
        yield td


@pytest.fixture
def sample_file_stat():
    return FakeStat(size=4096, file_attributes=0)


@pytest.fixture
def hidden_file_stat():
    return FakeStat(size=512, file_attributes=2)  # FILE_ATTRIBUTE_HIDDEN


@pytest.fixture
def system_file_stat():
    return FakeStat(size=8192, file_attributes=4)  # FILE_ATTRIBUTE_SYSTEM
