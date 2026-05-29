"""classifier.py 单元测试"""
import os
import pytest
from unittest import mock
from classifier import AIFileClassifier, FILE_CLASS, SYSTEM_LOCKED_DIRS


class TestFileClass:
    def test_file_class_structure(self):
        for cls_id in range(5):
            assert cls_id in FILE_CLASS
            name, label, color, desc = FILE_CLASS[cls_id]
            assert isinstance(name, str)
            assert isinstance(label, str)
            assert color.startswith("#")
            assert isinstance(desc, str)

    def test_system_locked_dirs_dynamic(self):
        """验证锁定目录列表已动态生成（非空且包含当前系统路径）。"""
        assert len(SYSTEM_LOCKED_DIRS) > 0
        # 至少包含 System32
        system32_found = any("System32" in d for d in SYSTEM_LOCKED_DIRS)
        assert system32_found, "SYSTEM_LOCKED_DIRS 应包含 System32"


class TestAIFileClassifier:
    def test_init(self):
        classifier = AIFileClassifier()
        assert classifier.feature_extractor is not None

    def test_check_path_locked(self):
        classifier = AIFileClassifier()
        # 系统目录应被锁定
        system32 = os.path.join(
            os.environ.get("SystemRoot", "C:\\Windows"), "System32", "ntdll.dll")
        assert classifier.check_path_locked(system32) is True

    def test_check_whitelist_system_dll(self):
        classifier = AIFileClassifier()
        system32 = os.path.join(
            os.environ.get("SystemRoot", "C:\\Windows"), "System32", "kernel32.dll")
        assert classifier.check_whitelist(system32) is True

    def test_check_whitelist_normal_file(self):
        classifier = AIFileClassifier()
        assert classifier.check_whitelist("D:\\Downloads\\photo.jpg") is False

    def test_check_whitelist_non_system_dll(self):
        classifier = AIFileClassifier()
        # DLL 在用户目录下不应被白名单保护
        assert classifier.check_whitelist("D:\\mygame\\mod.dll") is False
