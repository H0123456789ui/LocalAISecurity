"""ai_engine.py 单元测试"""
import os
import pytest
import numpy as np
from unittest import mock
from ai_engine import (
    JUNK_CATEGORIES,
    FileFeatureExtractor,
    SecurityAIInference,
    CleanAIInference,
    SECURITY_CLASS_NAMES,
    CLEAN_CLASS_NAMES,
    _build_system_locked_dirs,
)


class TestJunkCategories:
    def test_categories_structure(self):
        for cat_name, cat_info in JUNK_CATEGORIES.items():
            assert "label" in cat_info
            assert "risk" in cat_info
            assert "extensions" in cat_info
            assert "dir_patterns" in cat_info
            assert 0 <= cat_info["risk"] <= 2

    def test_extensions_are_lowercase(self):
        for cat_info in JUNK_CATEGORIES.values():
            for ext in cat_info["extensions"]:
                assert ext == ext.lower()


class TestFileFeatureExtractor:
    def setup_method(self):
        self.extractor = FileFeatureExtractor()

    def test_extract_18d_output_shape(self, sample_file_stat):
        features = self.extractor.extract_18d_features(
            "C:\\Windows\\Temp\\test.tmp", sample_file_stat)
        assert len(features) == 18
        assert all(f >= 0.0 for f in features), f"存在负值: {features}"

    def test_extract_on_hidden_file(self, hidden_file_stat):
        features = self.extractor.extract_18d_features(
            "C:\\Users\\test\\AppData\\Local\\hidden.cache", hidden_file_stat)
        assert len(features) == 18
        assert features[11] == 1.0  # is_hidden

    def test_get_category_by_extension(self):
        cat = self.extractor.get_category("C:\\Windows\\Temp\\test.tmp")
        assert cat in ("temp", "other")

    def test_get_category_by_dir(self):
        cat = self.extractor.get_category("C:\\Windows\\Logs\\app.log")
        assert cat in ("log", "temp", "other")

    def test_compute_file_hash_nonexistent(self):
        h = self.extractor.compute_file_hash("Z:\\nonexistent\\file.xyz")
        assert h == ""

    def test_check_path_locked_system32(self):
        system32 = os.path.join(
            os.environ.get("SystemRoot", "C:\\Windows"), "System32", "test.sys")
        assert self.extractor.check_path_locked(system32) is True

    def test_check_path_locked_user_dir(self):
        assert self.extractor.check_path_locked("C:\\Users\\test\\Downloads\\file.txt") is False


class TestBuildLockedDirs:
    def test_returns_list(self):
        dirs = _build_system_locked_dirs()
        assert isinstance(dirs, list)
        assert len(dirs) > 10

    def test_contains_system32(self):
        dirs = _build_system_locked_dirs()
        system32_found = any(
            d.lower().endswith("system32") for d in dirs)
        assert system32_found


class TestClassNames:
    def test_security_class_names(self):
        assert len(SECURITY_CLASS_NAMES) == 4
        assert SECURITY_CLASS_NAMES[0] == "正常"
        assert SECURITY_CLASS_NAMES[3] == "勒索软件"

    def test_clean_class_names(self):
        assert len(CLEAN_CLASS_NAMES) == 5
        assert CLEAN_CLASS_NAMES[0] == "系统核心"
        assert CLEAN_CLASS_NAMES[4] == "用户重要"


class TestSecurityAIInference:
    def test_unloaded_predict_returns_default(self):
        ai = SecurityAIInference()
        cls_id, conf, probs = ai.predict(np.zeros(32, dtype=np.float32))
        assert cls_id == 0
        assert 0.4 <= conf <= 0.6
        assert len(probs) == 4


class TestCleanAIInference:
    def test_unloaded_predict_returns_default(self):
        ai = CleanAIInference()
        cls_id, conf, probs = ai.predict(np.zeros(18, dtype=np.float32))
        assert cls_id == 4
        assert 0.4 <= conf <= 0.6
        assert len(probs) == 5
