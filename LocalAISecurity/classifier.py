import os
import time
import math
from ai_engine import (
    CleanAIInference, FileFeatureExtractor, JUNK_CATEGORIES,
    _build_system_locked_dirs,
)

SYSTEM_LOCKED_DIRS = _build_system_locked_dirs()

FILE_CLASS = {
    0: ("SYSTEM_CORE", "系统核心", "#FF3B30", "系统运行必需的核心文件，绝对禁止删除。"),
    1: ("SOFTWARE_CACHE", "软件缓存", "#FF9500", "软件运行必需的缓存，删除可能导致软件异常。"),
    2: ("SAFE_CLEANABLE", "安全可删", "#34C759", "普通垃圾文件，可安全删除，不影响系统。"),
    3: ("LARGE_REDUNDANT", "大型冗余", "#007AFF", "占用大量空间的冗余文件，删除需确认。"),
    4: ("USER_IMPORTANT", "用户重要", "#AF52DE", "用户个人重要文件，强制保护，不建议删除。"),
}


class AIFileClassifier:
    def __init__(self):
        self.ai = CleanAIInference()
        self.feature_extractor = FileFeatureExtractor()
        self.model_loaded = self.ai.load()
        if self.model_loaded:
            print(f"[AI] C盘清理AI模型加载成功 (PyTorch CNN)")
        else:
            print(f"[AI] C盘清理AI模型加载失败: {self.ai.load_error}, 使用规则引擎降级")

    def extract_features(self, filepath, stat):
        features_18d = self.feature_extractor.extract_18d_features(filepath, stat)
        ext = os.path.splitext(filepath)[1].lower()
        is_hidden = bool(stat.st_file_attributes & 2) if hasattr(stat, 'st_file_attributes') else False
        is_system = bool(stat.st_file_attributes & 4) if hasattr(stat, 'st_file_attributes') else False
        in_system_dir = any(filepath.lower().startswith(d.lower()) for d in SYSTEM_LOCKED_DIRS)
        in_program_files = "\\program files" in filepath.lower() or "\\program files (x86)" in filepath.lower()
        in_user_dir = "\\users\\" in filepath.lower()
        in_appdata = "\\appdata\\" in filepath.lower()
        in_temp = any(p in filepath.lower() for p in ["\\temp", "\\tmp", "\\cache"])
        try:
            access_days = (time.time() - stat.st_atime) / 86400
        except Exception:
            access_days = 365
        return {
            "path_depth": filepath.count(os.sep),
            "in_system_dir": in_system_dir,
            "in_program_files": in_program_files,
            "in_user_dir": in_user_dir,
            "in_appdata": in_appdata,
            "in_temp": in_temp,
            "file_size_log": math.log1p(stat.st_size) / 20.0 if stat.st_size > 0 else 0,
            "create_days_ago": (time.time() - stat.st_ctime) / 86400 if hasattr(stat, 'st_ctime') else 365,
            "access_days_ago": access_days,
            "modify_days_ago": (time.time() - stat.st_mtime) / 86400 if hasattr(stat, 'st_mtime') else 365,
            "ext_risk": features_18d[10],
            "is_hidden": is_hidden,
            "is_system": is_system,
            "ext": ext,
            "features_18d": features_18d,
        }

    def classify(self, filepath, stat):
        features = self.extract_features(filepath, stat)
        if features["in_system_dir"] and not features["in_temp"]:
            return 0, 0.95, features
        if features["in_program_files"] and features["access_days_ago"] < 30:
            return 1, 0.85, features
        if self.feature_extractor.check_whitelist(filepath):
            return 0, 0.95, features
        if self.model_loaded:
            cls_id, confidence, probs = self.ai.predict(features["features_18d"])
            if features["in_user_dir"] and not features["in_appdata"] and cls_id == 0:
                cls_id = 4
                confidence = 0.80
            if features["access_days_ago"] < 3 and cls_id >= 2:
                cls_id = 1
                confidence = max(confidence, 0.85)
            return cls_id, confidence, features
        ext = features["ext"]
        matched_cat = None
        for cat_name, cat_info in JUNK_CATEGORIES.items():
            if ext in cat_info["extensions"]:
                matched_cat = cat_name
                break
        if matched_cat is None:
            for cat_name, cat_info in JUNK_CATEGORIES.items():
                for dp in cat_info["dir_patterns"]:
                    if dp.lower() in filepath.lower():
                        matched_cat = cat_name
                        break
                if matched_cat:
                    break
        if matched_cat:
            cat_risk = JUNK_CATEGORIES[matched_cat]["risk"]
            if cat_risk == 0:
                return 2, 0.90, features
            elif cat_risk == 1:
                return 3, 0.80, features
            else:
                return 1, 0.70, features
        if features["in_temp"]:
            return 2, 0.88, features
        if features["in_user_dir"] and not features["in_appdata"]:
            return 4, 0.85, features
        if features["access_days_ago"] > 180 and features["in_appdata"]:
            return 3, 0.75, features
        if features["in_appdata"] and features["access_days_ago"] < 30:
            return 1, 0.80, features
        return 4, 0.60, features

    def check_path_locked(self, filepath):
        return self.feature_extractor.check_path_locked(filepath)

    def check_whitelist(self, filepath):
        return self.feature_extractor.check_whitelist(filepath)
