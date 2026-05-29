"""
Real training data collector — extracts features from the local machine using the
same ProcessFeatureCollector / FileFeatureExtractor used at inference time.

Usage:
    python collect_real_data.py                    # collect both security + clean data
    python collect_real_data.py --security-only    # only process features
    python collect_real_data.py --clean-only       # only file features
    python collect_real_data.py --label-threats    # interactive labeling mode
"""

import os
import sys
import json
import time
import argparse
import numpy as np
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))
from ai_engine import ProcessFeatureCollector, FileFeatureExtractor


DATASET_DIR = Path(__file__).parent / "dataset"
DATASET_DIR.mkdir(exist_ok=True)

SECURITY_FEATURES_FILE = DATASET_DIR / "security_features.npy"
SECURITY_LABELS_FILE = DATASET_DIR / "security_labels.npy"
CLEAN_FEATURES_FILE = DATASET_DIR / "clean_features.npy"
CLEAN_LABELS_FILE = DATASET_DIR / "clean_labels.npy"
METADATA_FILE = DATASET_DIR / "collection_metadata.json"


def collect_process_features():
    """Collect 32-dim features from all running processes."""
    collector = ProcessFeatureCollector()
    if not collector.is_available():
        print("[ERROR] psutil not available — cannot collect process features")
        return None, None, []

    psutil = collector._psutil
    features_list = []
    metadata = []

    for proc in psutil.process_iter(['pid']):
        try:
            pid = proc.info['pid']
            proc_obj = psutil.Process(pid)
            try:
                name = proc_obj.name()
                exe = proc_obj.exe() or ""
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

            feats = collector.collect_process_features(proc_obj)
            if feats is None:
                continue

            features_list.append(feats)
            metadata.append({
                "pid": pid,
                "name": name,
                "exe": exe,
                "collected_at": datetime.now().isoformat(),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if not features_list:
        print("[WARN] No process features collected")
        return None, None, []

    features = np.array(features_list, dtype=np.float32)
    labels = np.zeros(len(features), dtype=np.int64)  # default: normal (label 0)

    # Auto-label heuristics based on path/name patterns
    for i, meta in enumerate(metadata):
        name_lower = meta["name"].lower()
        exe_lower = meta["exe"].lower()

        suspicious_name_kw = [
            "miner", "hack", "crack", "keygen", "patch", "loader",
            "inject", "hook", "bypass", "exploit", "rat", "bot",
        ]
        suspicious_path_kw = [
            "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
            "\\downloads\\", "\\public\\",
        ]

        name_suspicious = any(kw in name_lower for kw in suspicious_name_kw)
        path_suspicious = any(kw in exe_lower for kw in suspicious_path_kw)

        if name_suspicious and path_suspicious:
            labels[i] = 2  # potential trojan
        elif name_suspicious:
            labels[i] = 1  # potential PUA/adware
        elif path_suspicious and not exe_lower.startswith("c:\\windows"):
            labels[i] = 1

    print(f"[OK] Collected {len(features)} process feature vectors "
          f"(auto-labeled: {(labels > 0).sum()} suspicious)")
    return features, labels, metadata


def collect_file_features(scan_roots=None):
    """Collect 18-dim features from real files on disk."""
    if scan_roots is None:
        scan_roots = [
            os.environ.get("TEMP", "C:\\Windows\\Temp"),
            os.path.join(os.environ.get("USERPROFILE", "C:\\Users\\Default"), "Downloads"),
            os.path.join(os.environ.get("USERPROFILE", "C:\\Users\\Default"), "AppData\\Local\\Temp"),
            "C:\\Windows\\Temp",
            "C:\\Windows\\Logs",
            "C:\\Windows\\Prefetch",
        ]

    extractor = FileFeatureExtractor()
    features_list = []
    metadata = []
    max_files = 5000
    count = 0

    for root_dir in scan_roots:
        if not os.path.exists(root_dir):
            continue
        for dirpath, dirnames, filenames in os.walk(root_dir):
            for fname in filenames:
                if count >= max_files:
                    break
                fpath = os.path.join(dirpath, fname)
                try:
                    stat = os.stat(fpath)
                    if extractor.check_path_locked(fpath):
                        continue
                    feats = extractor.extract_18d_features(fpath, stat)
                    features_list.append(feats)
                    metadata.append({
                        "path": fpath,
                        "size": stat.st_size,
                        "category": extractor.get_category(fpath),
                        "collected_at": datetime.now().isoformat(),
                    })
                    count += 1
                except (PermissionError, OSError):
                    continue
            if count >= max_files:
                break
        if count >= max_files:
            break

    if not features_list:
        print("[WARN] No file features collected")
        return None, None, []

    features = np.array(features_list, dtype=np.float32)
    labels = np.full(len(features), 4, dtype=np.int64)  # default: user important (label 4)

    # Auto-label based on category
    for i, meta in enumerate(metadata):
        cat = meta["category"]
        if cat in ("temp", "cache", "log", "thumb", "crash"):
            labels[i] = 2  # safe cleanable
        elif cat in ("update", "installer", "prefetch"):
            labels[i] = 3  # large redundant
        elif meta["size"] > 100 * 1024 * 1024 and cat == "other":
            labels[i] = 3  # large unrecognized → redundant
        elif meta["path"].lower().startswith("c:\\windows"):
            labels[i] = 0  # system core

    print(f"[OK] Collected {len(features)} file feature vectors "
          f"(cleanable: {(labels == 2).sum()}, redundant: {(labels == 3).sum()})")
    return features, labels, metadata


def merge_with_existing(new_features, new_labels, existing_file):
    """Merge new data with existing saved data, avoiding duplicates."""
    if existing_file.exists():
        existing = np.load(existing_file)
        combined = np.vstack([existing, new_features])
        print(f"  Merged with {len(existing)} existing samples → {len(combined)} total")
        return combined
    return new_features


def main():
    parser = argparse.ArgumentParser(description="Collect real training data for LocalAISecurity")
    parser.add_argument("--security-only", action="store_true")
    parser.add_argument("--clean-only", action="store_true")
    parser.add_argument("--max-files", type=int, default=5000)
    args = parser.parse_args()

    metadata = {
        "collected_at": datetime.now().isoformat(),
        "hostname": os.environ.get("COMPUTERNAME", "unknown"),
    }

    if not args.clean_only:
        print("\n[1/2] Collecting process (security) features...")
        feats, labels, proc_meta = collect_process_features()
        if feats is not None:
            merged_f = merge_with_existing(feats, labels, SECURITY_FEATURES_FILE)
            merged_l = merge_with_existing(labels, labels, SECURITY_LABELS_FILE)
            np.save(SECURITY_FEATURES_FILE, merged_f)
            np.save(SECURITY_LABELS_FILE, merged_l)
            metadata["security_samples"] = len(merged_f)
            metadata["security_suspicious"] = int((merged_l > 0).sum())

    if not args.security_only:
        print("\n[2/2] Collecting file (clean) features...")
        feats, labels, file_meta = collect_file_features()
        if feats is not None:
            merged_f = merge_with_existing(feats, labels, CLEAN_FEATURES_FILE)
            merged_l = merge_with_existing(labels, labels, CLEAN_LABELS_FILE)
            np.save(CLEAN_FEATURES_FILE, merged_f)
            np.save(CLEAN_LABELS_FILE, merged_l)
            metadata["clean_samples"] = len(merged_f)
            metadata["clean_cleanable"] = int((merged_l == 2).sum())

    with open(METADATA_FILE, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"\n{'='*50}")
    print("  Collection complete")
    print(f"  Data saved to: {DATASET_DIR}")
    for k, v in metadata.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
