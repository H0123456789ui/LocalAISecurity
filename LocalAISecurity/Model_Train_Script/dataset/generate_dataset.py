"""
数据集生成工具 - 安全行为样本
生成十万级进程行为时序特征数据
"""

import numpy as np
import json
import os
from pathlib import Path


def generate_security_dataset(output_dir, num_samples=100000):
    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True)

    data_list = []
    label_list = []

    feature_names = [
        "cpu_usage", "memory_usage", "thread_count", "handle_count",
        "file_create_rate", "file_modify_rate", "file_delete_rate", "file_rename_rate",
        "reg_read_rate", "reg_write_rate", "reg_delete_rate", "reg_monitor_rate",
        "net_conn_rate", "net_send_bytes", "net_recv_bytes", "abnormal_ports",
        "proc_inject", "dll_inject", "proc_hide", "proc_revive",
        "batch_encrypt", "keylog", "screenshot", "camera_access",
        "silent_install", "auto_start", "service_reg", "driver_load",
        "popup_freq", "induce_click", "browser_hijack", "privilege_escalate"
    ]

    class_names = ["正常程序", "可疑流氓行为", "高危木马/注入行为", "勒索病毒加密行为"]

    class_ratios = [0.55, 0.20, 0.15, 0.10]
    class_counts = [int(num_samples * r) for r in class_ratios]
    class_counts[0] += num_samples - sum(class_counts)

    for label, count in enumerate(class_counts):
        for _ in range(count):
            features = np.zeros(32, dtype=np.float32)

            if label == 0:
                features[0] = np.random.beta(2, 8) * 0.3
                features[1] = np.random.beta(2, 5) * 0.3
                features[2] = np.random.beta(2, 10) * 0.4
                features[3] = np.random.beta(3, 7) * 0.4
                features[4] = np.random.beta(1, 20) * 0.1
                features[5] = np.random.beta(1, 30) * 0.05
                features[8] = np.random.beta(2, 10) * 0.2
                features[9] = np.random.beta(1, 30) * 0.05
                features[12] = np.random.beta(2, 15) * 0.15
                features[14] = np.random.beta(8, 2) * 0.9
                features[15] = np.random.beta(7, 3) * 0.8
                features[16] = np.random.beta(6, 4) * 0.7
                features[17] = np.random.beta(8, 2) * 0.9
                features[18] = np.random.beta(9, 1) * 0.95
                features[19] = np.random.beta(8, 2) * 0.85
                features[22] = np.random.beta(1, 15) * 0.05
                features[23] = np.random.beta(1, 15) * 0.05
                features[24] = np.random.beta(1, 20) * 0.03
                features[25] = np.random.beta(1, 20) * 0.03
                features[26] = np.random.beta(1, 20) * 0.03
                features[27] = np.random.beta(1, 30) * 0.02
                features[28] = np.random.beta(1, 15) * 0.05
                features[29] = np.random.beta(1, 30) * 0.02
                features[30] = np.random.beta(1, 30) * 0.02
                features[31] = np.random.beta(1, 30) * 0.02

            elif label == 1:
                features[0] = np.random.beta(4, 6) * 0.5
                features[1] = np.random.beta(4, 4) * 0.5
                features[2] = np.random.beta(3, 7) * 0.5
                features[4] = np.random.beta(3, 7) * 0.3
                features[9] = np.random.beta(4, 6) * 0.4
                features[12] = np.random.beta(4, 6) * 0.5
                features[13] = np.random.beta(3, 7) * 0.4
                features[14] = np.random.beta(4, 6) * 0.5
                features[15] = np.random.beta(4, 6) * 0.5
                features[16] = np.random.beta(5, 5) * 0.5
                features[17] = np.random.beta(4, 6) * 0.5
                features[18] = np.random.beta(5, 5) * 0.5
                features[19] = np.random.beta(4, 6) * 0.5
                features[22] = np.random.beta(2, 8) * 0.2
                features[23] = np.random.beta(2, 8) * 0.2
                features[24] = np.random.beta(6, 4) * 0.7
                features[25] = np.random.beta(6, 4) * 0.7
                features[26] = np.random.beta(5, 5) * 0.6
                features[28] = np.random.beta(5, 5) * 0.6
                features[29] = np.random.beta(6, 4) * 0.7
                features[30] = np.random.beta(3, 7) * 0.3
                features[31] = np.random.beta(3, 7) * 0.3

            elif label == 2:
                features[0] = np.random.beta(5, 5) * 0.7
                features[1] = np.random.beta(5, 5) * 0.6
                features[2] = np.random.beta(4, 6) * 0.6
                features[14] = np.random.beta(3, 7) * 0.3
                features[15] = np.random.beta(3, 7) * 0.3
                features[16] = np.random.beta(7, 3) * 0.85
                features[17] = np.random.beta(7, 3) * 0.8
                features[18] = np.random.beta(6, 4) * 0.75
                features[19] = np.random.beta(6, 4) * 0.7
                features[21] = np.random.beta(6, 4) * 0.7
                features[22] = np.random.beta(5, 5) * 0.6
                features[23] = np.random.beta(4, 6) * 0.4
                features[24] = np.random.beta(3, 7) * 0.3
                features[25] = np.random.beta(4, 6) * 0.4
                features[26] = np.random.beta(4, 6) * 0.4
                features[27] = np.random.beta(6, 4) * 0.7
                features[30] = np.random.beta(5, 5) * 0.5
                features[31] = np.random.beta(7, 3) * 0.8

            elif label == 3:
                features[0] = np.random.beta(8, 2) * 0.95
                features[1] = np.random.beta(7, 3) * 0.8
                features[5] = np.random.beta(7, 3) * 0.85
                features[6] = np.random.beta(6, 4) * 0.75
                features[7] = np.random.beta(6, 4) * 0.75
                features[9] = np.random.beta(7, 3) * 0.8
                features[14] = np.random.beta(2, 8) * 0.2
                features[15] = np.random.beta(2, 8) * 0.2
                features[16] = np.random.beta(2, 8) * 0.2
                features[17] = np.random.beta(2, 8) * 0.2
                features[18] = np.random.beta(2, 8) * 0.2
                features[19] = np.random.beta(2, 8) * 0.2
                features[20] = np.random.beta(9, 1) * 0.95
                features[23] = np.random.beta(6, 4) * 0.7
                features[24] = np.random.beta(5, 5) * 0.6
                features[25] = np.random.beta(7, 3) * 0.8
                features[26] = np.random.beta(6, 4) * 0.7
                features[30] = np.random.beta(6, 4) * 0.7
                features[31] = np.random.beta(8, 2) * 0.9

            noise = np.random.normal(0, 0.02, 32).astype(np.float32)
            features = features + noise
            features = np.clip(features, 0, 1)

            data_list.append(features.tolist())
            label_list.append(label)

    # 保存数据集
    dataset = {
        "feature_names": feature_names,
        "class_names": class_names,
        "num_features": 32,
        "num_classes": 4,
        "data": data_list,
        "labels": label_list
    }

    output_path = output_dir / "security_behavior_dataset.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(dataset, f, ensure_ascii=False, indent=2)

    print(f"[*] 安全行为数据集已生成: {output_path}")
    print(f"    样本数: {num_samples}")
    print(f"    特征维度: 32")
    print(f"    分类数: 4")

    return dataset


def generate_clean_dataset(output_dir, num_samples=100000):
    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True)

    data_list = []
    label_list = []

    feature_names = [
        "path_depth", "in_system_dir", "in_program_files", "in_user_dir",
        "in_appdata", "in_temp", "file_size_log", "create_days_ago",
        "access_days_ago", "modify_days_ago", "modify_freq", "ext_weight",
        "sys_dir_weight", "stack_level", "is_hidden", "is_readonly",
        "is_system", "ext_risk_score"
    ]

    class_names = [
        "系统核心必需", "软件运行必需缓存", "安全可删普通垃圾",
        "大型冗余堆积", "用户个人重要文件"
    ]

    class_ratios = [0.25, 0.20, 0.25, 0.15, 0.15]
    class_counts = [int(num_samples * r) for r in class_ratios]
    class_counts[0] += num_samples - sum(class_counts)

    for label, count in enumerate(class_counts):
        for _ in range(count):
            features = np.zeros(18, dtype=np.float32)

            if label == 0:
                features[0] = np.random.beta(3, 8) * 0.3
                features[1] = np.random.beta(8, 2) * 0.9
                features[2] = np.random.beta(2, 8) * 0.15
                features[3] = np.random.beta(2, 8) * 0.1
                features[4] = np.random.beta(2, 8) * 0.1
                features[5] = np.random.beta(1, 30) * 0.02
                features[6] = np.random.beta(3, 7) * 0.25
                features[7] = np.random.beta(8, 2) * 0.9
                features[8] = np.random.beta(2, 8) * 0.1
                features[9] = np.random.beta(3, 7) * 0.3
                features[10] = np.random.beta(3, 7) * 0.3
                features[11] = np.random.beta(8, 2) * 0.9
                features[12] = np.random.beta(8, 2) * 0.9
                features[13] = np.random.beta(3, 7) * 0.3
                features[14] = np.random.beta(5, 5) * 0.5
                features[15] = np.random.beta(6, 4) * 0.6
                features[16] = np.random.beta(7, 3) * 0.7
                features[17] = np.random.beta(8, 2) * 0.9

            elif label == 1:
                features[0] = np.random.beta(5, 5) * 0.5
                features[1] = np.random.beta(3, 7) * 0.3
                features[2] = np.random.beta(6, 4) * 0.65
                features[3] = np.random.beta(3, 7) * 0.3
                features[4] = np.random.beta(6, 4) * 0.7
                features[5] = np.random.beta(3, 7) * 0.3
                features[6] = np.random.beta(4, 6) * 0.4
                features[7] = np.random.beta(4, 6) * 0.5
                features[8] = np.random.beta(3, 7) * 0.25
                features[9] = np.random.beta(4, 6) * 0.4
                features[10] = np.random.beta(5, 5) * 0.5
                features[11] = np.random.beta(5, 5) * 0.5
                features[12] = np.random.beta(5, 5) * 0.5
                features[13] = np.random.beta(4, 6) * 0.4
                features[14] = np.random.beta(3, 7) * 0.3
                features[15] = np.random.beta(3, 7) * 0.3
                features[16] = np.random.beta(3, 7) * 0.3
                features[17] = np.random.beta(5, 5) * 0.5

            elif label == 2:
                features[0] = np.random.beta(6, 4) * 0.7
                features[1] = np.random.beta(1, 20) * 0.05
                features[2] = np.random.beta(2, 8) * 0.15
                features[3] = np.random.beta(4, 6) * 0.4
                features[4] = np.random.beta(3, 7) * 0.3
                features[5] = np.random.beta(8, 2) * 0.85
                features[6] = np.random.beta(2, 8) * 0.15
                features[7] = np.random.beta(4, 6) * 0.4
                features[8] = np.random.beta(8, 2) * 0.9
                features[9] = np.random.beta(8, 2) * 0.9
                features[10] = np.random.beta(3, 7) * 0.25
                features[11] = np.random.beta(2, 8) * 0.15
                features[12] = np.random.beta(1, 20) * 0.05
                features[13] = np.random.beta(3, 7) * 0.25
                features[14] = np.random.beta(3, 7) * 0.3
                features[15] = np.random.beta(3, 7) * 0.3
                features[16] = np.random.beta(2, 8) * 0.15
                features[17] = np.random.beta(2, 8) * 0.15

            elif label == 3:
                features[0] = np.random.beta(7, 3) * 0.8
                features[1] = np.random.beta(2, 8) * 0.15
                features[2] = np.random.beta(3, 7) * 0.3
                features[3] = np.random.beta(4, 6) * 0.4
                features[4] = np.random.beta(6, 4) * 0.7
                features[5] = np.random.beta(3, 7) * 0.3
                features[6] = np.random.beta(8, 2) * 0.9
                features[7] = np.random.beta(5, 5) * 0.5
                features[8] = np.random.beta(8, 2) * 0.9
                features[9] = np.random.beta(8, 2) * 0.9
                features[10] = np.random.beta(2, 8) * 0.15
                features[11] = np.random.beta(3, 7) * 0.3
                features[12] = np.random.beta(2, 8) * 0.15
                features[13] = np.random.beta(7, 3) * 0.8
                features[14] = np.random.beta(3, 7) * 0.3
                features[15] = np.random.beta(3, 7) * 0.3
                features[16] = np.random.beta(2, 8) * 0.15
                features[17] = np.random.beta(3, 7) * 0.3

            elif label == 4:
                features[0] = np.random.beta(4, 6) * 0.4
                features[1] = np.random.beta(2, 8) * 0.15
                features[2] = np.random.beta(2, 8) * 0.15
                features[3] = np.random.beta(8, 2) * 0.9
                features[4] = np.random.beta(4, 6) * 0.4
                features[5] = np.random.beta(2, 8) * 0.15
                features[6] = np.random.beta(4, 6) * 0.4
                features[7] = np.random.beta(4, 6) * 0.4
                features[8] = np.random.beta(3, 7) * 0.25
                features[9] = np.random.beta(3, 7) * 0.25
                features[10] = np.random.beta(5, 5) * 0.5
                features[11] = np.random.beta(7, 3) * 0.7
                features[12] = np.random.beta(2, 8) * 0.15
                features[13] = np.random.beta(3, 7) * 0.25
                features[14] = np.random.beta(2, 8) * 0.15
                features[15] = np.random.beta(3, 7) * 0.3
                features[16] = np.random.beta(2, 8) * 0.15
                features[17] = np.random.beta(7, 3) * 0.7

            noise = np.random.normal(0, 0.02, 18).astype(np.float32)
            features = features + noise
            features = np.clip(features, 0, 1)
        features = np.clip(features, 0, None)

        data_list.append(features.tolist())
        label_list.append(label)

    dataset = {
        "feature_names": feature_names,
        "class_names": class_names,
        "num_features": 18,
        "num_classes": 5,
        "data": data_list,
        "labels": label_list
    }

    output_path = output_dir / "file_classify_dataset.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(dataset, f, ensure_ascii=False, indent=2)

    print(f"[*] 文件分类数据集已生成: {output_path}")
    print(f"    样本数: {num_samples}")
    print(f"    特征维度: 18")
    print(f"    分类数: 5")

    return dataset


if __name__ == "__main__":
    print("=" * 60)
    print("  双AI模型训练数据集生成器")
    print("=" * 60)

    base_dir = Path(__file__).parent / "dataset"
    generate_security_dataset(base_dir / "security", 100000)
    generate_clean_dataset(base_dir / "clean", 100000)

    print("\n[*] 所有数据集生成完成！")
