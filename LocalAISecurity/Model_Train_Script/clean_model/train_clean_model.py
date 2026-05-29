"""
AI C盘文件智能分类模型 - 训练脚本
模型2：文件特征分类CNN
输入：18维文件特征向量
输出：5分类（系统核心必需/软件运行必需缓存/安全可删普通垃圾/大型冗余堆积/用户个人重要文件）
框架：PyTorch（训练用） → 导出ONNX → C++推理
"""

import os
import sys
import json
import random
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from models import FileClassifyCNN


# ============================================================
# 2. 数据集定义
# ============================================================
# 18维文件特征:
# [0]:   文件路径深度 (目录层级数)
# [1]:   是否在系统目录 (0/1)
# [2]:   是否在Program Files (0/1)
# [3]:   是否在用户目录 (0/1)
# [4]:   是否在AppData (0/1)
# [5]:   是否在Temp目录 (0/1)
# [6]:   文件大小 (MB, log归一化)
# [7]:   创建时间距今天数
# [8]:   最后访问时间距今天数
# [9]:   最后修改时间距今天数
# [10]:  修改频率 (次/月)
# [11]:  文件后缀权重 (0-1, 系统文件高/临时文件低)
# [12]:  系统目录权重 (0-1)
# [13]:  堆叠层级特征 (同目录文件数)
# [14]:  是否为隐藏文件 (0/1)
# [15]:  是否为只读文件 (0/1)
# [16]:  是否为系统文件属性 (0/1)
# [17]:  扩展名风险评分 (0-1)

CLASS_NAMES = [
    "系统核心必需",         # 绝对禁止删除
    "软件运行必需缓存",     # 禁止删除
    "安全可删普通垃圾",     # 一键清理区
    "大型冗余堆积",         # 深度瘦身区
    "用户个人重要文件"      # 强制保护
]

class FileClassifyDataset(Dataset):
    """文件特征分类数据集"""
    def __init__(self, data_list, label_list):
        self.data = torch.FloatTensor(data_list).unsqueeze(1)  # (N, 1, 18)
        self.labels = torch.LongTensor(label_list)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return self.data[idx], self.labels[idx]


# ============================================================
# 3. 合成训练数据生成器
# ============================================================
def generate_synthetic_data(num_samples=100000):
    """生成合成训练数据 - 实际使用时替换为真实Windows文件特征数据"""
    data_list = []
    label_list = []

    for i in range(num_samples):
        label = i % 5
        features = np.zeros(18, dtype=np.float32)

        if label == 0:  # 系统核心必需
            features[0] = np.random.uniform(1, 5)       # 路径深度浅
            features[1] = np.random.uniform(0.8, 1)     # 在系统目录
            features[2] = np.random.uniform(0, 0.3)     # 不在Program Files
            features[3] = np.random.uniform(0, 0.1)     # 不在用户目录
            features[4] = np.random.uniform(0, 0.1)     # 不在AppData
            features[5] = 0                               # 不在Temp
            features[6] = np.random.uniform(-2, 3)       # 文件大小适中(log MB)
            features[7] = np.random.uniform(100, 1000)   # 创建很久
            features[8] = np.random.uniform(0, 10)       # 近期访问
            features[9] = np.random.uniform(0, 30)       # 近期修改
            features[10] = np.random.uniform(0, 2)       # 修改频率低
            features[11] = np.random.uniform(0.8, 1)     # 后缀权重高
            features[12] = np.random.uniform(0.8, 1)     # 系统目录权重高
            features[13] = np.random.uniform(1, 20)      # 同目录文件少
            features[14] = np.random.uniform(0, 0.3)     # 不隐藏
            features[15] = np.random.uniform(0.5, 1)     # 可能只读
            features[16] = np.random.uniform(0.7, 1)     # 系统文件属性
            features[17] = np.random.uniform(0.8, 1)     # 扩展名安全

        elif label == 1:  # 软件运行必需缓存
            features[0] = np.random.uniform(3, 8)       # 路径深度中等
            features[1] = np.random.uniform(0, 0.3)     # 不在系统目录
            features[2] = np.random.uniform(0.3, 0.8)   # 可能在Program Files
            features[3] = np.random.uniform(0, 0.3)     # 不在用户目录
            features[4] = np.random.uniform(0.5, 1)     # 在AppData
            features[5] = np.random.uniform(0, 0.3)     # 不在Temp
            features[6] = np.random.uniform(-1, 4)       # 文件大小中等
            features[7] = np.random.uniform(10, 500)     # 创建时间中等
            features[8] = np.random.uniform(0, 5)       # 近期访问
            features[9] = np.random.uniform(0, 10)       # 近期修改
            features[10] = np.random.uniform(1, 10)      # 修改频率中等
            features[11] = np.random.uniform(0.3, 0.7)   # 后缀权重中等
            features[12] = np.random.uniform(0.3, 0.7)   # 系统目录权重中等
            features[13] = np.random.uniform(5, 50)      # 同目录文件中等
            features[14] = np.random.uniform(0, 0.3)     # 不隐藏
            features[15] = np.random.uniform(0, 0.5)     # 不只读
            features[16] = np.random.uniform(0, 0.3)     # 非系统文件
            features[17] = np.random.uniform(0.3, 0.7)   # 扩展名中等

        elif label == 2:  # 安全可删普通垃圾
            features[0] = np.random.uniform(4, 12)      # 路径深度深
            features[1] = np.random.uniform(0, 0.1)     # 不在系统目录
            features[2] = np.random.uniform(0, 0.2)     # 不在Program Files
            features[3] = np.random.uniform(0, 0.3)     # 可能在用户目录
            features[4] = np.random.uniform(0.3, 0.8)   # 可能在AppData
            features[5] = np.random.uniform(0.7, 1)     # 在Temp
            features[6] = np.random.uniform(-3, 2)       # 文件小
            features[7] = np.random.uniform(0, 100)     # 创建时间短
            features[8] = np.random.uniform(30, 1000)   # 很久没访问
            features[9] = np.random.uniform(30, 1000)   # 很久没修改
            features[10] = np.random.uniform(0, 1)       # 修改频率低
            features[11] = np.random.uniform(0, 0.3)     # 后缀权重低(.tmp/.log等)
            features[12] = np.random.uniform(0, 0.2)     # 系统目录权重低
            features[13] = np.random.uniform(10, 200)    # 同目录文件多
            features[14] = np.random.uniform(0, 0.5)     # 可能隐藏
            features[15] = np.random.uniform(0, 0.2)     # 不只读
            features[16] = 0                              # 非系统文件
            features[17] = np.random.uniform(0, 0.3)     # 扩展名低风险

        elif label == 3:  # 大型冗余堆积
            features[0] = np.random.uniform(5, 15)      # 路径深度很深
            features[1] = np.random.uniform(0, 0.2)     # 不在系统目录
            features[2] = np.random.uniform(0, 0.3)     # 不在Program Files
            features[3] = np.random.uniform(0, 0.5)     # 可能在用户目录
            features[4] = np.random.uniform(0.5, 1)     # 在AppData
            features[5] = np.random.uniform(0, 0.5)     # 可能在Temp
            features[6] = np.random.uniform(3, 8)       # 文件大(log MB)
            features[7] = np.random.uniform(30, 500)    # 创建时间中等
            features[8] = np.random.uniform(60, 1000)   # 很久没访问
            features[9] = np.random.uniform(60, 1000)   # 很久没修改
            features[10] = np.random.uniform(0, 0.5)    # 修改频率极低
            features[11] = np.random.uniform(0, 0.4)    # 后缀权重低
            features[12] = np.random.uniform(0, 0.3)    # 系统目录权重低
            features[13] = np.random.uniform(50, 500)   # 同目录文件极多
            features[14] = np.random.uniform(0, 0.3)    # 不隐藏
            features[15] = np.random.uniform(0, 0.2)    # 不只读
            features[16] = 0                              # 非系统文件
            features[17] = np.random.uniform(0, 0.4)    # 扩展名低风险

        elif label == 4:  # 用户个人重要文件
            features[0] = np.random.uniform(2, 8)       # 路径深度中等
            features[1] = np.random.uniform(0, 0.1)     # 不在系统目录
            features[2] = np.random.uniform(0, 0.1)     # 不在Program Files
            features[3] = np.random.uniform(0.8, 1)     # 在用户目录
            features[4] = np.random.uniform(0, 0.3)     # 不在AppData
            features[5] = 0                               # 不在Temp
            features[6] = np.random.uniform(-1, 5)       # 文件大小不定
            features[7] = np.random.uniform(0, 500)     # 创建时间不定
            features[8] = np.random.uniform(0, 30)       # 近期访问
            features[9] = np.random.uniform(0, 30)       # 近期修改
            features[10] = np.random.uniform(1, 15)      # 修改频率中等
            features[11] = np.random.uniform(0.5, 1)     # 后缀权重高(.doc/.xls等)
            features[12] = np.random.uniform(0, 0.2)     # 系统目录权重低
            features[13] = np.random.uniform(1, 30)      # 同目录文件少
            features[14] = np.random.uniform(0, 0.2)     # 不隐藏
            features[15] = np.random.uniform(0, 0.5)     # 可能只读
            features[16] = 0                              # 非系统文件
            features[17] = np.random.uniform(0.7, 1)     # 扩展名安全

        # 添加噪声
        features += np.random.normal(0, 0.03, 18).astype(np.float32)
        features = np.clip(features, 0, None)

        data_list.append(features)
        label_list.append(label)

    return data_list, label_list


# ============================================================
# 4. 训练流程
# ============================================================
def train_model():
    # 超参数（白皮书规定）
    BATCH_SIZE = 16
    LEARNING_RATE = 0.0008
    EPOCHS = 100
    MODEL_DIR = Path(__file__).parent.parent.parent / "models"
    MODEL_DIR.mkdir(exist_ok=True)

    device = torch.device("cpu")

    # 生成/加载数据
    print("[*] 生成训练数据...")
    data_list, label_list = generate_synthetic_data(100000)

    # 划分训练集/验证集 (90/10)
    split_idx = int(len(data_list) * 0.9)
    train_dataset = FileClassifyDataset(data_list[:split_idx], label_list[:split_idx])
    val_dataset = FileClassifyDataset(data_list[split_idx:], label_list[split_idx:])

    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False)

    # 模型
    model = FileClassifyCNN().to(device)
    print(f"[*] 模型参数量: {sum(p.numel() for p in model.parameters()):,}")

    # 损失函数 & 优化器
    # 对类别0和4（不可删类）增加权重，防误删核心指标
    class_weights = torch.FloatTensor([2.0, 1.5, 1.0, 1.0, 2.5]).to(device)
    criterion = nn.CrossEntropyLoss(weight=class_weights)
    optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE)
    scheduler = optim.lr_scheduler.StepLR(optimizer, step_size=25, gamma=0.5)

    # 训练循环
    best_val_acc = 0.0
    for epoch in range(EPOCHS):
        model.train()
        train_loss = 0.0
        train_correct = 0
        train_total = 0

        for batch_data, batch_labels in train_loader:
            batch_data, batch_labels = batch_data.to(device), batch_labels.to(device)

            optimizer.zero_grad()
            outputs = model(batch_data)
            loss = criterion(outputs, batch_labels)
            loss.backward()
            optimizer.step()

            train_loss += loss.item()
            _, predicted = torch.max(outputs.data, 1)
            train_total += batch_labels.size(0)
            train_correct += (predicted == batch_labels).sum().item()

        scheduler.step()

        # 验证
        model.eval()
        val_correct = 0
        val_total = 0
        val_loss = 0.0
        # 分类别统计
        class_correct = [0] * 5
        class_total = [0] * 5

        with torch.no_grad():
            for batch_data, batch_labels in val_loader:
                batch_data, batch_labels = batch_data.to(device), batch_labels.to(device)
                outputs = model(batch_data)
                loss = criterion(outputs, batch_labels)
                val_loss += loss.item()
                _, predicted = torch.max(outputs.data, 1)
                val_total += batch_labels.size(0)
                val_correct += (predicted == batch_labels).sum().item()

                for c in range(5):
                    mask = batch_labels == c
                    class_total[c] += mask.sum().item()
                    class_correct[c] += (predicted[mask] == c).sum().item()

        train_acc = 100.0 * train_correct / train_total
        val_acc = 100.0 * val_correct / val_total

        if (epoch + 1) % 10 == 0:
            print(f"Epoch [{epoch+1}/{EPOCHS}] "
                  f"Train Loss: {train_loss/len(train_loader):.4f} Acc: {train_acc:.2f}% | "
                  f"Val Loss: {val_loss/len(val_loader):.4f} Acc: {val_acc:.2f}%")
            # 分类别报告
            for c in range(5):
                if class_total[c] > 0:
                    ca = 100.0 * class_correct[c] / class_total[c]
                    print(f"  类别{c} [{CLASS_NAMES[c]}]: {ca:.1f}%")

        if val_acc > best_val_acc:
            best_val_acc = val_acc
            torch.save(model.state_dict(), MODEL_DIR / "clean_model_best.pt")

    print(f"\n[*] 最佳验证准确率: {best_val_acc:.2f}%")

    # ============================================================
    # 5. INT4量化 & 导出
    # ============================================================
    print("\n[*] 执行INT4量化压缩...")
    model.load_state_dict(torch.load(MODEL_DIR / "clean_model_best.pt", weights_only=True))
    model.eval()

    # 导出ONNX
    dummy_input = torch.randn(1, 1, 18)
    onnx_path = MODEL_DIR / "clean_model.onnx"
    torch.onnx.export(
        model, dummy_input, onnx_path,
        input_names=["file_features"],
        output_names=["classification"],
        dynamic_axes={"file_features": {0: "batch_size"}, "classification": {0: "batch_size"}},
        opset_version=13
    )
    print(f"[*] ONNX模型已导出: {onnx_path}")

    # INT4量化
    quantized_model = quantize_int4(model)
    quant_path = MODEL_DIR / "clean_model_int4.bin"
    save_quantized_model(quantized_model, quant_path)
    print(f"[*] INT4量化模型已保存: {quant_path}")

    # 模型体积报告
    onnx_size = os.path.getsize(onnx_path) / (1024 * 1024)
    quant_size = os.path.getsize(quant_path) / (1024 * 1024)
    print(f"\n[*] 模型体积报告:")
    print(f"    ONNX模型: {onnx_size:.2f} MB")
    print(f"    INT4量化: {quant_size:.2f} MB")
    print(f"    压缩率: {(1 - quant_size/onnx_size)*100:.1f}%")

    return model


# ============================================================
# 6. INT4量化实现（同安全模型方案）
# ============================================================
def quantize_int4(model):
    """自研INT4量化方案"""
    quantized_state = {}
    for name, param in model.state_dict().items():
        if param.dim() < 2:
            quantized_state[name] = param
            continue

        weight = param.data.numpy()
        group_size = 16
        orig_shape = weight.shape
        flat_weight = weight.flatten()
        num_groups = (len(flat_weight) + group_size - 1) // group_size

        scales = np.zeros(num_groups, dtype=np.float32)
        zero_points = np.zeros(num_groups, dtype=np.float32)
        quant_weights = np.zeros(num_groups * group_size, dtype=np.uint8)

        for g in range(num_groups):
            start = g * group_size
            end = min(start + group_size, len(flat_weight))
            group = flat_weight[start:end]

            w_min = group.min()
            w_max = group.max()
            scale = (w_max - w_min) / 15.0
            if scale == 0:
                scale = 1e-8
            zero_point = w_min

            scales[g] = scale
            zero_points[g] = zero_point

            q = np.clip(np.round((group - zero_point) / scale), 0, 15).astype(np.uint8)
            quant_weights[start:end] = q

        quantized_state[name] = {
            'quant_weights': quant_weights[:len(flat_weight)],
            'scales': scales,
            'zero_points': zero_points,
            'orig_shape': orig_shape,
            'group_size': group_size
        }

    return quantized_state


def save_quantized_model(quantized_state, path):
    """保存量化模型为二进制文件"""
    import struct

    with open(path, 'wb') as f:
        f.write(b'CIQF')  # Clean AI Quantized File
        f.write(struct.pack('<I', 1))

        num_layers = sum(1 for v in quantized_state.values() if isinstance(v, dict))
        f.write(struct.pack('<I', num_layers))

        for name, data in quantized_state.items():
            if isinstance(data, dict):
                name_bytes = name.encode('utf-8')
                f.write(struct.pack('<I', len(name_bytes)))
                f.write(name_bytes)

                shape = data['orig_shape']
                f.write(struct.pack('<I', len(shape)))
                for s in shape:
                    f.write(struct.pack('<I', s))

                scales = data['scales']
                zero_points = data['zero_points']
                f.write(struct.pack('<I', len(scales)))
                f.write(scales.tobytes())
                f.write(zero_points.tobytes())

                qw = data['quant_weights']
                if len(qw) % 2 != 0:
                    qw = np.append(qw, 0)
                packed = np.zeros(len(qw) // 2, dtype=np.uint8)
                for i in range(len(packed)):
                    packed[i] = (qw[i*2] & 0x0F) | ((qw[i*2+1] & 0x0F) << 4)
                f.write(struct.pack('<I', len(packed)))
                f.write(packed.tobytes())
            else:
                name_bytes = name.encode('utf-8')
                f.write(struct.pack('<I', len(name_bytes)))
                f.write(name_bytes)
                f.write(struct.pack('<I', 0))
                tensor = data.numpy()
                f.write(struct.pack('<I', tensor.size))
                f.write(tensor.tobytes())


# ============================================================
# 主入口
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  AI C盘文件智能分类模型 - 训练流水线")
    print("  输入: 18维文件特征向量")
    print("  输出: 5分类 (系统必需/必需缓存/可删垃圾/冗余堆积/用户重要)")
    print("=" * 60)

    model = train_model()

    print("\n[*] 训练完成！模型文件已保存至 models/ 目录")
