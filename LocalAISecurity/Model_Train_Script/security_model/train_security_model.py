"""
AI安全行为识别模型 - 训练脚本
模型1：进程行为时序分类CNN
输入：32维进程行为时序特征向量
输出：4分类（正常/可疑流氓/高危木马/勒索病毒）
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
from models import SecurityBehaviorCNN


# ============================================================
# 2. 数据集定义
# ============================================================
# 32维进程行为特征:
# [0-3]:  CPU占用率, 内存占用率, 线程数, 句柄数
# [4-7]:  文件创建频率, 文件修改频率, 文件删除频率, 文件重命名频率
# [8-11]: 注册表读取频率, 注册表写入频率, 注册表删除频率, 注册表监控频率
# [12-15]: 网络连接频率, 网络发送字节数, 网络接收字节数, 异常端口连接数
# [16-19]: 进程注入行为, DLL注入行为, 进程隐藏行为, 进程复活行为
# [20-23]: 批量文件加密行为, 键盘记录行为, 截屏行为, 摄像头访问行为
# [24-27]: 静默安装行为, 后台自启动, 服务注册行为, 驱动加载行为
# [28-31]: 弹窗频率, 诱导点击行为, 浏览器劫持行为, 权限提升行为

CLASS_NAMES = ["正常程序", "可疑流氓行为", "高危木马/注入行为", "勒索病毒加密行为"]

class SecurityBehaviorDataset(Dataset):
    """进程行为时序数据集"""
    def __init__(self, data_list, label_list):
        self.data = torch.FloatTensor(data_list).unsqueeze(1)  # (N, 1, 32)
        self.labels = torch.LongTensor(label_list)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return self.data[idx], self.labels[idx]


# ============================================================
# 3. 合成训练数据生成器（实际训练时替换为真实数据）
# ============================================================
def generate_synthetic_data(num_samples=100000):
    """生成合成训练数据 - 实际使用时替换为真实采集数据"""
    data_list = []
    label_list = []

    for i in range(num_samples):
        label = i % 4
        features = np.zeros(32, dtype=np.float32)

        if label == 0:  # 正常程序
            features[0] = np.random.uniform(0, 15)      # CPU低
            features[1] = np.random.uniform(0, 200)      # 内存正常
            features[2] = np.random.uniform(1, 20)       # 线程正常
            features[3] = np.random.uniform(10, 200)     # 句柄正常
            features[4] = np.random.uniform(0, 2)        # 文件创建少
            features[5] = np.random.uniform(0, 3)        # 文件修改少
            features[8] = np.random.uniform(0, 2)        # 注册表读取少
            features[9] = np.random.uniform(0, 1)        # 注册表写入极少
            features[12] = np.random.uniform(0, 3)       # 网络连接正常
            features[16:24] = 0                           # 无恶意行为
            features[28] = np.random.uniform(0, 1)        # 弹窗少

        elif label == 1:  # 可疑流氓行为
            features[0] = np.random.uniform(5, 40)       # CPU中等
            features[1] = np.random.uniform(100, 500)    # 内存偏高
            features[2] = np.random.uniform(5, 50)       # 线程偏多
            features[4] = np.random.uniform(2, 10)       # 文件创建多
            features[9] = np.random.uniform(2, 8)        # 注册表写入多
            features[12] = np.random.uniform(3, 15)      # 网络连接多
            features[13] = np.random.uniform(100, 5000)  # 网络发送多
            features[24] = np.random.uniform(0.5, 1)     # 静默安装
            features[25] = np.random.uniform(0.5, 1)     # 后台自启动
            features[26] = np.random.uniform(0.3, 0.8)   # 服务注册
            features[28] = np.random.uniform(3, 20)      # 弹窗多
            features[29] = np.random.uniform(0.5, 1)     # 诱导点击

        elif label == 2:  # 高危木马/注入行为
            features[0] = np.random.uniform(10, 60)      # CPU偏高
            features[1] = np.random.uniform(50, 800)     # 内存波动大
            features[2] = np.random.uniform(3, 100)      # 线程波动
            features[16] = np.random.uniform(0.7, 1)     # 进程注入
            features[17] = np.random.uniform(0.6, 1)     # DLL注入
            features[18] = np.random.uniform(0.5, 1)     # 进程隐藏
            features[19] = np.random.uniform(0.4, 1)     # 进程复活
            features[20] = np.random.uniform(0, 0.3)     # 少量加密
            features[21] = np.random.uniform(0.5, 1)     # 键盘记录
            features[22] = np.random.uniform(0.3, 0.8)   # 截屏
            features[27] = np.random.uniform(0.5, 1)     # 驱动加载
            features[31] = np.random.uniform(0.6, 1)     # 权限提升

        elif label == 3:  # 勒索病毒加密行为
            features[0] = np.random.uniform(30, 95)      # CPU极高
            features[1] = np.random.uniform(200, 1000)   # 内存高
            features[5] = np.random.uniform(50, 500)     # 文件修改极多
            features[6] = np.random.uniform(10, 100)     # 文件删除多
            features[7] = np.random.uniform(10, 100)     # 文件重命名多
            features[9] = np.random.uniform(5, 30)       # 注册表写入多
            features[16] = np.random.uniform(0.3, 0.8)   # 部分注入
            features[20] = np.random.uniform(0.9, 1)     # 批量加密
            features[25] = np.random.uniform(0.7, 1)     # 自启动
            features[26] = np.random.uniform(0.5, 1)     # 服务注册
            features[31] = np.random.uniform(0.8, 1)     # 权限提升

        # 添加噪声
        features += np.random.normal(0, 0.05, 32).astype(np.float32)
        features = np.clip(features, 0, None)

        data_list.append(features)
        label_list.append(label)

    return data_list, label_list


# ============================================================
# 4. 训练流程
# ============================================================
def train_model():
    # 超参数（白皮书规定）
    BATCH_SIZE = 32
    LEARNING_RATE = 0.001
    EPOCHS = 80
    MODEL_DIR = Path(__file__).parent.parent.parent / "models"
    MODEL_DIR.mkdir(exist_ok=True)

    # 设备
    device = torch.device("cpu")  # 强制CPU训练，确保兼容性

    # 生成/加载数据
    print("[*] 生成训练数据...")
    data_list, label_list = generate_synthetic_data(100000)

    # 划分训练集/验证集 (90/10)
    split_idx = int(len(data_list) * 0.9)
    train_dataset = SecurityBehaviorDataset(data_list[:split_idx], label_list[:split_idx])
    val_dataset = SecurityBehaviorDataset(data_list[split_idx:], label_list[split_idx:])

    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False)

    # 模型
    model = SecurityBehaviorCNN().to(device)
    print(f"[*] 模型参数量: {sum(p.numel() for p in model.parameters()):,}")

    # 损失函数 & 优化器
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE)
    scheduler = optim.lr_scheduler.StepLR(optimizer, step_size=20, gamma=0.5)

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
        with torch.no_grad():
            for batch_data, batch_labels in val_loader:
                batch_data, batch_labels = batch_data.to(device), batch_labels.to(device)
                outputs = model(batch_data)
                loss = criterion(outputs, batch_labels)
                val_loss += loss.item()
                _, predicted = torch.max(outputs.data, 1)
                val_total += batch_labels.size(0)
                val_correct += (predicted == batch_labels).sum().item()

        train_acc = 100.0 * train_correct / train_total
        val_acc = 100.0 * val_correct / val_total

        if (epoch + 1) % 10 == 0:
            print(f"Epoch [{epoch+1}/{EPOCHS}] "
                  f"Train Loss: {train_loss/len(train_loader):.4f} Acc: {train_acc:.2f}% | "
                  f"Val Loss: {val_loss/len(val_loader):.4f} Acc: {val_acc:.2f}%")

        if val_acc > best_val_acc:
            best_val_acc = val_acc
            torch.save(model.state_dict(), MODEL_DIR / "security_model_best.pt")

    print(f"\n[*] 最佳验证准确率: {best_val_acc:.2f}%")

    # ============================================================
    # 5. INT4量化 & 导出
    # ============================================================
    print("\n[*] 执行INT4量化压缩...")
    model.load_state_dict(torch.load(MODEL_DIR / "security_model_best.pt", weights_only=True))
    model.eval()

    # 导出ONNX
    dummy_input = torch.randn(1, 1, 32)
    onnx_path = MODEL_DIR / "security_model.onnx"
    torch.onnx.export(
        model, dummy_input, onnx_path,
        input_names=["behavior_features"],
        output_names=["classification"],
        dynamic_axes={"behavior_features": {0: "batch_size"}, "classification": {0: "batch_size"}},
        opset_version=13
    )
    print(f"[*] ONNX模型已导出: {onnx_path}")

    # INT4量化（使用自定义量化方案）
    quantized_model = quantize_int4(model)
    quant_path = MODEL_DIR / "security_model_int4.bin"
    save_quantized_model(quantized_model, quant_path)
    print(f"[*] INT4量化模型已保存: {quant_path}")

    # 模型体积报告
    import os
    onnx_size = os.path.getsize(onnx_path) / (1024 * 1024)
    quant_size = os.path.getsize(quant_path) / (1024 * 1024)
    print(f"\n[*] 模型体积报告:")
    print(f"    ONNX模型: {onnx_size:.2f} MB")
    print(f"    INT4量化: {quant_size:.2f} MB")
    print(f"    压缩率: {(1 - quant_size/onnx_size)*100:.1f}%")

    return model


# ============================================================
# 6. INT4量化实现
# ============================================================
def quantize_int4(model):
    """
    自研INT4量化方案
    将FP32权重压缩为4bit整数
    每16个权重共享一个缩放因子(scale)和零点(zero_point)
    """
    quantized_state = {}
    for name, param in model.state_dict().items():
        if param.dim() < 2:
            quantized_state[name] = param
            continue

        weight = param.data.numpy()
        # 分组量化: 每16个元素一组
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
            scale = (w_max - w_min) / 15.0  # 4bit: 0-15
            if scale == 0:
                scale = 1e-8
            zero_point = w_min

            scales[g] = scale
            zero_points[g] = zero_point

            # 量化到0-15
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
        # 文件头: 魔数 + 版本 + 层数
        f.write(b'SAIQ')  # Security AI Quantized
        f.write(struct.pack('<I', 1))  # 版本1

        num_layers = sum(1 for v in quantized_state.values() if isinstance(v, dict))
        f.write(struct.pack('<I', num_layers))

        for name, data in quantized_state.items():
            if isinstance(data, dict):
                # 层名
                name_bytes = name.encode('utf-8')
                f.write(struct.pack('<I', len(name_bytes)))
                f.write(name_bytes)

                # 形状
                shape = data['orig_shape']
                f.write(struct.pack('<I', len(shape)))
                for s in shape:
                    f.write(struct.pack('<I', s))

                # 量化参数
                scales = data['scales']
                zero_points = data['zero_points']
                f.write(struct.pack('<I', len(scales)))
                f.write(scales.tobytes())
                f.write(zero_points.tobytes())

                # 量化权重 (两个4bit值打包到一个uint8)
                qw = data['quant_weights']
                # 填充到偶数长度
                if len(qw) % 2 != 0:
                    qw = np.append(qw, 0)
                packed = np.zeros(len(qw) // 2, dtype=np.uint8)
                for i in range(len(packed)):
                    packed[i] = (qw[i*2] & 0x0F) | ((qw[i*2+1] & 0x0F) << 4)
                f.write(struct.pack('<I', len(packed)))
                f.write(packed.tobytes())
            else:
                # 非量化参数（BN等）
                name_bytes = name.encode('utf-8')
                f.write(struct.pack('<I', len(name_bytes)))
                f.write(name_bytes)
                f.write(struct.pack('<I', 0))  # 标记为非量化层
                tensor = data.numpy()
                f.write(struct.pack('<I', tensor.size))
                f.write(tensor.tobytes())


# ============================================================
# 7. 验证量化模型精度
# ============================================================
def validate_quantized_model(model, quantized_state, num_samples=1000):
    """验证INT4量化后模型精度损失"""
    # 反量化
    dequant_state = {}
    for name, data in quantized_state.items():
        if isinstance(data, dict):
            qw = data['quant_weights']
            scales = data['scales']
            zero_points = data['zero_points']
            group_size = data['group_size']
            orig_shape = data['orig_shape']

            flat = np.zeros(len(qw), dtype=np.float32)
            num_groups = len(scales)
            for g in range(num_groups):
                start = g * group_size
                end = min(start + group_size, len(flat))
                flat[start:end] = qw[start:end].astype(np.float32) * scales[g] + zero_points[g]

            dequant_state[name] = torch.FloatTensor(flat.reshape(orig_shape))
        else:
            dequant_state[name] = data

    # 测试精度
    model_copy = SecurityBehaviorCNN()
    model_copy.load_state_dict(dequant_state)
    model_copy.eval()

    data_list, label_list = generate_synthetic_data(num_samples)
    dataset = SecurityBehaviorDataset(data_list, label_list)
    loader = DataLoader(dataset, batch_size=32, shuffle=False)

    correct = 0
    total = 0
    with torch.no_grad():
        for batch_data, batch_labels in loader:
            outputs = model_copy(batch_data)
            _, predicted = torch.max(outputs.data, 1)
            total += batch_labels.size(0)
            correct += (predicted == batch_labels).sum().item()

    acc = 100.0 * correct / total
    print(f"[*] INT4量化后准确率: {acc:.2f}%")
    return acc


# ============================================================
# 主入口
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  AI安全行为识别模型 - 训练流水线")
    print("  输入: 32维进程行为时序特征")
    print("  输出: 4分类 (正常/流氓/木马/勒索)")
    print("=" * 60)

    model = train_model()

    print("\n[*] 训练完成！模型文件已保存至 models/ 目录")
