import os
import sys
import struct
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))
from models import SecurityBehaviorCNN, FileClassifyCNN
from data_utils import (
    generate_boundary_samples, generate_boundary_samples_clean,
    mixup_augmentation, load_real_data, blend_real_and_synthetic,
    add_outlier_samples,
)

MODELS_DIR = Path(__file__).parent.parent / "models"
MODELS_DIR.mkdir(exist_ok=True)


def generate_security_data(n=20000):
    data, labels = [], []
    class_ratios = [0.55, 0.20, 0.15, 0.10]
    class_counts = [int(n * r) for r in class_ratios]
    class_counts[0] += n - sum(class_counts)

    for label, count in enumerate(class_counts):
        for _ in range(count):
            f = np.zeros(32, dtype=np.float32)
            if label == 0:
                f[0] = np.random.beta(2, 8) * 0.3
                f[1] = np.random.beta(2, 5) * 0.3
                f[2] = np.random.beta(2, 10) * 0.4
                f[3] = np.random.beta(3, 7) * 0.4
                f[4] = np.random.beta(1, 20) * 0.1
                f[5] = np.random.beta(1, 30) * 0.05
                f[8] = np.random.beta(2, 10) * 0.2
                f[9] = np.random.beta(1, 30) * 0.05
                f[12] = np.random.beta(2, 15) * 0.15
                f[28] = np.random.beta(1, 20) * 0.1
                f[14] = np.random.beta(8, 2) * 0.9
                f[15] = np.random.beta(7, 3) * 0.8
                f[16] = np.random.beta(6, 4) * 0.7
                f[17] = np.random.beta(8, 2) * 0.9
                f[18] = np.random.beta(9, 1) * 0.95
                f[19] = np.random.beta(8, 2) * 0.85
                f[22] = np.random.beta(1, 15) * 0.05
                f[23] = np.random.beta(1, 15) * 0.05
                f[24] = np.random.beta(1, 20) * 0.03
                f[25] = np.random.beta(1, 20) * 0.03
                f[26] = np.random.beta(1, 20) * 0.03
                f[27] = np.random.beta(1, 30) * 0.02
                f[28] = np.random.beta(1, 15) * 0.05
                f[29] = np.random.beta(1, 30) * 0.02
                f[30] = np.random.beta(1, 30) * 0.02
                f[31] = np.random.beta(1, 30) * 0.02
            elif label == 1:
                f[0] = np.random.beta(4, 6) * 0.5
                f[1] = np.random.beta(4, 4) * 0.5
                f[2] = np.random.beta(3, 7) * 0.5
                f[4] = np.random.beta(3, 7) * 0.3
                f[9] = np.random.beta(4, 6) * 0.4
                f[12] = np.random.beta(4, 6) * 0.5
                f[13] = np.random.beta(3, 7) * 0.4
                f[24] = np.random.beta(6, 4) * 0.7
                f[25] = np.random.beta(6, 4) * 0.7
                f[26] = np.random.beta(5, 5) * 0.6
                f[28] = np.random.beta(5, 5) * 0.6
                f[29] = np.random.beta(6, 4) * 0.7
                f[14] = np.random.beta(4, 6) * 0.5
                f[15] = np.random.beta(4, 6) * 0.5
                f[16] = np.random.beta(5, 5) * 0.5
                f[17] = np.random.beta(4, 6) * 0.5
                f[18] = np.random.beta(5, 5) * 0.5
                f[19] = np.random.beta(4, 6) * 0.5
                f[22] = np.random.beta(2, 8) * 0.2
                f[23] = np.random.beta(2, 8) * 0.2
                f[30] = np.random.beta(3, 7) * 0.3
                f[31] = np.random.beta(3, 7) * 0.3
            elif label == 2:
                f[0] = np.random.beta(5, 5) * 0.7
                f[1] = np.random.beta(5, 5) * 0.6
                f[2] = np.random.beta(4, 6) * 0.6
                f[16] = np.random.beta(7, 3) * 0.85
                f[17] = np.random.beta(7, 3) * 0.8
                f[18] = np.random.beta(6, 4) * 0.75
                f[19] = np.random.beta(6, 4) * 0.7
                f[21] = np.random.beta(6, 4) * 0.7
                f[22] = np.random.beta(5, 5) * 0.6
                f[27] = np.random.beta(6, 4) * 0.7
                f[31] = np.random.beta(7, 3) * 0.8
                f[14] = np.random.beta(3, 7) * 0.3
                f[15] = np.random.beta(3, 7) * 0.3
                f[16] = np.random.beta(7, 3) * 0.85
                f[17] = np.random.beta(7, 3) * 0.8
                f[18] = np.random.beta(6, 4) * 0.75
                f[19] = np.random.beta(6, 4) * 0.7
                f[23] = np.random.beta(4, 6) * 0.4
                f[24] = np.random.beta(3, 7) * 0.3
                f[25] = np.random.beta(4, 6) * 0.4
                f[26] = np.random.beta(4, 6) * 0.4
                f[30] = np.random.beta(5, 5) * 0.5
            elif label == 3:
                f[0] = np.random.beta(8, 2) * 0.95
                f[1] = np.random.beta(7, 3) * 0.8
                f[5] = np.random.beta(7, 3) * 0.85
                f[6] = np.random.beta(6, 4) * 0.75
                f[7] = np.random.beta(6, 4) * 0.75
                f[9] = np.random.beta(7, 3) * 0.8
                f[20] = np.random.beta(9, 1) * 0.95
                f[25] = np.random.beta(7, 3) * 0.8
                f[26] = np.random.beta(6, 4) * 0.7
                f[31] = np.random.beta(8, 2) * 0.9
                f[14] = np.random.beta(2, 8) * 0.2
                f[15] = np.random.beta(2, 8) * 0.2
                f[16] = np.random.beta(2, 8) * 0.2
                f[17] = np.random.beta(2, 8) * 0.2
                f[18] = np.random.beta(2, 8) * 0.2
                f[19] = np.random.beta(2, 8) * 0.2
                f[23] = np.random.beta(6, 4) * 0.7
                f[24] = np.random.beta(5, 5) * 0.6
                f[30] = np.random.beta(6, 4) * 0.7

            noise = np.random.normal(0, 0.02, 32).astype(np.float32)
            f = f + noise
            f = np.clip(f, 0, 1)
            data.append(f)
            labels.append(label)
    idx = np.arange(len(data))
    np.random.shuffle(idx)
    data = np.array(data)[idx]
    labels = np.array(labels)[idx]
    return data, labels


def generate_clean_data(n=20000):
    data, labels = [], []
    class_ratios = [0.25, 0.20, 0.25, 0.15, 0.15]
    class_counts = [int(n * r) for r in class_ratios]
    class_counts[0] += n - sum(class_counts)

    for label, count in enumerate(class_counts):
        for _ in range(count):
            f = np.zeros(18, dtype=np.float32)
            if label == 0:
                f[0] = np.random.beta(3, 8) * 0.3
                f[1] = np.random.beta(8, 2) * 0.9
                f[2] = np.random.beta(2, 8) * 0.15
                f[3] = np.random.beta(2, 8) * 0.1
                f[4] = np.random.beta(2, 8) * 0.1
                f[5] = np.random.beta(1, 30) * 0.02
                f[6] = np.random.beta(3, 7) * 0.25
                f[7] = np.random.beta(8, 2) * 0.9
                f[8] = np.random.beta(2, 8) * 0.1
                f[9] = np.random.beta(3, 7) * 0.3
                f[10] = np.random.beta(3, 7) * 0.3
                f[11] = np.random.beta(8, 2) * 0.9
                f[12] = np.random.beta(8, 2) * 0.9
                f[13] = np.random.beta(3, 7) * 0.3
                f[14] = np.random.beta(5, 5) * 0.5
                f[15] = np.random.beta(6, 4) * 0.6
                f[16] = np.random.beta(7, 3) * 0.7
                f[17] = np.random.beta(8, 2) * 0.9
            elif label == 1:
                f[0] = np.random.beta(5, 5) * 0.5
                f[1] = np.random.beta(3, 7) * 0.3
                f[2] = np.random.beta(6, 4) * 0.65
                f[3] = np.random.beta(3, 7) * 0.3
                f[4] = np.random.beta(6, 4) * 0.7
                f[5] = np.random.beta(3, 7) * 0.3
                f[6] = np.random.beta(4, 6) * 0.4
                f[7] = np.random.beta(4, 6) * 0.5
                f[8] = np.random.beta(3, 7) * 0.25
                f[9] = np.random.beta(4, 6) * 0.4
                f[10] = np.random.beta(5, 5) * 0.5
                f[11] = np.random.beta(5, 5) * 0.5
                f[12] = np.random.beta(5, 5) * 0.5
                f[13] = np.random.beta(4, 6) * 0.4
                f[14] = np.random.beta(3, 7) * 0.3
                f[15] = np.random.beta(3, 7) * 0.3
                f[16] = np.random.beta(3, 7) * 0.3
                f[17] = np.random.beta(5, 5) * 0.5
            elif label == 2:
                f[0] = np.random.beta(6, 4) * 0.7
                f[1] = np.random.beta(1, 20) * 0.05
                f[2] = np.random.beta(2, 8) * 0.15
                f[3] = np.random.beta(4, 6) * 0.4
                f[4] = np.random.beta(3, 7) * 0.3
                f[5] = np.random.beta(8, 2) * 0.85
                f[6] = np.random.beta(2, 8) * 0.15
                f[7] = np.random.beta(4, 6) * 0.4
                f[8] = np.random.beta(8, 2) * 0.9
                f[9] = np.random.beta(8, 2) * 0.9
                f[10] = np.random.beta(3, 7) * 0.25
                f[11] = np.random.beta(2, 8) * 0.15
                f[12] = np.random.beta(1, 20) * 0.05
                f[13] = np.random.beta(3, 7) * 0.25
                f[14] = np.random.beta(3, 7) * 0.3
                f[15] = np.random.beta(3, 7) * 0.3
                f[16] = np.random.beta(2, 8) * 0.15
                f[17] = np.random.beta(2, 8) * 0.15
            elif label == 3:
                f[0] = np.random.beta(7, 3) * 0.8
                f[1] = np.random.beta(2, 8) * 0.15
                f[2] = np.random.beta(3, 7) * 0.3
                f[3] = np.random.beta(4, 6) * 0.4
                f[4] = np.random.beta(6, 4) * 0.7
                f[5] = np.random.beta(3, 7) * 0.3
                f[6] = np.random.beta(8, 2) * 0.9
                f[7] = np.random.beta(5, 5) * 0.5
                f[8] = np.random.beta(8, 2) * 0.9
                f[9] = np.random.beta(8, 2) * 0.9
                f[10] = np.random.beta(2, 8) * 0.15
                f[11] = np.random.beta(3, 7) * 0.3
                f[12] = np.random.beta(2, 8) * 0.15
                f[13] = np.random.beta(7, 3) * 0.8
                f[14] = np.random.beta(3, 7) * 0.3
                f[15] = np.random.beta(3, 7) * 0.3
                f[16] = np.random.beta(2, 8) * 0.15
                f[17] = np.random.beta(3, 7) * 0.3
            elif label == 4:
                f[0] = np.random.beta(4, 6) * 0.4
                f[1] = np.random.beta(2, 8) * 0.15
                f[2] = np.random.beta(2, 8) * 0.15
                f[3] = np.random.beta(8, 2) * 0.9
                f[4] = np.random.beta(4, 6) * 0.4
                f[5] = np.random.beta(2, 8) * 0.15
                f[6] = np.random.beta(4, 6) * 0.4
                f[7] = np.random.beta(4, 6) * 0.4
                f[8] = np.random.beta(3, 7) * 0.25
                f[9] = np.random.beta(3, 7) * 0.25
                f[10] = np.random.beta(5, 5) * 0.5
                f[11] = np.random.beta(7, 3) * 0.7
                f[12] = np.random.beta(2, 8) * 0.15
                f[13] = np.random.beta(3, 7) * 0.25
                f[14] = np.random.beta(2, 8) * 0.15
                f[15] = np.random.beta(3, 7) * 0.3
                f[16] = np.random.beta(2, 8) * 0.15
                f[17] = np.random.beta(7, 3) * 0.7

            noise = np.random.normal(0, 0.02, 18).astype(np.float32)
            f = f + noise
            f = np.clip(f, 0, 1)
            data.append(f)
            labels.append(label)
    idx = np.arange(len(data))
    np.random.shuffle(idx)
    data = np.array(data)[idx]
    labels = np.array(labels)[idx]
    return data, labels


def train_model(model, data, labels, name, epochs=30, batch_size=64):
    print(f"\n{'='*50}")
    print(f"  Training {name}")
    print(f"{'='*50}")

    tensor_data = torch.FloatTensor(data).unsqueeze(1)
    tensor_labels = torch.LongTensor(labels)

    dataset = torch.utils.data.TensorDataset(tensor_data, tensor_labels)
    train_size = int(0.9 * len(dataset))
    val_size = len(dataset) - train_size
    train_ds, val_ds = torch.utils.data.random_split(dataset, [train_size, val_size])

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size)

    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)

    best_acc = 0
    for epoch in range(epochs):
        model.train()
        total_loss = 0
        correct = 0
        total = 0
        for bx, by in train_loader:
            optimizer.zero_grad()
            out = model(bx)
            loss = criterion(out, by)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            correct += (out.argmax(1) == by).sum().item()
            total += by.size(0)

        model.eval()
        v_correct = 0
        v_total = 0
        with torch.no_grad():
            for bx, by in val_loader:
                out = model(bx)
                v_correct += (out.argmax(1) == by).sum().item()
                v_total += by.size(0)

        val_acc = 100.0 * v_correct / v_total
        if (epoch + 1) % 10 == 0:
            print(f"  Epoch {epoch+1}/{epochs}  Loss: {total_loss/len(train_loader):.4f}  "
                  f"Train: {100*correct/total:.1f}%  Val: {val_acc:.1f}%")

        if val_acc > best_acc:
            best_acc = val_acc
            best_state = {k: v.clone() for k, v in model.state_dict().items()}

    model.load_state_dict(best_state)
    print(f"  Best val accuracy: {best_acc:.1f}%")
    return model


def quantize_int4(state_dict):
    quantized = {}
    for name, param in state_dict.items():
        if param.dim() < 2:
            quantized[name] = ('raw', param.data.numpy())
            continue
        weight = param.data.numpy()
        group_size = 16
        orig_shape = weight.shape
        flat = weight.flatten()
        num_groups = (len(flat) + group_size - 1) // group_size

        scales = np.zeros(num_groups, dtype=np.float32)
        zero_points = np.zeros(num_groups, dtype=np.float32)
        qw = np.zeros(num_groups * group_size, dtype=np.uint8)

        for g in range(num_groups):
            s = g * group_size
            e = min(s + group_size, len(flat))
            grp = flat[s:e]
            w_min, w_max = grp.min(), grp.max()
            scale = (w_max - w_min) / 15.0
            if scale == 0:
                scale = 1e-8
            zp = w_min
            scales[g] = scale
            zero_points[g] = zp
            qw[s:e] = np.clip(np.round((grp - zp) / scale), 0, 15).astype(np.uint8)

        quantized[name] = ('quant', {
            'quant_weights': qw[:len(flat)],
            'scales': scales,
            'zero_points': zero_points,
            'orig_shape': orig_shape,
            'group_size': group_size
        })
    return quantized


def _save_quantized_model(magic, quantized, path):
    """通用量化模型保存函数。magic: b'SAIQ' 安全模型 / b'CIQF' 清理模型"""
    with open(path, 'wb') as f:
        f.write(magic)
        f.write(struct.pack('<I', 1))  # version
        num_layers = sum(1 for v in quantized.values() if v[0] == 'quant')
        f.write(struct.pack('<I', num_layers))
        for name, (kind, data) in quantized.items():
            if kind == 'quant':
                nb = name.encode('utf-8')
                f.write(struct.pack('<I', len(nb)))
                f.write(nb)
                shape = data['orig_shape']
                f.write(struct.pack('<I', len(shape)))
                for s in shape:
                    f.write(struct.pack('<I', s))
                f.write(struct.pack('<I', len(data['scales'])))
                f.write(data['scales'].tobytes())
                f.write(data['zero_points'].tobytes())
                qw = data['quant_weights']
                if len(qw) % 2 != 0:
                    qw = np.append(qw, 0)
                packed = np.zeros(len(qw) // 2, dtype=np.uint8)
                for i in range(len(packed)):
                    packed[i] = (qw[i * 2] & 0x0F) | ((qw[i * 2 + 1] & 0x0F) << 4)
                f.write(struct.pack('<I', len(packed)))
                f.write(packed.tobytes())
            else:
                nb = name.encode('utf-8')
                f.write(struct.pack('<I', len(nb)))
                f.write(nb)
                f.write(struct.pack('<I', 0))  # shape_dims=0 表示非量化层
                tensor = data
                f.write(struct.pack('<I', tensor.size))
                f.write(tensor.tobytes())


def main():
    print("=" * 60)
    print("  Dual AI Model Training Pipeline")
    print("  Security Model (4-class) + Clean Model (5-class)")
    print("=" * 60)

    sec_data, sec_labels = generate_security_data(20000)
    sec_bnd_f, sec_bnd_l = generate_boundary_samples(800)
    sec_data = np.vstack([sec_data, sec_bnd_f])
    sec_labels = np.concatenate([sec_labels, sec_bnd_l])
    sec_real_f, sec_real_l = load_real_data("security")
    sec_data, sec_labels = blend_real_and_synthetic(
        sec_real_f, sec_real_l, sec_data, sec_labels, real_weight=0.3)
    sec_mix_f, sec_mix_l = mixup_augmentation(sec_data, sec_labels, alpha=0.2, n_samples=2000)
    sec_data = np.vstack([sec_data, sec_mix_f])
    sec_labels = np.concatenate([sec_labels, sec_mix_l])
    sec_data, sec_labels = add_outlier_samples(sec_data, sec_labels, pct=0.02)
    print(f"  Security dataset: {len(sec_data)} samples")

    sec_model = SecurityBehaviorCNN()
    sec_model = train_model(sec_model, sec_data, sec_labels, "SecurityBehaviorCNN", epochs=30)

    torch.save(sec_model.state_dict(), MODELS_DIR / "security_model_best.pt")
    dummy = torch.randn(1, 1, 32)
    try:
        torch.onnx.export(sec_model, dummy, MODELS_DIR / "security_model.onnx",
                          input_names=["behavior_features"],
                          output_names=["classification"],
                          opset_version=18)
        print("  ONNX export OK")
    except Exception as e:
        print(f"  ONNX export skipped: {e}")
    sec_quant = quantize_int4(sec_model.state_dict())
    _save_quantized_model(b'SAIQ', sec_quant, MODELS_DIR / "security_model_int4.bin")

    clean_data, clean_labels = generate_clean_data(20000)
    clean_bnd_f, clean_bnd_l = generate_boundary_samples_clean(800)
    clean_data = np.vstack([clean_data, clean_bnd_f])
    clean_labels = np.concatenate([clean_labels, clean_bnd_l])
    clean_real_f, clean_real_l = load_real_data("clean")
    clean_data, clean_labels = blend_real_and_synthetic(
        clean_real_f, clean_real_l, clean_data, clean_labels, real_weight=0.3)
    clean_mix_f, clean_mix_l = mixup_augmentation(clean_data, clean_labels, alpha=0.2, n_samples=2000)
    clean_data = np.vstack([clean_data, clean_mix_f])
    clean_labels = np.concatenate([clean_labels, clean_mix_l])
    clean_data, clean_labels = add_outlier_samples(clean_data, clean_labels, pct=0.02)
    print(f"  Clean dataset: {len(clean_data)} samples")

    clean_model = FileClassifyCNN()
    clean_model = train_model(clean_model, clean_data, clean_labels, "FileClassifyCNN", epochs=30)

    torch.save(clean_model.state_dict(), MODELS_DIR / "clean_model_best.pt")
    dummy = torch.randn(1, 1, 18)
    try:
        torch.onnx.export(clean_model, dummy, MODELS_DIR / "clean_model.onnx",
                          input_names=["file_features"],
                          output_names=["classification"],
                          opset_version=18)
        print("  ONNX export OK")
    except Exception as e:
        print(f"  ONNX export skipped: {e}")
    clean_quant = quantize_int4(clean_model.state_dict())
    _save_quantized_model(b'CIQF', clean_quant, MODELS_DIR / "clean_model_int4.bin")

    print("\n" + "=" * 60)
    print("  Model Export Summary")
    print("=" * 60)
    for f in MODELS_DIR.iterdir():
        size_kb = f.stat().st_size / 1024
        print(f"  {f.name}: {size_kb:.1f} KB")
    print("\n  All models exported successfully!")


if __name__ == "__main__":
    main()
