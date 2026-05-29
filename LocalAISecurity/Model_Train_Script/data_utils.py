"""
Improved training data utilities — realistic distributions, class-boundary
samples, mixup augmentation, and real/synthetic data blending.
"""

import numpy as np
from pathlib import Path


DATASET_DIR = Path(__file__).parent / "dataset"


def generate_boundary_samples(n_per_class=200, noise_std=0.03):
    """
    Generate hard samples near the decision boundary between each pair of
    adjacent classes. These force the model to learn sharper boundaries.
    """
    n_classes = 4
    samples = []
    labels = []

    for c1 in range(n_classes - 1):
        c2 = c1 + 1
        for _ in range(n_per_class):
            alpha = np.random.uniform(0.4, 0.6)
            f1 = _get_class_centroid(c1, 32) + np.random.normal(0, 0.05, 32)
            f2 = _get_class_centroid(c2, 32) + np.random.normal(0, 0.05, 32)
            f = alpha * f1 + (1 - alpha) * f2 + np.random.normal(0, noise_std, 32)
            f = np.clip(f, 0, 1)
            label = c1 if alpha > 0.5 else c2
            samples.append(f.astype(np.float32))
            labels.append(label)

        for _ in range(n_per_class // 2):
            alpha = np.random.uniform(0.2, 0.4)
            f1 = _get_class_centroid(c1, 32)
            f2 = _get_class_centroid(c2, 32) + np.random.normal(0, 0.1, 32)
            f = alpha * f1 + (1 - alpha) * f2 + np.random.normal(0, noise_std, 32)
            f = np.clip(f, 0, 1)
            samples.append(f.astype(np.float32))
            labels.append(c2)

    return np.array(samples), np.array(labels)


def generate_boundary_samples_clean(n_per_class=200, noise_std=0.03):
    """Boundary samples for the 5-class clean model."""
    n_classes = 5
    samples = []
    labels = []

    for c1 in range(n_classes - 1):
        c2 = c1 + 1
        for _ in range(n_per_class):
            alpha = np.random.uniform(0.4, 0.6)
            f1 = _get_clean_centroid(c1) + np.random.normal(0, 0.05, 18)
            f2 = _get_clean_centroid(c2) + np.random.normal(0, 0.05, 18)
            f = alpha * f1 + (1 - alpha) * f2 + np.random.normal(0, noise_std, 18)
            f = np.clip(f, 0, 1)
            label = c1 if alpha > 0.5 else c2
            samples.append(f.astype(np.float32))
            labels.append(label)

    return np.array(samples), np.array(labels)


def _get_class_centroid(cls_id, dim):
    """Approximate centroid for each security class."""
    f = np.zeros(dim, dtype=np.float32)
    if cls_id == 0:  # normal
        f[0:4] = [0.05, 0.08, 0.1, 0.1]
        f[14:20] = [0.85, 0.8, 0.7, 0.9, 0.9, 0.8]
        f[28:32] = [0.05, 0.02, 0.02, 0.02]
    elif cls_id == 1:  # PUA
        f[0:4] = [0.35, 0.4, 0.35, 0.35]
        f[14:20] = [0.5, 0.5, 0.5, 0.5, 0.5, 0.5]
        f[28:32] = [0.5, 0.4, 0.3, 0.3]
    elif cls_id == 2:  # trojan
        f[0:4] = [0.55, 0.5, 0.5, 0.45]
        f[14:20] = [0.3, 0.3, 0.3, 0.3, 0.3, 0.3]
        f[28:32] = [0.0, 0.0, 0.4, 0.4]
    elif cls_id == 3:  # ransomware
        f[0:4] = [0.85, 0.75, 0.7, 0.6]
        f[5:8] = [0.8, 0.7, 0.7]
        f[14:20] = [0.2, 0.2, 0.2, 0.2, 0.2, 0.2]
        f[28:32] = [0.0, 0.0, 0.0, 0.8]
    return f


def _get_clean_centroid(cls_id):
    """Approximate centroid for each clean class."""
    f = np.zeros(18, dtype=np.float32)
    if cls_id == 0:  # system core
        f[0:6] = [0.15, 0.9, 0.12, 0.08, 0.08, 0.02]
        f[7:10] = [0.9, 0.1, 0.3]
        f[11:14] = [0.9, 0.9, 0.3]
        f[14:18] = [0.5, 0.6, 0.7, 0.9]
    elif cls_id == 1:  # software cache
        f[0:6] = [0.5, 0.3, 0.65, 0.3, 0.7, 0.3]
        f[7:10] = [0.5, 0.25, 0.4]
        f[11:14] = [0.5, 0.5, 0.4]
        f[14:18] = [0.3, 0.3, 0.3, 0.5]
    elif cls_id == 2:  # safe cleanable
        f[0:6] = [0.7, 0.05, 0.15, 0.4, 0.3, 0.85]
        f[7:10] = [0.4, 0.9, 0.9]
        f[11:14] = [0.15, 0.05, 0.25]
        f[14:18] = [0.3, 0.3, 0.15, 0.15]
    elif cls_id == 3:  # large redundant
        f[0:6] = [0.8, 0.15, 0.3, 0.4, 0.7, 0.3]
        f[6] = 0.85
        f[7:10] = [0.5, 0.9, 0.9]
        f[11:14] = [0.3, 0.15, 0.8]
        f[14:18] = [0.3, 0.3, 0.15, 0.3]
    elif cls_id == 4:  # user important
        f[0:6] = [0.4, 0.15, 0.15, 0.9, 0.4, 0.15]
        f[7:10] = [0.4, 0.25, 0.25]
        f[11:14] = [0.7, 0.15, 0.25]
        f[14:18] = [0.15, 0.3, 0.15, 0.7]
    return f


def mixup_augmentation(features, labels, alpha=0.2, n_samples=2000):
    """
    Mixup augmentation: creates new samples by convex combination of pairs.
    Improves model robustness and calibration.
    """
    n = len(features)
    mixed_f = []
    mixed_l = []

    for _ in range(n_samples):
        i, j = np.random.randint(0, n, 2)
        lam = np.random.beta(alpha, alpha)
        f_mix = lam * features[i] + (1 - lam) * features[j]
        mixed_f.append(f_mix.astype(np.float32))
        mixed_l.append(labels[i] if lam > 0.5 else labels[j])

    return np.array(mixed_f), np.array(mixed_l)


def load_real_data(prefix="security"):
    """Load previously collected real data if available."""
    feat_path = DATASET_DIR / f"{prefix}_features.npy"
    label_path = DATASET_DIR / f"{prefix}_labels.npy"
    if feat_path.exists() and label_path.exists():
        features = np.load(feat_path)
        labels = np.load(label_path)
        print(f"  Loaded {len(features)} real {prefix} samples from {DATASET_DIR}")
        return features, labels
    return None, None


def blend_real_and_synthetic(real_f, real_l, synthetic_f, synthetic_l, real_weight=0.5):
    """
    Blend real collected data with synthetic data.
    If real data is available, it gets `real_weight` proportion of the final dataset.
    """
    if real_f is not None and len(real_f) > 0:
        n_real = min(len(real_f), int(len(synthetic_f) * real_weight))
        idx = np.random.choice(len(real_f), n_real, replace=False)
        blended_f = np.vstack([synthetic_f, real_f[idx]])
        blended_l = np.concatenate([synthetic_l, real_l[idx]])
        print(f"  Blended: {len(synthetic_f)} synth + {n_real} real = {len(blended_f)} total")
        return blended_f, blended_l
    return synthetic_f, synthetic_l


def add_outlier_samples(features, labels, pct=0.02):
    """Add a small percentage of outlier/extreme samples for robustness."""
    n_out = int(len(features) * pct)
    outliers_f = np.random.uniform(0, 1, (n_out, features.shape[1])).astype(np.float32)
    outliers_l = np.random.randint(0, max(labels) + 1, n_out).astype(np.int64)
    return (np.vstack([features, outliers_f]),
            np.concatenate([labels, outliers_l]))
