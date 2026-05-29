"""data_utils.py 单元测试"""
import os
import sys
import numpy as np
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "Model_Train_Script"))

from data_utils import (
    generate_boundary_samples,
    generate_boundary_samples_clean,
    mixup_augmentation,
    add_outlier_samples,
)


class TestBoundarySamples:
    def test_security_boundary_shape(self):
        samples, labels = generate_boundary_samples(n_per_class=50)
        assert samples.shape[1] == 32
        assert len(labels) == len(samples)
        assert all(0 <= l <= 3 for l in labels)

    def test_clean_boundary_shape(self):
        samples, labels = generate_boundary_samples_clean(n_per_class=50)
        assert samples.shape[1] == 18
        assert len(labels) == len(samples)
        assert all(0 <= l <= 4 for l in labels)

    def test_values_in_range(self):
        samples, _ = generate_boundary_samples(n_per_class=50)
        assert np.all(samples >= 0)
        assert np.all(samples <= 1)


class TestMixup:
    def test_mixup_shape(self):
        data = np.random.rand(100, 32).astype(np.float32)
        labels = np.random.randint(0, 4, 100)
        mixed_f, mixed_l = mixup_augmentation(data, labels, n_samples=50)
        assert mixed_f.shape == (50, 32)
        assert len(mixed_l) == 50

    def test_mixup_values_in_range(self):
        data = np.random.rand(200, 18).astype(np.float32)
        labels = np.random.randint(0, 5, 200)
        mixed_f, _ = mixup_augmentation(data, labels, n_samples=100)
        assert np.all(mixed_f >= 0)
        assert np.all(mixed_f <= 1)


class TestOutlierSamples:
    def test_outlier_count(self):
        data = np.random.rand(1000, 32).astype(np.float32)
        labels = np.random.randint(0, 4, 1000)
        aug_f, aug_l = add_outlier_samples(data, labels, pct=0.02)
        # 应该增加了约 2% 的样本
        assert len(aug_f) > len(data)
        assert len(aug_l) == len(aug_f)

    def test_outlier_values_in_range(self):
        data = np.random.rand(500, 18).astype(np.float32)
        labels = np.random.randint(0, 5, 500)
        aug_f, _ = add_outlier_samples(data, labels, pct=0.05)
        assert np.all(aug_f >= 0)
        assert np.all(aug_f <= 1)
