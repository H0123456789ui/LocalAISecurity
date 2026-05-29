/**
 * @file nn_ops.h
 * @brief 双AI引擎共享算子库 — INT4反量化 + 神经网络推理原语
 * 消除 security_ai_engine 和 clean_ai_engine 之间的 ~200 行重复代码
 */

#pragma once

#include <vector>
#include <cstdint>
#include <iterator>
#include <algorithm>
#include <cmath>

namespace AINN {

// ============================================================
// INT4反量化
// ============================================================
struct QuantizedLayer {
    std::vector<uint8_t> quant_weights;
    std::vector<float> scales;
    std::vector<float> zero_points;
    std::vector<int> original_shape;
    int group_size = 16;
};

inline std::vector<float> dequantize(const QuantizedLayer& layer) {
    int total_elements = 1;
    for (auto s : layer.original_shape) total_elements *= s;

    std::vector<float> result(total_elements, 0.0f);

    int group_size = layer.group_size;
    int num_groups = static_cast<int>(layer.scales.size());
    if (num_groups == 0 || layer.quant_weights.empty()) return result;

    int packed_bytes = static_cast<int>(layer.quant_weights.size());
    int required_bytes = (total_elements + 1) / 2;
    if (packed_bytes < required_bytes) return result;

    int idx = 0;
    for (int g = 0; g < num_groups && idx < total_elements; g++) {
        for (int j = 0; j < group_size && idx < total_elements; j++, idx++) {
            int byte_idx = idx / 2;
            if (byte_idx >= packed_bytes) return result;

            bool is_high = (idx % 2 == 1);
            uint8_t packed = layer.quant_weights[byte_idx];
            uint8_t qval = is_high ? (packed >> 4) : (packed & 0x0F);

            float scale = (g < num_groups) ? layer.scales[g] : 1.0f;
            float zp = (g < static_cast<int>(layer.zero_points.size()))
                           ? layer.zero_points[g] : 0.0f;
            result[idx] = static_cast<float>(qval) * scale + zp;
        }
    }
    return result;
}

// ============================================================
// Conv1d (same-padding, stride=1)
// ============================================================
inline std::vector<float> conv1d(
    const std::vector<float>& input,
    const std::vector<float>& weight,
    const std::vector<float>& bias,
    int in_channels, int out_channels, int kernel_size)
{
    int input_len = static_cast<int>(input.size()) / in_channels;
    int output_len = input_len;
    std::vector<float> output(out_channels * output_len, 0.0f);

    for (int oc = 0; oc < out_channels; oc++) {
        for (int i = 0; i < output_len; i++) {
            float sum = bias[oc];
            for (int ic = 0; ic < in_channels; ic++) {
                for (int k = 0; k < kernel_size; k++) {
                    int input_idx = i + k - kernel_size / 2;
                    if (input_idx >= 0 && input_idx < input_len) {
                        int w_idx = oc * in_channels * kernel_size + ic * kernel_size + k;
                        sum += input[ic * input_len + input_idx] * weight[w_idx];
                    }
                }
            }
            output[oc * output_len + i] = sum;
        }
    }
    return output;
}

// ============================================================
// BatchNorm1d
// ============================================================
inline std::vector<float> batch_norm(
    const std::vector<float>& input,
    const std::vector<float>& gamma,
    const std::vector<float>& beta,
    const std::vector<float>& mean,
    const std::vector<float>& var)
{
    int channels = static_cast<int>(gamma.size());
    int spatial = static_cast<int>(input.size()) / channels;
    std::vector<float> output(input.size());
    float eps = 1e-5f;

    for (int c = 0; c < channels; c++) {
        float scale = gamma[c] / std::sqrt(var[c] + eps);
        float offset = beta[c] - mean[c] * scale;
        for (int s = 0; s < spatial; s++) {
            output[c * spatial + s] = input[c * spatial + s] * scale + offset;
        }
    }
    return output;
}

// ============================================================
// MaxPool1d
// ============================================================
inline std::vector<float> max_pool1d(
    const std::vector<float>& input, int channels, int kernel_size)
{
    int spatial = static_cast<int>(input.size()) / channels;
    int output_spatial = spatial / kernel_size;
    std::vector<float> output(channels * output_spatial);

    for (int c = 0; c < channels; c++) {
        int c_offset = c * spatial;
        int out_offset = c * output_spatial;
        for (int i = 0; i < output_spatial; i++) {
            float max_val = -1e30f;
            for (int k = 0; k < kernel_size; k++) {
                float val = input[c_offset + i * kernel_size + k];
                if (val > max_val) max_val = val;
            }
            output[out_offset + i] = max_val;
        }
    }
    return output;
}

// ============================================================
// Linear (全连接层)
// ============================================================
inline std::vector<float> linear(
    const std::vector<float>& input,
    const std::vector<float>& weight,
    const std::vector<float>& bias)
{
    int output_dim = static_cast<int>(bias.size());
    int input_dim = static_cast<int>(input.size());
    std::vector<float> output(output_dim);

    for (int o = 0; o < output_dim; o++) {
        float sum = bias[o];
        for (int i = 0; i < input_dim; i++) {
            sum += input[i] * weight[o * input_dim + i];
        }
        output[o] = sum;
    }
    return output;
}

// ============================================================
// ReLU
// ============================================================
inline std::vector<float> relu(const std::vector<float>& x) {
    std::vector<float> result(x.size());
    for (size_t i = 0; i < x.size(); i++) {
        result[i] = std::max(0.0f, x[i]);
    }
    return result;
}

// ============================================================
// Softmax
// ============================================================
inline std::vector<float> softmax(const std::vector<float>& x) {
    float max_val = *std::max_element(x.begin(), x.end());
    std::vector<float> result(x.size());
    float sum = 0.0f;
    for (size_t i = 0; i < x.size(); i++) {
        result[i] = std::exp(x[i] - max_val);
        sum += result[i];
    }
    if (sum > 0.0f) {
        for (size_t i = 0; i < x.size(); i++) {
            result[i] /= sum;
        }
    }
    return result;
}

} // namespace AINN
