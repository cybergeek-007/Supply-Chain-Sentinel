#include "entropy.h"

#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace sentinel {

double EntropyCalculator::calculate(const uint8_t* data, size_t length) {
    if (data == nullptr && length > 0) {
        throw std::invalid_argument("data pointer cannot be null when length > 0");
    }
    if (length == 0) {
        return 0.0;
    }

    unsigned int frequencies[256] = {0};
    for (size_t index = 0; index < length; ++index) {
        frequencies[data[index]]++;
    }

    double entropy = 0.0;
    for (unsigned int frequency : frequencies) {
        if (frequency == 0) {
            continue;
        }
        const double probability = static_cast<double>(frequency) / static_cast<double>(length);
        entropy -= probability * std::log2(probability);
    }

    return entropy;
}

std::vector<double> EntropyCalculator::calculate_windowed(
    const uint8_t* data,
    size_t length,
    size_t window_size
) {
    if (window_size == 0) {
        throw std::invalid_argument("window_size must be greater than zero");
    }

    std::vector<double> scores;
    if (length == 0) {
        scores.push_back(0.0);
        return scores;
    }
    if (length < window_size) {
        scores.push_back(calculate(data, length));
        return scores;
    }

    for (size_t offset = 0; offset < length; offset += window_size) {
        const size_t chunk_size = std::min(window_size, length - offset);
        scores.push_back(calculate(data + offset, chunk_size));
    }

    return scores;
}

std::vector<uint8_t> EntropyCalculator::entropy_heatmap(
    const uint8_t* data,
    size_t length,
    size_t window_size
) {
    if (window_size == 0) {
        throw std::invalid_argument("window_size must be greater than zero");
    }

    std::vector<uint8_t> heatmap;
    if (length == 0) {
        heatmap.push_back(0);
        return heatmap;
    }

    for (size_t offset = 0; offset < length; offset += window_size) {
        const size_t chunk_size = std::min(window_size, length - offset);
        const double entropy = calculate(data + offset, chunk_size);
        const auto intensity = static_cast<uint8_t>(std::min(255.0, (entropy / 8.0) * 255.0));
        heatmap.push_back(intensity);
    }

    return heatmap;
}

}  // namespace sentinel

