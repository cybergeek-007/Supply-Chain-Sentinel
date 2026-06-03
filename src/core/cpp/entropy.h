#ifndef SENTINEL_ENTROPY_H
#define SENTINEL_ENTROPY_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace sentinel {

class EntropyCalculator {
public:
    static double calculate(const uint8_t* data, size_t length);

    static std::vector<double> calculate_windowed(
        const uint8_t* data,
        size_t length,
        size_t window_size = 1024
    );

    static std::vector<uint8_t> entropy_heatmap(
        const uint8_t* data,
        size_t length,
        size_t window_size = 256
    );
};

}  // namespace sentinel

#endif  // SENTINEL_ENTROPY_H

