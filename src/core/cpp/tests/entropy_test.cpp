#include <gtest/gtest.h>

#include "../entropy.h"

using namespace sentinel;

TEST(EntropyCalculator, ZeroEntropyUniformData) {
    uint8_t data[100];
    for (int index = 0; index < 100; ++index) {
        data[index] = 0x00;
    }
    const double entropy = EntropyCalculator::calculate(data, 100);
    EXPECT_DOUBLE_EQ(entropy, 0.0);
}

TEST(EntropyCalculator, MaxEntropyUniformDistribution) {
    uint8_t data[256];
    for (int index = 0; index < 256; ++index) {
        data[index] = static_cast<uint8_t>(index);
    }
    const double entropy = EntropyCalculator::calculate(data, 256);
    EXPECT_DOUBLE_EQ(entropy, 8.0);
}

TEST(EntropyCalculator, WindowedEntropy) {
    uint8_t data[200];
    for (int index = 0; index < 100; ++index) {
        data[index] = 'A';
    }
    for (int index = 100; index < 200; ++index) {
        data[index] = 'B';
    }

    const auto scores = EntropyCalculator::calculate_windowed(data, 200, 100);
    EXPECT_EQ(scores.size(), 2);
    EXPECT_DOUBLE_EQ(scores[0], 0.0);
    EXPECT_DOUBLE_EQ(scores[1], 0.0);
}

TEST(EntropyCalculator, HeatmapGeneration) {
    uint8_t data[512];
    for (int index = 0; index < 512; ++index) {
        data[index] = static_cast<uint8_t>((index / 256) * 255);
    }

    const auto heatmap = EntropyCalculator::entropy_heatmap(data, 512, 256);
    EXPECT_EQ(heatmap.size(), 2);
    EXPECT_TRUE(heatmap[0] <= 255);
    EXPECT_TRUE(heatmap[1] <= 255);
}

