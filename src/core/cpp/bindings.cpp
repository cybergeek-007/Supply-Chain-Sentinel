#include "entropy.h"

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <cstdint>
#include <string>
#include <vector>

namespace py = pybind11;
using namespace sentinel;

namespace {

std::vector<uint8_t> bytes_to_vector(const py::bytes& data) {
    const std::string raw = data;
    return std::vector<uint8_t>(raw.begin(), raw.end());
}

}  // namespace

PYBIND11_MODULE(sentinel_core, module) {
    module.doc() = "Supply Chain Sentinel C++ core engine";

    py::class_<EntropyCalculator>(module, "EntropyCalculator")
        .def_static(
            "calculate",
            [](const py::bytes& data) {
                const auto buffer = bytes_to_vector(data);
                return EntropyCalculator::calculate(buffer.data(), buffer.size());
            },
            "Calculate Shannon entropy of binary data"
        )
        .def_static(
            "calculate_windowed",
            [](const py::bytes& data, size_t window_size) {
                const auto buffer = bytes_to_vector(data);
                return EntropyCalculator::calculate_windowed(buffer.data(), buffer.size(), window_size);
            },
            "Calculate windowed entropy scores",
            py::arg("data"),
            py::arg("window_size") = 1024
        )
        .def_static(
            "entropy_heatmap",
            [](const py::bytes& data, size_t window_size) {
                const auto buffer = bytes_to_vector(data);
                return EntropyCalculator::entropy_heatmap(buffer.data(), buffer.size(), window_size);
            },
            "Generate entropy heatmap",
            py::arg("data"),
            py::arg("window_size") = 256
        );
}

