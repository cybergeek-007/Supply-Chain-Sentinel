# Third-party research data

Project code is MIT. Research data and samples retain their upstream terms.

- Datadog Security Labs, [Malicious Software Packages Dataset](https://github.com/DataDog/malicious-software-packages-dataset), Apache-2.0 dataset, commit `72c723be547033c558244520524b117c8d71663b`. This repository retains selected paths, URLs, hashes and derived measurements, not executable samples. Original package code within upstream samples can carry its original licenses. Dataset label/selection limitations are documented in the benchmark.
- [OSV](https://osv.dev/) aggregates upstream vulnerability records. The advisory evaluation retains selected public record summaries, IDs, timestamps and provenance URLs; consult each originating database for its terms.
- [GitHub Advisory Database](https://github.com/github/advisory-database) and [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) supply records available through OSV. Each cached result links the exact advisory; no ownership of upstream intelligence is claimed.
- The official Python Docker image used for research is pinned by digest in `benchmarks/Dockerfile`. Container image/runtime licenses and any vulnerabilities are independent of the project code license.
