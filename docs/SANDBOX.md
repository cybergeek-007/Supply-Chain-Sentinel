# Isolated research environment and threat model

The supported CLI does **not** execute packages. `--dynamic` fails explicitly. This document describes the separate research benchmark used to read malicious source in isolation. Fake-network detonation and production dynamic scanning are deliberately not implemented.

## Boundaries and assumptions

Assets: host files/credentials, host network, scanner policy, public-record integrity and machine availability. Adversary: a package controls its archive paths, source strings, manifests and payloads. It may exploit parsers or try to exhaust memory/CPU. A package name or public reputation is not a trust exemption.

Docker shares the host kernel. Rootless Docker and dropped capabilities reduce risk but do not prove resistance to kernel/runtime exploits. For hostile detonation beyond static inspection, use a disposable VM with a patched runtime and no shared folders/clipboard, preferably gVisor or a microVM inside it. The present checks are functional isolation probes, not a penetration test or proof of sandbox security.

The acquisition container runs trusted Python HTTP code as UID 65532 with dropped capabilities, no-new-privileges and resource limits. It has outbound networking solely for public npm metadata/tarballs and GitHub dataset metadata/encrypted ZIPs. No npm install, JS evaluation, shell hook or sample execution occurs. Allowlisted HTTPS hosts/redirects are enforced. It stores samples only in container storage; no host bind mounts, Docker socket, SSH agents or real credentials are exposed. This acquisition network mode is never used for analysis.

The acquisition container is stopped and committed to a local image. Analysis runs from that frozen image with **network none**, read-only root, non-root UID, all capabilities dropped, no-new-privileges, 1 GiB memory/swap cap, one CPU quota, 64 PIDs and a 64 MiB noexec/nosuid temporary filesystem. No mounts expose host paths. ZIP decryption and source parsing occur only here; source code is never executed. Only JSON result metadata leaves the container; sample bytes and source excerpts are not exported or committed to this repository.

The worker rejects oversized ZIPs, path traversal and archive resource violations. A malformed/unreadable sample is counted as an error, not a missed or detected source sample. The runtime also performs bounded archive reading without extracting package paths. A timeout/error is never a clean verdict.

## Environment actually used

- Host Python 3.14.8; validation image Python 3.11 slim pinned in `benchmarks/Dockerfile` by digest.
- Rootless Docker Engine **28.5.2**, RootlessKit/vpnkit from the official Docker static bundles, downloaded to `/tmp/sentinel-tools`; daemon data/runtime under `/tmp/sentinel-docker`.
- Official downloads: `https://download.docker.com/linux/static/stable/x86_64/docker-28.5.2.tgz` and `docker-rootless-extras-28.5.2.tgz`. This records the tested version, not an assertion that it is the newest or vulnerability-free.
- Initial sudo check required a password. User subsequently installed host Docker 28.5.2+dfsg4, but this session could not access `/var/run/docker.sock`; the temporary rootless daemon was used instead.
- No root password was received or stored. No eBPF/Qt/YARA/native toolchain was installed; those features were removed from the supported runtime.
- Project tools installed locally from `requirements-dev.txt`: pytest, pytest-cov, Ruff, mypy, build and jsonschema at explicit versions. The existing virtualenv may retain old dependencies; a fresh runtime install needs none of them.

Harmless probe results inside the analysis-style container:

| Probe | Observed |
| --- | --- |
| UID | 65532 |
| Interfaces | loopback only |
| Connect to 1.1.1.1:443 | failed, network unreachable (errno 101) |
| Write root filesystem | failed, read-only filesystem (errno 30) |
| Host home `/home/kali` | absent |
| Memory cgroup limit | 268435456 bytes (256 MiB probe) |
| PID limit | 64 |
| CPU quota | 50000 / 100000 (0.5 CPU probe) |

The larger benchmark uses 1 GiB/one CPU; enforcement must be checked rather than inferred from flags on a new host. Rootless Docker needs unprivileged user namespaces, subuid/subgid mappings, a supported networking helper and delegated cgroup v2. Do not disable seccomp, use privileged mode, add host networking to analysis, or fall back to a host process when prerequisites fail.

## Reproduction

Use a dedicated rootless Docker daemon. With the session daemon, set `DOCKER_HOST=unix:///tmp/sentinel-docker/run/docker.sock`. Build without networking:

After unpacking the official static bundles, the temporary daemon was started with:

```bash
mkdir -p /tmp/sentinel-docker/{run,data,exec}
env PATH="/tmp/sentinel-tools/docker-rootless-extras:/tmp/sentinel-tools/docker:$PATH" \
  XDG_RUNTIME_DIR=/tmp/sentinel-docker/run DOCKERD_ROOTLESS_ROOTLESSKIT_NET=vpnkit \
  /tmp/sentinel-tools/docker-rootless-extras/dockerd-rootless.sh \
  --host unix:///tmp/sentinel-docker/run/docker.sock --data-root /tmp/sentinel-docker/data \
  --exec-root /tmp/sentinel-docker/exec --storage-driver vfs --iptables=false --bridge=none
```

Recheck kernel/runtime/image security before reusing historical pinned versions. This daemon is independent of the user's installed system Docker service.

```bash
docker build --network none -f benchmarks/Dockerfile -t sentinel-benchmark:review .
docker run --name sentinel-corpus-acquire --network host --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges --memory 1g --memory-swap 1g \
  --cpus 1 --pids-limit 64 sentinel-benchmark:review fetch --frozen
docker commit sentinel-corpus-acquire sentinel-benchmark:corpus
docker run --rm --network none --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges --memory 1g --memory-swap 1g \
  --cpus 1 --pids-limit 64 --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  sentinel-benchmark:corpus evaluate > results.json
```

Here acquisition `--network host` means the already isolated rootless daemon's network namespace, not a rootful host namespace. Do not apply this recipe unchanged to a rootful production daemon. Keep acquisition separate from analysis. The dataset selection is pinned to a Git commit, fixed seed, exact sample paths and hashes in results. GitHub API limits or dataset structure changes can interrupt acquisition; do not silently accept a truncated tree or substitute missing samples.

## Deferred dynamic design

If later implemented, require a dedicated, tested runner rather than arbitrary shell commands in the developer process. Copy input through a bounded stream/OCI layer, use no host binds, run non-root with kernel/runtime isolation, trace only the analysis cgroup/process tree, bound traces/stdout, enforce wall-clock and cgroup limits, and remove disposable state on every outcome. A fake network must be a separate internal namespace with no default route, DNS and HTTP sinks that cannot proxy externally, and explicit egress verification. strace of executed paths is useful; eBPF is unnecessary for the first reliable runner. No such dynamic/egress/deception capability is claimed in this release.

## Cleanup of this research run

After sanitized results were saved, the two acquisition containers, all task-specific benchmark/corpus images and the dedicated daemon's build cache were removed. No live sample bytes are retained in the project. The official Python base image and temporary Docker binaries are separate from the discarded corpus. The user's system Docker service was not changed by this cleanup. Reproduction requires reacquisition through the isolated fetch step.
