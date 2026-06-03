FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    python3.10 \
    python3.10-dev \
    python3.10-venv \
    build-essential \
    clang \
    llvm-14 \
    libelf-dev \
    bpfcc-tools \
    libbpfcc-dev \
    python3-bpfcc \
    pybind11-dev \
    linux-headers-generic \
    docker.io \
    curl \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN python3.10 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p build && cd build && \
    cmake .. -DSCS_BUILD_CPP_CORE=ON -DSCS_BUILD_CPP_TESTS=OFF && \
    cmake --build . -j"$(nproc)" && \
    cp sentinel_core* ../src/ || true

RUN useradd -m -u 1000 sentinel && chown -R sentinel:sentinel /app
USER sentinel

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:8000/api/v1/health || exit 1

CMD ["uvicorn", "src.api.app:app", "--host", "0.0.0.0", "--port", "8000"]

