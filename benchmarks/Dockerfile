FROM python:3.11-slim@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535
COPY src/supply_chain_sentinel /opt/sentinel/supply_chain_sentinel
COPY benchmarks /opt/benchmarks
RUN mkdir /corpus && chown 65532:65532 /corpus
ENV PYTHONPATH=/opt/sentinel
ENV PYTHONDONTWRITEBYTECODE=1
USER 65532:65532
ENTRYPOINT ["python", "/opt/benchmarks/worker.py"]
