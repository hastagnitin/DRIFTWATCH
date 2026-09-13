FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY drift_engine/ drift_engine/
COPY driftwatch/ driftwatch/

RUN pip install --no-cache-dir --upgrade pip build && \
    python -m build --wheel --outdir /wheels

FROM python:3.12-slim AS runtime

RUN groupadd -g 10001 driftwatch && \
    useradd -u 10001 -g driftwatch -m -s /bin/bash driftwatch

WORKDIR /home/driftwatch/app

COPY --from=builder /wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && \
    rm -rf /tmp/*.whl

COPY --chown=driftwatch:driftwatch terraform/ terraform/
COPY --chown=driftwatch:driftwatch run.sh .
RUN chmod +x run.sh

USER driftwatch

ENTRYPOINT ["driftwatch"]
CMD ["scan"]