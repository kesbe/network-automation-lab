ARG BASE_IMAGE=docker.io/library/python:3.12-alpine@sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31

FROM ${BASE_IMAGE}

RUN apk update \
    && apk add \
       --upgrade \
       --no-cache \
       'libssl3=3.5.8-r0' \
       'libcrypto3=3.5.8-r0' \
    && rm -rf /var/cache/apk/*


ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY containers/compliance-exporter/requirements.txt \
     /tmp/compliance-exporter-requirements.txt

RUN python3 -m pip install \
      --no-cache-dir \
      --disable-pip-version-check \
      -r /tmp/compliance-exporter-requirements.txt \
    && rm -f \
      /tmp/compliance-exporter-requirements.txt

COPY scripts/compliance_exporter.py \
     /app/compliance_exporter.py

RUN chmod 0555 \
      /app/compliance_exporter.py

USER 65532:65532

EXPOSE 9808

ENTRYPOINT ["python3", "/app/compliance_exporter.py"]
