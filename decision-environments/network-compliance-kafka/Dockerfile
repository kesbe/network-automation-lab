# Network Compliance Kafka Decision Environment
#
# Base image is pinned to the exact image digest proven during
# Kafka -> ansible.eda.kafka -> rule engine acceptance testing.

ARG BASE_IMAGE=quay.io/ansible/ansible-rulebook@sha256:d176608bf47927bb5ac89db0d381325c722774a9b53141c18f0533c03bfdae92
FROM ${BASE_IMAGE}

USER 0

COPY requirements.txt /tmp/network-compliance-de-requirements.txt

RUN /usr/bin/python3.12 -m pip install       --no-cache-dir       -r /tmp/network-compliance-de-requirements.txt  && /usr/bin/python3.12 -c       'import fastavro; assert fastavro.__version__ == "1.12.2"'

USER 1001

LABEL org.opencontainers.image.title="Network Compliance Kafka Decision Environment"
LABEL org.opencontainers.image.description="Pinned EDA runtime for Kafka-driven network compliance automation"
LABEL netauto.ansible-eda="2.13.0"
LABEL netauto.ansible-rulebook="1.3.1"
LABEL netauto.fastavro="1.12.2"
