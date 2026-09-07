FROM quay.io/ansible/awx-ee:24.6.1@sha256:89593d2a0268acacdbd1c075d8810ab50d961cf7769e36de19219bb6cb4efcc1

USER root

COPY execution-environments/ticketing-runtime-ee/requirements.txt /tmp/ticketing-runtime-requirements.txt

RUN python3 -m pip install \
      --no-cache-dir \
      --only-binary=:all: \
      -r /tmp/ticketing-runtime-requirements.txt \
    && python3 -c "import confluent_kafka; assert confluent_kafka.__version__ == '2.15.0'" \
    && python3 -c "import psycopg2; assert psycopg2.__version__.startswith('2.9.12')"

RUN mkdir -p /opt/network-compliance-ticketing/scripts

COPY scripts/ticketing_runtime_common.py /opt/network-compliance-ticketing/scripts/ticketing_runtime_common.py
COPY scripts/ticketing_lifecycle_publisher.py /opt/network-compliance-ticketing/scripts/ticketing_lifecycle_publisher.py
COPY scripts/zammad_ticketing_adapter.py /opt/network-compliance-ticketing/scripts/zammad_ticketing_adapter.py

RUN chmod 0644 \
      /opt/network-compliance-ticketing/scripts/ticketing_runtime_common.py \
      /opt/network-compliance-ticketing/scripts/ticketing_lifecycle_publisher.py \
      /opt/network-compliance-ticketing/scripts/zammad_ticketing_adapter.py

WORKDIR /opt/network-compliance-ticketing

ENV PYTHONPATH=/opt/network-compliance-ticketing

RUN python3 -m py_compile \
      scripts/ticketing_runtime_common.py \
      scripts/ticketing_lifecycle_publisher.py \
      scripts/zammad_ticketing_adapter.py \
    && python3 -c "import scripts.ticketing_runtime_common" \
    && python3 -c "import scripts.ticketing_lifecycle_publisher" \
    && python3 -c "import scripts.zammad_ticketing_adapter"

USER 1000
