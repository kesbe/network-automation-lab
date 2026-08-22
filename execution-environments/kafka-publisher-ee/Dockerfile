FROM quay.io/ansible/awx-ee:24.6.1@sha256:89593d2a0268acacdbd1c075d8810ab50d961cf7769e36de19219bb6cb4efcc1

USER root

COPY requirements.txt /tmp/kafka-publisher-requirements.txt

RUN python3 -m pip install \
      --no-cache-dir \
      --only-binary=:all: \
      -r /tmp/kafka-publisher-requirements.txt \
    && python3 -c "import confluent_kafka; assert confluent_kafka.__version__ == '2.15.0'"

USER 1000
