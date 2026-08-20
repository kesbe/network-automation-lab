FROM quay.io/ansible/awx-ee:24.6.1@sha256:89593d2a0268acacdbd1c075d8810ab50d961cf7769e36de19219bb6cb4efcc1

USER root

RUN ansible-galaxy collection install \
      "community.postgresql:==4.2.0" \
      -p /usr/share/ansible/collections

RUN python3 -m pip install \
      --no-cache-dir \
      "psycopg2-binary==2.9.12"

USER 1000
