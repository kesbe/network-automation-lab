FROM quay.io/ansible/awx-ee:24.6.1@sha256:89593d2a0268acacdbd1c075d8810ab50d961cf7769e36de19219bb6cb4efcc1

USER root

RUN ansible-galaxy collection install \
      "netbox.netbox:==3.19.1" \
      -p /usr/share/ansible/collections

ENV ANSIBLE_TRANSFORM_INVALID_GROUP_CHARS=silently

USER 1000
