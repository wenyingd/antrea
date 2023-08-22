# Copyright 2022 Antrea Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG BUILD_TAG
FROM nsx-ujo-docker-local.artifactory.eng.vmware.com/interworking/ubuntu:22.04 as cni-binaries

ARG CNI_BINARIES_VERSION
ARG DOWNLOAD_CNI_BINARIES=false

COPY cni-plugins-*.tgz /tmp

RUN echo "deb http://build-artifactory.eng.vmware.com/ubuntu-remote jammy main restricted universe" > /etc/apt/sources.list && \
    echo "deb http://build-artifactory.eng.vmware.com/ubuntu-remote jammy-security main restricted" >> /etc/apt/sources.list && \
    echo "deb http://build-artifactory.eng.vmware.com/ubuntu-remote jammy-updates main restricted" >> /etc/apt/sources.list

RUN apt-get update && \
    apt-get install -y --no-install-recommends wget ca-certificates

# Leading dot is required for the tar command below
ENV CNI_PLUGINS="./host-local ./loopback ./portmap ./bandwidth"

# Download containernetworking plugin binaries for the correct architecture
RUN set -eux; \
    mkdir -p /opt/cni/bin; \
    if ${DOWNLOAD_CNI_BINARIES}; then \
        dpkgArch="$(dpkg --print-architecture)"; \
        case "${dpkgArch##*-}" in \
            amd64) pluginsArch='amd64' ;; \
        armhf) pluginsArch='arm' ;; \
        arm64) pluginsArch='arm64' ;; \
            *) pluginsArch=''; echo >&2; echo >&2 "unsupported architecture '$dpkgArch'"; echo >&2 ; exit 1 ;; \
        esac; \
        wget -q -O - https://github.com/containernetworking/plugins/releases/download/$CNI_BINARIES_VERSION/cni-plugins-linux-${pluginsArch}-$CNI_BINARIES_VERSION.tgz | tar xz -C /opt/cni/bin $CNI_PLUGINS; \
    else \
        tar -zxvf /tmp/cni-plugins-*.tgz -C /opt/cni/bin $CNI_PLUGINS; \
    fi

FROM antrea/openvswitch:${BUILD_TAG}

ARG SURICATA_VERSION

LABEL maintainer="Antrea <projectantrea-dev@googlegroups.com>"
LABEL description="An Ubuntu based Docker base image for Antrea."

RUN echo "deb http://build-artifactory.eng.vmware.com/ubuntu-remote jammy main restricted universe" > /etc/apt/sources.list && \
    echo "deb http://build-artifactory.eng.vmware.com/ubuntu-remote jammy-security main restricted" >> /etc/apt/sources.list && \
    echo "deb http://build-artifactory.eng.vmware.com/ubuntu-remote jammy-updates main restricted" >> /etc/apt/sources.list

USER root

COPY iptables-wrapper-installer.sh /iptables-wrapper-installer.sh

RUN apt-get update && apt-get install -y --no-install-recommends ipset jq iproute2 inotify-tools gpg-agent software-properties-common && \
    # ethtool is for commercial release Antrea to toggle Geneve checksum offload.
    apt-get install -y --no-install-recommends ethtool && \
    add-apt-repository ppa:oisf/suricata-${SURICATA_VERSION} && apt-get update && apt-get install -y suricata && \
    apt-get remove -y gpg-agent software-properties-common && apt-get autoremove -y && rm -rf /var/cache/apt/* /var/lib/apt/lists/* && \
    /iptables-wrapper-installer.sh

COPY --from=cni-binaries /opt/cni/bin /opt/cni/bin
