#!/usr/bin/env bash

# Copyright 2019 Antrea Authors
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

# This is a very simple script that builds the Open vSwitch base image for Antrea and pushes it to
# the Antrea Dockerhub (https://hub.docker.com/u/antrea). The image is tagged with the OVS version.

set -eo pipefail

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

source $THIS_DIR/../build-utils.sh

_usage="Usage: $0 [--pull] [--push] [--platform <PLATFORM>] [--distro [ubuntu|ubi|windows]]
Build the antrea openvswitch image.
        --pull                  Always attempt to pull a newer version of the base images
        --push                  Push the built image to the registry
        --platform <PLATFORM>   Target platform for the image if server is multi-platform capable
        --distro <distro>       Target distribution. If distro is 'windows', platform should be empty. The script uses 'windows/amd64' automatically
        --no-cache              Do not use the local build cache nor the cached image from the registry
        --download-ovs          Download OVS source code tarball from internet. Default is false.
        --ipsec                 Build with IPsec support. Default is false.
        --rpm-repo-url <url>        URL of the RPM repository to use for Photon builds."

function print_usage {
    echoerr "$_usage"
}

PULL=false
PUSH=false
NO_CACHE=false
IPSEC=false
PLATFORM=""
DISTRO="ubuntu"
DOWNLOAD_OVS=false
SUPPORT_DISTROS=("ubuntu" "ubi" "debian" "photon" "windows")

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --push)
    PUSH=true
    shift
    ;;
    --pull)
    PULL=true
    shift
    ;;
    --platform)
    PLATFORM="$2"
    shift 2
    ;;
    --distro)
    DISTRO="$2"
    shift 2
    ;;
    --no-cache)
    NO_CACHE=true
    shift
    ;;
    --download-ovs)
    DOWNLOAD_OVS=true
    shift
    ;;
    --ipsec)
    IPSEC=true
    shift
    ;;
    --rpm-repo-url)
    RPM_REPO_URL="$2"
    shift 2
    ;;
    -h|--help)
    print_usage
    exit 0
    ;;
    *)    # unknown option
    echoerr "Unknown option $1"
    exit 1
    ;;
esac
done

# When --push is provided, we assume that we want to use --cache-to, which will
# push the "cache image" to the registry. This functionality is not supported
# with the default docker driver.
# See https://docs.docker.com/build/cache/backends/registry/
if $PUSH && [ "$DISTRO" != "windows" ] && ! check_docker_build_driver "docker-container"; then
    echoerr "--push requires the docker-container build driver"
    exit 1
fi

if [ "$PLATFORM" != "" ] && $PUSH; then
    echoerr "Cannot use --platform with --push"
    exit 1
fi

if [ "$DISTRO" != "ubuntu" ] && [ "$DISTRO" != "ubi" ] && [ "$DISTRO" != "windows" ]; then
    echoerr "Invalid distribution $DISTRO"
    exit 1
fi

OVS_VERSION_FILE="../deps/ovs-version"
if [ "$DISTRO" == "windows" ]; then
  OVS_VERSION_FILE="../deps/ovs-version-windows"
fi

PLATFORM_ARG=""
if [ "$PLATFORM" != "" ]; then
    PLATFORM_ARG="--platform $PLATFORM"
fi

DISTRO_VALID=false
for dist in "${SUPPORT_DISTROS[@]}"; do
    if [ "$DISTRO" == "$dist" ]; then
        DISTRO_VALID=true
        break
    fi
done

if ! $DISTRO_VALID; then
    echoerr "Invalid distribution $DISTRO"
    exit 1
fi

pushd $THIS_DIR > /dev/null

OVS_VERSION=$(head -n 1 ${OVS_VERSION_FILE})

BUILD_TAG=$(../build-tag.sh)
if [ "$IPSEC" == "true" ]; then
    BUILD_TAG="${BUILD_TAG}-ipsec"
fi

if $DOWNLOAD_OVS; then
    curl -LO https://www.openvswitch.org/releases/openvswitch-$OVS_VERSION.tar.gz
elif [ ! -f openvswitch-$OVS_VERSION.tar.gz ]; then
    echoerr "openvswitch-$OVS_VERSION.tar.gz not found. Use --download-ovs to download it."
    exit 1
fi

if $PULL; then
    if [ "$DISTRO" == "ubuntu" ]; then
        if [[ ${DOCKER_REGISTRY} == "" ]]; then
            docker pull $PLATFORM_ARG ubuntu:22.04
        else
            docker pull ${DOCKER_REGISTRY}/antrea/ubuntu:22.04
            docker tag ${DOCKER_REGISTRY}/antrea/ubuntu:22.04 ubuntu:22.04
        fi
    elif [ "$DISTRO" == "ubi" ]; then
        docker pull $PLATFORM_ARG quay.io/centos/centos:stream9
        docker pull $PLATFORM_ARG registry.access.redhat.com/ubi9
    elif [ "$DISTRO" == "windows" ]; then
        docker pull --platform linux/amd64 ubuntu:22.04
    fi
fi

function docker_build_and_push() {
    local image="$1"
    local dockerfile="$2"
    local build_args="--build-arg OVS_VERSION=$OVS_VERSION"
    local cache_args=""
    if $PUSH; then
        cache_args="$cache_args --cache-to type=registry,ref=$image-cache:$BUILD_TAG,mode=max"
    fi
    if $NO_CACHE; then
        cache_args="$cache_args --no-cache"
    else
        cache_args="$cache_args --cache-from type=registry,ref=$image-cache:$BUILD_TAG,mode=max"
    fi
    docker buildx build $PLATFORM_ARG -o type=docker -t $image:$BUILD_TAG $cache_args $build_args -f $dockerfile .

    if $PUSH; then
        docker push $image:$BUILD_TAG
    fi
}

if [ "$DISTRO" == "ubuntu" ]; then
    docker_build_and_push "antrea/openvswitch" "Dockerfile"
elif [ "$DISTRO" == "ubi" ]; then
    docker_build_and_push "antrea/openvswitch-ubi" "Dockerfile.ubi"
elif [ "$DISTRO" == "debian" ]; then
    docker_build_and_push "antrea/openvswitch-debian" "Dockerfile.debian"
elif [ "$DISTRO" == "windows" ]; then
    image="antrea/windows-ovs"
    build_args="--build-arg OVS_VERSION=$OVS_VERSION"
    docker_build_and_push_windows "${image}" "Dockerfile.windows" "${build_args}" "${OVS_VERSION}" $PUSH ""
elif [ "$DISTRO" == "photon" ]; then
    if [ "$RPM_REPO_URL" == "" ]; then
        echoerr "Must specify --rpm-repo-url when building for Photon"
        exit 1
    fi
    if [ "$IPSEC" == "true" ]; then
        echoerr "IPsec is not supported for Photon"
        exit 1
    fi
    if ! [ -f "photon-rootfs.tar.gz" ]; then
        echoerr "photon-rootfs.tar.gz not found."
        exit 1
    fi
    docker_build_and_push "antrea/openvswitch-photon" "Dockerfile.photon"
elif [ "$DISTRO" == "ubi" ]; then
    docker_build_and_push "antrea/openvswitch-ubi" "Dockerfile.ubi"
fi

popd > /dev/null
