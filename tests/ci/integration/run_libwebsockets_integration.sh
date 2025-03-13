#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -ex

source tests/ci/common_posix_setup.sh

# Set up environment.

# SYS_ROOT
#  - SRC_ROOT(aws-lc)
#    - SCRATCH_FOLDER
#      - SOCKET_SRC_FOLDER
#      - AWS_LC_BUILD_FOLDER
#      - AWS_LC_INSTALL_FOLDER

# Assumes script is executed from the root of aws-lc directory
SCRATCH_FOLDER="${SRC_ROOT}/SOCKETS_BUILD_ROOT"
SOCKET_SRC_FOLDER="${SCRATCH_FOLDER}/libwebsockets"
SOCKET_BUILD_PREFIX="${SOCKET_SRC_FOLDER}/build/install"
AWS_LC_BUILD_FOLDER="${SCRATCH_FOLDER}/aws-lc-build"
AWS_LC_INSTALL_FOLDER="${SCRATCH_FOLDER}/aws-lc-install"

mkdir -p ${SCRATCH_FOLDER}
rm -rf "${SCRATCH_FOLDER:?}"/*
cd ${SCRATCH_FOLDER}

function libwebsockets_build() {
#  export CFLAGS="-I${AWS_LC_INSTALL_FOLDER}/include ${CFLAGS}"
#  export CXXFLAGS="-I${AWS_LC_INSTALL_FOLDER}/include ${CXXFLAGS}"
#  export LDFLAGS="-L${AWS_LC_INSTALL_FOLDER}/lib ${LDFLAGS}"
#  export LD_LIBRARY_PATH="${AWS_LC_INSTALL_FOLDER}/lib"
  mkdir build && cd build
  cmake .. -DOPENSSL_LIBRARIES="${AWS_LC_INSTALL_FOLDER}/lib/libssl.so;\
  ${AWS_LC_INSTALL_FOLDER}/lib/libcrypto.so" -DOPENSSL_INCLUDE_DIRS="${AWS_LC_INSTALL_FOLDER}/include" \
  -DLWS_WITH_BORINGSSL=1 -DCMAKE_BUILD_TYPE=Debug
  make -j  && sudo make install

#  local kafka_executable="${SOCKET_BUILD_PREFIX}/lib/librdkafka.so"
#  ldd ${kafka_executable} \
#    | grep "${AWS_LC_INSTALL_FOLDER}/lib/libcrypto.so" || exit 1
}
#
#function kafka_run_tests() {
#  export LD_LIBRARY_PATH="${AWS_LC_INSTALL_FOLDER}/lib"
#  python3 -m venv venv
#  source venv/bin/activate
#
#  pushd ${SOCKET_SRC_FOLDER}/tests
#  python3 -m pip install -U -r requirements.txt
#  python3 -m trivup.clusters.KafkaCluster --version 2.8.0 << EOF
#  TESTS_SKIP=0092,0113 make -j quick
#  exit
#EOF
#}

# This patch is only needed to execute the tests. A run_test executable is not
# available with the make quick target, this patch allows us to build that executable first.
#function kafka_patch_test() {
#  patchfile="${SOCKET_TEST_PATCH_FOLDER}/librdkafka-testing.patch"
#  echo "Apply patch $patchfile..."
#  patch -p1 --quiet -i "$patchfile"
#}

git clone https://github.com/warmcat/libwebsockets.git ${SOCKET_SRC_FOLDER}
mkdir -p ${AWS_LC_BUILD_FOLDER} ${AWS_LC_INSTALL_FOLDER}
ls

aws_lc_build "$SRC_ROOT" "$AWS_LC_BUILD_FOLDER" "$AWS_LC_INSTALL_FOLDER" -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_TESTING=OFF -DBUILD_TOOL=OFF -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=1

# Build openvpn from source.
pushd ${SOCKET_SRC_FOLDER}
libwebsockets_build
popd
