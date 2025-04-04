#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -ex

source tests/ci/common_posix_setup.sh

# Set up environment.

# SYS_ROOT
#  - SRC_ROOT(aws-lc)
#    - SCRATCH_FOLDER
#      - THRIFT_SRC_FOLDER
#      - AWS_LC_BUILD_FOLDER
#      - AWS_LC_INSTALL_FOLDER

# Assumes script is executed from the root of aws-lc directory
SCRATCH_FOLDER="${SRC_ROOT}/THRIFT_BUILD_ROOT"
THRIFT_SRC_FOLDER="${SCRATCH_FOLDER}/thrift"
THRIFT_BUILD_PREFIX="${THRIFT_SRC_FOLDER}/build/install"
AWS_LC_BUILD_FOLDER="${SCRATCH_FOLDER}/aws-lc-build"
AWS_LC_INSTALL_FOLDER="${SCRATCH_FOLDER}/aws-lc-install"

mkdir -p ${SCRATCH_FOLDER}
rm -rf "${SCRATCH_FOLDER:?}"/*
cd ${SCRATCH_FOLDER}

function thrift_build() {
  # Generate configure file
  ./bootstrap.sh
#
#  export CFLAGS="-I${AWS_LC_INSTALL_FOLDER}/include ${CFLAGS}"
#  export CXXFLAGS="-I${AWS_LC_INSTALL_FOLDER}/include ${CXXFLAGS}"
#  export LDFLAGS="-L${AWS_LC_INSTALL_FOLDER}/lib ${LDFLAGS}"
#  export LD_LIBRARY_PATH="${AWS_LC_INSTALL_FOLDER}/lib"

  ./configure --prefix="$THRIFT_BUILD_PREFIX" --with-openssl="$AWS_LC_INSTALL_FOLDER"
  make -j install
  make check

#  local kafka_executable="${THRIFT_BUILD_PREFIX}/lib/librdkafka.so"
#  ldd ${kafka_executable} \
#    | grep "${AWS_LC_INSTALL_FOLDER}/lib/libcrypto.so" || exit 1
}

function thrift_run_tests() {

}

git clone https://github.com/apache/thrift.git ${THRIFT_SRC_FOLDER}
mkdir -p ${AWS_LC_BUILD_FOLDER} ${AWS_LC_INSTALL_FOLDER}
ls

aws_lc_build "$SRC_ROOT" "$AWS_LC_BUILD_FOLDER" "$AWS_LC_INSTALL_FOLDER" -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_TESTING=OFF -DBUILD_TOOL=OFF -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=1

# Build openvpn from source.
pushd ${THRIFT_SRC_FOLDER}
thrift_build
thrift_run_tests
popd
