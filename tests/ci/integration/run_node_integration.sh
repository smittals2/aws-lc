#!/bin/bash -exu
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

source tests/ci/common_posix_setup.sh

# SYS_ROOT
#  - SRC_ROOT(aws-lc)
#    - SCRATCH_FOLDER
#      - node
#      - AWS_LC_BUILD_FOLDER
#      - AWS_LC_INSTALL_FOLDER


# Assumes script is executed from the root of aws-lc directory
SCRATCH_FOLDER="${SRC_ROOT}/NODE_BUILD_ROOT"
NODE_SRC_FOLDER="${SCRATCH_FOLDER}/node"
NODE_PATCH_BUILD_FOLDER="${SRC_ROOT}/tests/ci/integration/node_patch"
AWS_LC_BUILD_FOLDER="${SCRATCH_FOLDER}/aws-lc-build"
AWS_LC_INSTALL_FOLDER="${SCRATCH_FOLDER}/aws-lc-install"

mkdir -p ${SCRATCH_FOLDER}
rm -rf "${SCRATCH_FOLDER:?}"/*
cd ${SCRATCH_FOLDER}

function node_build() {
  ./configure --shared-openssl \
    --shared-openssl-libpath="${AWS_LC_INSTALL_FOLDER}/lib" \
    --shared-openssl-includes="${AWS_LC_INSTALL_FOLDER}/include" \
    --shared-openssl-libname=crypto,ssl
  make -j "$NUM_CPU_THREADS"
}

function node_run_tests() {
  make -j "$NUM_CPU_THREADS" test
}

# TODO: Remove this when we make an upstream contribution.
function node_patch_build() {
  for patchfile in $(find -L "${NODE_PATCH_BUILD_FOLDER}" -type f -name '*.patch'); do
    echo "Apply patch $patchfile..."
    patch -p1 --quiet -i "$patchfile"
  done
}

git clone https://github.com/nodejs/node.git ${NODE_SRC_FOLDER} --depth 1
mkdir -p ${AWS_LC_BUILD_FOLDER} ${AWS_LC_INSTALL_FOLDER}
ls

aws_lc_build "$SRC_ROOT" "$AWS_LC_BUILD_FOLDER" "$AWS_LC_INSTALL_FOLDER" -DBUILD_TESTING=OFF -DBUILD_TOOL=OFF -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_SHARED_LIBS=0

# Build and test node from source.
pushd ${NODE_SRC_FOLDER}
node_patch_build
node_build
node_run_tests
popd
