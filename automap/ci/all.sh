#!/bin/bash -xev
# Copyright (c) 2019-2020, MASQ (https://masq.ai) and/or its affiliates. All rights reserved.
CI_DIR="$( cd "$( dirname "$0" )" && pwd )"

#export RUSTC_WRAPPER="$HOME/.cargo/bin/sccache"
pushd "$CI_DIR/.."
ci/lint.sh
ci/build.sh
ci/unit_tests.sh
popd