#!/bin/bash
rustup show
rustup update stable
rustup show
rustup component add rustfmt
rustup component add clippy
./ci/all.sh
./ci/multinode_integration_test.sh
./ci/collect_results.sh
