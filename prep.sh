#!/bin/bash
set -e

# Run once, to initialize the git repo
#
git submodule update --init --depth 1 --recursive
