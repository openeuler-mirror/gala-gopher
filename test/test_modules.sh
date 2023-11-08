#!/bin/bash

PROGRAM=$0
PROJECT_FOLDER=$(dirname $(readlink -f "$0"))
TEST_FOLDER=${PROJECT_FOLDER}

function compile_test()
{
    cd ${TEST_FOLDER}
    cd test_modules
    rm -rf build
    mkdir build
    cd build

    cmake ..
    make
}

function run_test()
{
    cd ${TEST_FOLDER}
    ./submodule_test > test.log 2>&1
}

function log_info()
{
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

log_info "Compiling test modules..."
compile_test
log_info "Test modules compiled successfully."

log_info "Running test..."
run_test
log_info "Running test..."
