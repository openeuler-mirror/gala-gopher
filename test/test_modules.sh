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
    ./submodule_test
}

compile_test
run_test

