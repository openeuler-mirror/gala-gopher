#!/bin/bash

# 一键构建脚本
if [ "$1" == "clean" ]; then
    echo "Cleaning build directory..."
    rm -rf build
    exit 0
fi

mkdir -p build
cd build
cmake ..

make
