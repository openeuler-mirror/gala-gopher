#!/bin/bash
ARCH=$(uname -m)
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))

TOOLS_DIR=${PRJ_DIR}/tools
SRC_DIR=${PRJ_DIR}/src
VMLINUX_DIR=${SRC_DIR}/include
LINUX_VER="${VMLINUX_VER:-$(uname -r)}"
DEP_LIST=(elfutils-devel libbpf libbpf-devel llvm libstdc++ libstdc++-devel)
# tailor probes
export EBPF_TAILOR_PROBES=$(for probe in ${EXTEND_PROBES//|/ } ; do printf "./%s/ " $probe; done)

function add_bpftool()
{
    cd ${TOOLS_DIR}
    if [ -f "bpftool" ];then
        echo "bpftool has existed."
        return $?
    fi

    LIBBPF_MAJOR=`rpm -qa | grep libbpf-devel | awk -F'-' '{print $3}' | awk -F'.' '{print $1}'`
    LIBBPF_MINOR=`rpm -qa | grep libbpf-devel | awk -F'-' '{print $3}' | awk -F'.' '{print $2}'`
    if [ "$LIBBPF_MAJOR" -gt 0 ];then
        ln -s bpftool_v6.8.0/bpftool_${ARCH} bpftool
    elif [ "$LIBBPF_MINOR" -ge 8 ];then
        ln -s bpftool_v6.8.0/bpftool_${ARCH} bpftool
    else
        ln -s bpftool_${ARCH} bpftool
    fi
}

function check_dep()
{
    for dep in "${DEP_LIST[@]}" ; do
        rpm -q $dep --quiet
        if [ $? -ne 0 ];then
            echo "Error: $dep not installed"
            exit 1
        fi
    done

    rpm -q clang --quiet || rpm -q clang12 --quiet
    if [ $? -ne 0 ];then
            echo "Error: clang and clang12 not installed"
            exit 1
    fi

    V=`clang --version | grep version | awk -F ' ' '{print $3}' | awk -F . '{print $1}'`
    if [ "$V" -lt 10 ];then
        echo "Error: clange version need >= 10.x.x"
        exit 1
    fi
}

function enable_debug()
{
    export BUILD_OPTS="${BUILD_OPTS} -DGOPHER_DEBUG"
}

function compile_probe()
{
    cd ${SRC_DIR}
    echo "=======Begin to compile ebpf-based probes======:" ${EBPF_PROBES}
    echo "Compiling with BUILD_OPTS=\"${BUILD_OPTS}\""
    make
}

function compile_clean()
{
    cd ${SRC_DIR}
    make clean
}

if [ -z "$1"  -o  "$1" == "-h"  -o  "$1" == "--help" ];
then
    echo build.sh -h/--help : Show this message.
    echo build.sh    --check: Check the environment including arch/os/kernel/packages.
    echo build.sh -c/--clean: Clean the built binary.
    echo build.sh -b/--build: Build all the probes.
    exit
fi

if [ "$1" == "--check" ];
then
    check_dep
    exit
fi

add_bpftool

if [ "$1" == "-b"  -o  "$1" == "--build" ];
then
    check_dep

    if [ "$2" == "-d"  -o  "$2" == "--debug" ];
    then
        enable_debug
    fi
    compile_probe || exit 1
    exit
fi


if [ "$1" == "-c"  -o  "$1" == "--clean" ];
then
    compile_clean
    exit
fi
