#!/bin/bash

CUR_FOLDER=$(dirname $(readlink -f "$0"))
DEP_FILES_DIR=${CUR_FOLDER}
VMLINUX_DIR=${CUR_FOLDER}/vmlinux_tmp
VMLINUX_PATH=${VMLINUX_DIR}/vmlinux_llvm
DST_VMLINUX_H=${CUR_FOLDER}/../src/include/vmlinux.h
BPFTOOL=${CUR_FOLDER}/bpftool
VMLINUX_REL=
IPVS_REL=

function install_pahole()
{
    # 1 check pahole already installed
    PAHOLE_VERSION=`pahole --version`
    if [ ${PAHOLE_VERSION} != "v1.20" ]; then
        return 0
    fi

    cd ${DEP_FILES_DIR}
    tar jxvf dwarves.tar.bz2

    DWARVES_DIR=${DEP_FILES_DIR}/dwarves-dfsg-1.20
    if [ ! d ${DWARVES_DIR} ]; then
        echo "Install pahole failed. Please check dwarves.tar.bz2 existed."
        exit 1
    fi

    # 2 build & install
    cd ${DWARVES_DIR}
    mkdir build
    cd build
    cmake -D__LIB=lib ..
    make
    make install

    # 3 check pahole version
    PAHOLE_VERSION=`pahole --version`
    if [ ${PAHOLE_VERSION} != "v1.20" ]; then
        echo "Failed to install pahole."
        exit 1
    fi

    # 4 clear tmp files
    rm -rf ${DWARVES_DIR}
    echo "Pahole install succeed."
}

function install_dep_packages()
{
    yum install -y asciidoc audit-libs-devel bc \
                   binutils-devel bison gtk2-devel \
                   java-1.8.0-openjdk java-1.8.0-openjdk-devel libbabeltrace-devel \
                   libunwind-devel ncurses-devel net-tools \
                   newt-devel numactl-devel openssl-devel \
                   pciutils-devel perl-generators python3-devel \
                   python3-docutils xmlto llvm llvm-devel
}

function prepare_dep()
{
    # 1 clear tmp files
    echo "==== Step 1: clear tmp files"
    rm -rf /root/rpmbuild/

    # 2 download kernel source rpm
    echo "==== Step 2: download kernel source rpm"
    rm -rf ${VMLINUX_DIR}
    mkdir -p ${VMLINUX_DIR}
    cd ${VMLINUX_DIR}

    yum download --source kernel
    if [ ! -f kernel*.src.rpm ]; then
        echo "****Warning: Failed to download kernel-*.src.rpm, please check yum.repo****"
        return 1
    fi

    install_pahole
    install_dep_packages
}

function merge_rel_objs()
{
    ld -r $1/*.rel -o vmlinux_obj
    VMLINUX_REL=${VMLINUX_DIR}/vmlinux_obj
}

function build_vmlinux()
{
    cd ${VMLINUX_DIR}

    rpm -ivh kernel*.src.rpm

    # 3 rpm build
    echo "==== Step 3: build kernel"
    cd /root/rpmbuild/
    mkdir BUILD SRPMS RPMS
    cd BUILD
    rpmbuild -ba ../SPECS/kernel.spec

    # 4 generate vmlinux.h
    echo "==== Step 4: generate vmlinux from vmlinux.o and ip_vs.ko"
    mkdir ${VMLINUX_DIR}
    cd ${VMLINUX_DIR}
    cp /root/rpmbuild/BUILD/kernel-*/linux-*/vmlinux.o vmlinux.rel
    cp /root/rpmbuild/BUILD/kernel-*/linux-*/net/netfilter/ipvs/ip_vs.ko ip_vs.rel

    merge_rel_objs ${VMLINUX_DIR}

    pahole -J ${VMLINUX_REL}
    llvm-objcopy --only-section=.BTF \
        --set-section-flags .BTF=alloc,readonly \
        --strip-all ${VMLINUX_REL} ${VMLINUX_PATH}
    if [ ! -f ${VMLINUX_PATH} ]; then
        return 1
    fi
    strip -x ${VMLINUX_PATH}
    echo "==== Succeed to generate vmlinux:" ${VMLINUX_PATH}
}

function generate_vmlinux_h()
{
    if [ ! -f ${VMLINUX_PATH} ];then
        return 1
    fi

    cd ${VMLINUX_DIR}
    echo "==== Generate vmlinux.h from vmlinux"
    echo "==== Step 1: Generate vmlinux.h from vmlinux"
    ${BPFTOOL} btf dump file ${VMLINUX_PATH} format c > vmlinux.h

    # del '#ifndef BPF_NO_PRESERVE_ACCESS_INDEX' line and 2 lines below
    echo "==== Step 2: Strip BPF_NO_PRESERVE_ACCESS_INDEX from vmlinux.h"
    sed -i '/#ifndef BPF_NO_PRESERVE_ACCESS_INDEX/,+2d' vmlinux.h

    echo "==== Step 3: Add ext_def.h to vmlinux.h"
    sed -i '$i #include "ext_def.h"' vmlinux.h

    echo "==== Step 4: Copy vmlinux.h to " ${DST_VMLINUX_H}
    rm -rf ${DST_VMLINUX_H}
    cp vmlinux.h ${DST_VMLINUX_H}
    echo "==== Succeed to generate vmlinux.h"
}

function clean_temp_files()
{
    # clean temp files
    rm -rf /root/rpmbuild/
    rm -rf ${VMLINUX_DIR}
}

# build vmlinux
if [ -f /sys/fs/bpf/vmlinux ]; then
    echo "==== vmlinux exist!"
    exit
fi
prepare_dep
if [ $? -ne 0 ]; then
    clean_temp_files
    exit
fi
build_vmlinux
generate_vmlinux_h
clean_temp_files
