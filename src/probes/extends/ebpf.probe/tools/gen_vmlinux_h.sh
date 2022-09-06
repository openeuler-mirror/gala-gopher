#/bin/sh

MAIN=`uname -r | awk -F . '{print $1}'`
MINOR=`uname -r | awk -F . '{print $2}'`
CO_RE=0

CUR_FOLDER=$(dirname $(readlink -f "$0"))
VMLINUX_H=${CUR_FOLDER}/../src/include/vmlinux.h

if [ "$MAIN" -ge 5 ] && [ "$MINOR" -ge 3 ]; then
    CO_RE=1
fi

if [ ${CO_RE} -ne 1 ]; then
    # not support bpf co-re
    echo "==== Env not support bpf co-re"
    ./vmlinux_build.sh
else
    if [ ! -f /sys/kernel/btf/vmlinux ]; then
        echo "==== Env don't have /sys/kernel/btf/vmlinux"
        ./vmlinux_build.sh
        exit
    fi
    echo "Gen vmlinux.h for kernel_"${MAIN}.${MINOR}
    rm -rf ${VMLINUX_H}
    ./bpftool btf dump file ${1:-/sys/kernel/btf/vmlinux} format c > ${VMLINUX_H}
    sed -i '$i #include "ext_def.h"' ${VMLINUX_H}
    echo "==== Succeed to generate vmlinux.h"
fi
