#!/bin/sh
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))
MAKE_DIR=${PRJ_DIR}/src

EXT_PATH=/usr/bin/extends
if [ $# -eq 1 ]; then
    EXT_PATH=$1
fi
INSTALL_PATH=${EXT_PATH}/ebpf.probe
INSTALL_CONF_FILES="stackprobe/stackprobe.conf"

# make and copy to specify dir
cd ${MAKE_DIR}
make install INSTALL_DIR=${INSTALL_PATH}
cp ${INSTALL_CONF_FILES} ${INSTALL_PATH}
\cp ${INSTALL_PATH}/* $1

rm -rf ${INSTALL_PATH}
