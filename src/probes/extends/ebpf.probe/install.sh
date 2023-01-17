#!/bin/sh
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))
MAKE_DIR=${PRJ_DIR}/src

EXT_PATH=/usr/bin/extends
CONF_PATH=/etc/gala-gopher/extend_probes
while getopts ":b:c:" opt
do
    case $opt in
        b) EXT_PATH=$OPTARG;;
        c) CONF_PATH=$OPTARG;;
        ?) echo "unknow param"; exit 1;;
    esac
done

EXT_INSTALL_PATH=${EXT_PATH}/ebpf.probe
CONF_INSTALL_PATH=${CONF_PATH}/ebpf.probe

# make and copy to specify dir
cd ${MAKE_DIR}
make install INSTALL_DIR=${EXT_INSTALL_PATH} CONF_INSTALL_DIR=${CONF_INSTALL_PATH}
\cp -r ${EXT_INSTALL_PATH}/* ${EXT_PATH}
rm -rf ${EXT_INSTALL_PATH}
\cp -r ${CONF_INSTALL_PATH}/* ${CONF_PATH}
rm -rf ${CONF_INSTALL_PATH}
