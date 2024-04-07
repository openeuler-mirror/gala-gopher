#!/bin/sh
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))
MAKE_DIR=${PRJ_DIR}/src

EXT_PATH=/opt/gala-gopher/extend_probes
CONF_PATH=/etc/gala-gopher/extend_probes
# tailor probes
export EBPF_TAILOR_PROBES=$(for probe in ${EXTEND_PROBES//|/ } ; do printf "./%s/ " $probe; done)

while getopts ":b:c:" opt
do
    case $opt in
        b) EXT_PATH=$OPTARG;;
        c) CONF_PATH=$OPTARG;;
        ?) echo "unknow param"; exit 1;;
    esac
done

# make and copy to specify dir
cd ${MAKE_DIR}
make install INSTALL_DIR=${EXT_PATH} CONF_INSTALL_DIR=${CONF_PATH}
