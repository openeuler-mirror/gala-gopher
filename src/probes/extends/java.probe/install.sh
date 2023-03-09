#!/bin/bash
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))
INSTALL_FILES="jvm.probe/JvmProbe.jar"
INSTALL_FILES+=" jvm.probe/JvmProbeAgent.jar"

while getopts ":b:c:" opt
do
    case $opt in
        b) INSTALL_PATH=$OPTARG;;
        c) CONF_PATH=$OPTARG;;
        ?) echo "unknow param"; exit 1;;
    esac
done

cd ${PRJ_DIR}
    if [ ${INSTALL_PATH} ]; then
        mkdir -p ${INSTALL_PATH}
        for file in ${INSTALL_FILES}; do
            cp ${file} ${INSTALL_PATH}
        done
    fi

