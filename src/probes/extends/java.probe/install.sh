#!/bin/bash
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))
INSTALL_FILES="jvm.probe/JvmProbe.jar"

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
        \cp ${INSTALL_FILES} ${INSTALL_PATH}
    fi

