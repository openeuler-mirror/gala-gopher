#!/bin/sh
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))

INSTALL_FILES="rabbitmq.probe/rabbitmq_probe.sh"

while getopts ":b:c:" opt
do
    case $opt in
        b) INSTALL_PATH=$OPTARG;;
        c) CONF_PATH=$OPTARG;;
        ?) echo "unknow param"; exit 1;;
    esac
done

if [ ${INSTALL_PATH} ]; then
    mkdir -p ${INSTALL_PATH}
    cd ${PRJ_DIR}
    \cp ${INSTALL_FILES} ${INSTALL_PATH}
fi