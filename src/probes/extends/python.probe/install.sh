#!/bin/bash
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))

INSTALL_FILES="redis.probe/redis_probe.py"
INSTALL_FILES+=" redis_client.probe/client-async.py"
INSTALL_FILES+=" cadvisor.probe/cadvisor_probe.py"
INSTALL_FILES+=" pg_stat.probe/pg_stat_probe.py"
CONF_FILES="cadvisor.probe/cadvisor_probe.conf"
CONF_FILES+=" pg_stat.probe/pg_stat_probe.conf"

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
    # copy to specify dir
    cd ${PRJ_DIR}
    for file in ${INSTALL_FILES}; do
        cp ${file} ${INSTALL_PATH}
    done
fi

if [ ${CONF_PATH} ]; then
    mkdir -p ${CONF_PATH}
    cd ${PRJ_DIR}
    for file in ${CONF_FILES}; do
        cp ${file} ${CONF_PATH}
    done
fi