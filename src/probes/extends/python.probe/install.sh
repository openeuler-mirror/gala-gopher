#!/bin/bash
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))

INSTALL_FILES="redis.probe/redis_probe.py"
INSTALL_FILES+=" redis_client.probe/client-async.py"
INSTALL_FILES+=" cadvisor.probe/cadvisor_probe.py"
INSTALL_FILES+=" cadvisor.probe/cadvisor_probe.conf"
INSTALL_FILES+=" pg_stat.probe/pg_stat_probe.py"
INSTALL_FILES+=" pg_stat.probe/pg_stat_probe.conf"

if [ $# -eq 1 ]; then
    # copy to specify dir
    cd ${PRJ_DIR}
    for file in ${INSTALL_FILES}; do
        cp ${file} $1
    done
fi