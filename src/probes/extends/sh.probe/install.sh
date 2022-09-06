#!/bin/sh
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))

INSTALL_FILES="rabbitmq.probe/rabbitmq_probe.sh"

if [ $# -eq 1 ]; then
    # copy to specify dir
    cd ${PRJ_DIR}
    \cp ${INSTALL_FILES} $1
fi