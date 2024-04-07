#!/bin/sh
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))
SH_TAILOR_PROBES=$EXTEND_PROBES

INSTALL_FILES=""

while getopts ":b:c:" opt
do
    case $opt in
        b) INSTALL_PATH=$OPTARG;;
        c) CONF_PATH=$OPTARG;;
        ?) echo "unknow param"; exit 1;;
    esac
done

cd ${PRJ_DIR}
for probe_dir in $(ls $PRJ_DIR | grep ".probe$") ; do
    # tailor probes
    if ! [[ $SH_TAILOR_PROBES =~ $probe_dir ]] ; then
        INSTALL_FILES+=" $probe_dir/*.sh"
    fi
done

mkdir -p ${INSTALL_PATH}
if [ ! -n ${INSTALL_FILES} ] ; then
    \cp ${INSTALL_FILES} ${INSTALL_PATH}
fi