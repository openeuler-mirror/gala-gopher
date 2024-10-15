#!/bin/bash
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))
PY_TAILOR_PROBES=$EXTEND_PROBES

INSTALL_FILES=""
CONF_FILES=""
META_FILES=""

while getopts ":b:c:m:" opt
do
    case $opt in
        b) INSTALL_PATH=$OPTARG;;
        c) CONF_PATH=$OPTARG;;
        m) META_PATH=$OPTARG;;
        ?) echo "unknown param"; exit 1;;
    esac
done

cd ${PRJ_DIR}
for probe_dir in $(ls $PRJ_DIR | grep ".probe$") ; do
    # tailor probes
    if ! [[ $PY_TAILOR_PROBES =~ $probe_dir ]] ; then
        INSTALL_FILES+=" $probe_dir/*.py"
        if [ -f $probe_dir/*.conf ] ; then
            CONF_FILES+=" $probe_dir/*.conf"
        fi
        if [ -f $probe_dir/*.meta ] ; then
            META_FILES+=" $probe_dir/*.meta"
        fi
    fi
done

# copy ipc.py to /opt/gala-gopher/extend_probes/
INSTALL_FILES+=" ${PRJ_DIR}/common/*.py"

mkdir -p ${INSTALL_PATH}
# copy to specify dir
for file in ${INSTALL_FILES}; do
    cp ${file} ${INSTALL_PATH}
done

mkdir -p ${CONF_PATH}
for file in ${CONF_FILES}; do
    cp ${file} ${CONF_PATH}
done

mkdir -p ${META_PATH}
for file in ${META_FILES}; do
    cp ${file} ${META_PATH}
done