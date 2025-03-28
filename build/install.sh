#!/bin/bash

PROGRAM=$0
PROJECT_FOLDER=$(dirname "$PWD")
EXT_PROBE_FOLDER=${PROJECT_FOLDER}/src/probes/extends
SHARED_LIB_FOLDER=${PROJECT_FOLDER}/src/common
PROBES_PATH_LIST=$(find ${PROJECT_FOLDER}/src/probes -maxdepth 1 | grep ".probe\>")
EXT_PROBE_INSTALL_LIST=$(find ${EXT_PROBE_FOLDER} -maxdepth 2 | grep "\<install.sh\>")
SHARED_LIB_LIST=$(find ${SHARED_LIB_FOLDER} -name "*.so")
JVM_ATTACH_BIN=${PROJECT_FOLDER}/src/lib/jvm/jvm_attach
TAILOR_PATH=${PROJECT_FOLDER}/tailor.conf
TAILOR_PATH_TMP=${TAILOR_PATH}.tmp
BTF_CACHE=${PROJECT_FOLDER}/.cache
BTF_DIR=${PROJECT_FOLDER}/btf

function __create_btf_cache() {
    rm -rf ${BTF_CACHE}
    mkdir -p ${BTF_CACHE}
    mkdir -p ${BTF_DIR}
    ARCH=$(uname -m)
    for file in $(find ${BTF_DIR} -name "*"${ARCH}"*.btf.tar.xz"); do
        tar -xf $file
    done

    for file in $(find ./ -name "*.btf"); do
        mv $file -t ${BTF_CACHE}
    done
}

function __delete_btf_cache() {
    rm -rf ${BTF_CACHE}
}

function load_tailor() {
    if [ -f ${TAILOR_PATH} ]; then
        cp ${TAILOR_PATH} ${TAILOR_PATH_TMP}

        sed -i '/^$/d' ${TAILOR_PATH_TMP}
        sed -i 's/ //g' ${TAILOR_PATH_TMP}
        sed -i 's/^/export /' ${TAILOR_PATH_TMP}
        eval $(cat ${TAILOR_PATH_TMP})
        rm -rf ${TAILOR_PATH_TMP}
    fi
}

function install_daemon_bin() {
    GOPHER_BIN_FILE=${PROJECT_FOLDER}/gala-gopher
    GOPHER_BIN_TARGET_DIR=/usr/bin

    if [ $# -eq 1 ]; then
        GOPHER_BIN_TARGET_DIR=$1
    fi

    cd ${PROJECT_FOLDER}
    if [ ! -f ${GOPHER_BIN_FILE} ]; then
        echo "${GOPHER_BIN_FILE} not exist. please check if build success."
        exit 1
    fi
    if [ ! -d ${GOPHER_BIN_TARGET_DIR} ]; then
        mkdir -p ${GOPHER_BIN_TARGET_DIR}
    fi
    # install gala-gopher bin
    cp -f ${GOPHER_BIN_FILE} ${GOPHER_BIN_TARGET_DIR}
    echo "install ${GOPHER_BIN_FILE} success."

}

function install_conf() {
    GOPHER_CONF_FILE=${PROJECT_FOLDER}/config/gala-gopher.conf
    GOPHER_PROBES_INIT_FILE=${PROJECT_FOLDER}/config/probes.init
    GOPHER_CONF_TARGET_DIR=/etc/gala-gopher
    GOPHER_CUSTOM_FILE=${PROJECT_FOLDER}/config/gala-gopher-custom.json

    if [ $# -eq 1 ]; then
        GOPHER_CONF_TARGET_DIR=$1
    fi

    cd ${PROJECT_FOLDER}
    if [ ! -f ${GOPHER_CONF_FILE} ]; then
        echo "${GOPHER_CONF_FILE} not exist. please check ./config dir."
        exit 1
    fi
    if [ ! -f ${GOPHER_PROBES_INIT_FILE} ]; then
        echo "${GOPHER_PROBES_INIT_FILE} not exist. please check ./config dir."
    fi
    if [ ! -f ${GOPHER_CUSTOM_FILE} ]; then
        echo "${GOPHER_CUSTOM_FILE} not exist. please check ./config dir."
    fi

    # install gala-gopher.conf
    if [ ! -d ${GOPHER_CONF_TARGET_DIR} ]; then
        mkdir -p ${GOPHER_CONF_TARGET_DIR}
    fi
    cp -f ${GOPHER_CONF_FILE} ${GOPHER_CONF_TARGET_DIR}
    echo "install ${GOPHER_CONF_FILE} success."
    cp -f ${GOPHER_CUSTOM_FILE} ${GOPHER_CONF_TARGET_DIR}
    echo "install ${GOPHER_CUSTOM_FILE} success."
    cp -f ${GOPHER_PROBES_INIT_FILE} ${GOPHER_CONF_TARGET_DIR}
    echo "install ${GOPHER_PROBES_INIT_FILE} success."
}

function install_meta() {
    GOPHER_META_DIR=/opt/gala-gopher/meta

    if [ $# -eq 1 ]; then
        GOPHER_META_DIR=$1/meta
    fi

    rm -rf ${GOPHER_META_DIR}/*.meta

    cd ${PROJECT_FOLDER}

    # install meta files
    if [ ! -d ${GOPHER_META_DIR} ]; then
        mkdir -p ${GOPHER_META_DIR}
    fi

    if [ -n ${PROBES} ]; then
        # check tailor env
        PROBES_PATH_LIST=$(echo "$PROBES_PATH_LIST" | grep -Ev "$PROBES")
    fi

    for PROBE_PATH in ${PROBES_PATH_LIST}; do
        cp ${PROBE_PATH}/*.meta ${GOPHER_META_DIR}
    done
    echo "install meta file of native probes success."
}

function install_btf() {
    GOPHER_BTF_DIR=/opt/gala-gopher/btf

    __create_btf_cache

    if [ $# -eq 1 ]; then
        GOPHER_BTF_DIR=$1/btf
    fi

    rm -rf ${GOPHER_BTF_DIR}/*.btf

    cd ${PROJECT_FOLDER}

    # install btf files
    if [ ! -d ${GOPHER_BTF_DIR} ]; then
        mkdir -p ${GOPHER_BTF_DIR}
    fi
    BTF_FILES=$(find ${BTF_CACHE} -name "*.btf")
    for file in ${BTF_FILES}; do
        cp ${file} ${GOPHER_BTF_DIR}
    done
    __delete_btf_cache
    echo "install btf files success."
}

function install_shared_lib() {
    GOPHER_SHARED_LIB_DIR=/opt/gala-gopher/lib

    if [ $# -eq 1 ]; then
        GOPHER_SHARED_LIB_DIR=$1/lib
    fi

    if [ ! -d ${GOPHER_SHARED_LIB_DIR} ]; then
        mkdir -p ${GOPHER_SHARED_LIB_DIR}
    fi

    for SHARED_LIB in ${SHARED_LIB_LIST}; do
        echo "install lib:" ${SHARED_LIB}
        cp ${SHARED_LIB} ${GOPHER_SHARED_LIB_DIR}
    done

    echo "install lib:" ${JVM_ATTACH_BIN}
    cp ${JVM_ATTACH_BIN} ${GOPHER_SHARED_LIB_DIR}
}

function install_extend_probes() {
    GOPHER_EXTEND_PROBE_DIR=${1:-/opt/gala-gopher}/extend_probes
    GOPHER_EXTEND_PROBE_CONF_DIR=${2:-/etc/gala-gopher}/extend_probes
    GOPHER_EXTEND_PROBE_META_DIR=${1:-/opt/gala-gopher}/meta

    if [ ! -d ${GOPHER_EXTEND_PROBE_DIR} ]; then
        mkdir -p ${GOPHER_EXTEND_PROBE_DIR}
    fi

    if [ ! -d ${GOPHER_EXTEND_PROBE_CONF_DIR} ]; then
        mkdir -p ${GOPHER_EXTEND_PROBE_CONF_DIR}
    fi

    if [ ! -d ${GOPHER_EXTEND_PROBE_META_DIR} ]; then
        mkdir -p ${GOPHER_EXTEND_PROBE_META_DIR}
    fi
    cd ${PROJECT_FOLDER}

    # Search for install.sh in extend probe directory
    cd ${EXT_PROBE_FOLDER}
    for INSTALL_PATH in ${EXT_PROBE_INSTALL_LIST}; do
        echo "install path:" ${INSTALL_PATH}
        sh ${INSTALL_PATH} -b ${GOPHER_EXTEND_PROBE_DIR} -c ${GOPHER_EXTEND_PROBE_CONF_DIR} -m ${GOPHER_EXTEND_PROBE_META_DIR}
    done
}

function install_script() {
    INIT_PROBES_SCRIPT=${PROJECT_FOLDER}/script/init_probes.sh
    START_PRE_SCRIPT=${PROJECT_FOLDER}/script/start_pre.sh
    SCRIPT_TARGET_DIR=/usr/libexec/gala-gopher

    if [ $# -eq 1 ]; then
        SCRIPT_TARGET_DIR=$1
    fi

    if [ ! -d ${SCRIPT_TARGET_DIR} ]; then
        mkdir -p ${SCRIPT_TARGET_DIR}
    fi

    cd ${PROJECT_FOLDER}
    if [ ! -f ${INIT_PROBES_SCRIPT} ]; then
        echo "${INIT_PROBES_SCRIPT} does not exist. Please check ./script dir"
        exit 1
    fi

    cp -f ${INIT_PROBES_SCRIPT} ${START_PRE_SCRIPT} ${SCRIPT_TARGET_DIR}
    echo "install ${INIT_PROBES_SCRIPT} and ${START_PRE_SCRIPT} success."
}

function install_client_bin()
{
    CLI_BIN_FILE=${PROJECT_FOLDER}/gopher-ctl
    CLI_BIN_TARGET_DIR=/usr/bin

    if [ $# -eq 1 ]; then
        CLI_BIN_TARGET_DIR=$1
    fi

    cd ${PROJECT_FOLDER}
    if [ ! -f ${CLI_BIN_FILE} ]; then
        echo "${CLI_BIN_FILE} does not exist. Please check if build success."
        exit 1
    fi

    # install gopher-cli bin
    cp -f ${CLI_BIN_FILE} ${CLI_BIN_TARGET_DIR}
    echo "install ${CLI_BIN_FILE} success."

}

# main process
load_tailor
install_daemon_bin $1
install_conf $3
install_meta $2
install_shared_lib $2
install_extend_probes $2 $3
install_script $4
install_btf $5
install_client_bin $1