#!/bin/bash

PROGRAM=$0
PROJECT_FOLDER=$(dirname "$PWD")

PROBES_FOLDER=${PROJECT_FOLDER}/src/probes
PROBES_PATH_LIST=`find ${PROJECT_FOLDER}/src/probes -maxdepth 1 | grep ".probe\>"`
EXT_PROBE_FOLDER=${PROJECT_FOLDER}/src/probes/extends
PROBE_MNG_FOLDER=${PROJECT_FOLDER}/src/lib/probe
JVM_FOLDER=${PROJECT_FOLDER}/src/lib/jvm
VMLINUX_DIR=${PROJECT_FOLDER}/src/probes/extends/ebpf.probe/src/include
EXT_PROBE_BUILD_LIST=`find ${EXT_PROBE_FOLDER} -maxdepth 2 | grep "\<build.sh\>"`
DEP_LIST=(cmake git librdkafka-devel libconfig-devel uthash-devel libbpf-devel clang bpftool
          llvm java-1.8.0-openjdk-devel jsoncpp-devel libcurl-devel openssl-devel libevent-devel)
PROBES_LIST=""
PROBES_C_LIST=""
PROBES_META_LIST=""

COMMON_FOLDER=${PROJECT_FOLDER}/src/common
DAEMON_FOLDER=${PROJECT_FOLDER}/src/daemon

TAILOR_PATH=${PROJECT_FOLDER}/tailor.conf
TAILOR_PATH_TMP=${TAILOR_PATH}.tmp

# libbpf version
LIBBPF_VER=$(rpm -q libbpf | awk -F'-' '{print $2}')
LIBBPF_VER_MAJOR=$(echo ${LIBBPF_VER} | awk -F'.' '{print $1}')
LIBBPF_VER_MINOR=$(echo ${LIBBPF_VER} | awk -F'.' '{print $2}')

DEFAULT_BUILD_OPTS="-DFLAMEGRAPH_SVG=1"

function load_tailor()
{
    if [ -f ${TAILOR_PATH} ]; then
        cp ${TAILOR_PATH} ${TAILOR_PATH_TMP}

        sed -i '/^$/d' ${TAILOR_PATH_TMP}
        sed -i 's/ //g' ${TAILOR_PATH_TMP}
        sed -i 's/^/export /' ${TAILOR_PATH_TMP}
        eval `cat ${TAILOR_PATH_TMP}`

        rm -rf ${TAILOR_PATH_TMP}
    fi
    # disable some probes that work not very well
    export EXTEND_PROBES="$EXTEND_PROBES cgprobe lvsprobe schedprobe nsprobe rabbitmq.probe redis_client.probe redis.probe"
}

function __get_probes_source_files()
{
    one_probe_src_list=`find $1 -name "*.c"`
    for one_file in ${one_probe_src_list}
    do
        file_name=${one_file#*$1/}
        file_name=${file_name%.*}

        if [[ ! $file_name = $2 && ! $file_name = $2_daemon ]]; then
            PROBES_C_LIST=${PROBES_C_LIST}\;${1}/${file_name}.c
        fi
    done
}

function __build_bpf()
{
    cd ${PROBE_MNG_FOLDER}
    make
}

function __rm_bpf()
{
    cd ${PROBE_MNG_FOLDER}
    make clean
}

function __build_jvm_attach()
{
    cd ${JVM_FOLDER}
    make
}

function __rm_jvm_attach()
{
    cd ${JVM_FOLDER}
    make clean
}

function prepare_probes()
{
	__build_bpf
    if [ ${PROBES} ]; then
        # check tailor env
        PROBES_PATH_LIST=$(echo "$PROBES_PATH_LIST" | grep -Ev "$PROBES")
        echo "prepare probes after tailor: " ${PROBES_PATH_LIST}
    fi

    cd ${PROBES_FOLDER}
    for PROBE_PATH in ${PROBES_PATH_LIST}
    do
        PROBE_NAME=${PROBE_PATH##*/}
        PROBE_NAME=${PROBE_NAME%.*}
        rm -f ${PROBE_PATH}/${PROBE_NAME}_daemon.c
        cp -f ${PROBE_PATH}/${PROBE_NAME}.c ${PROBE_PATH}/${PROBE_NAME}_daemon.c
        sed -i "s/int main(/int probe_main_${PROBE_NAME}(/g" ${PROBE_PATH}/${PROBE_NAME}_daemon.c

        if [ x"$PROBES_C_LIST" = x ];then
            PROBES_C_LIST=${PROBE_PATH}/${PROBE_NAME}_daemon.c
        else
            PROBES_C_LIST=${PROBES_C_LIST}\;${PROBE_PATH}/${PROBE_NAME}_daemon.c
        fi

        __get_probes_source_files $PROBE_PATH $PROBE_NAME

        if [ x"$PROBES_LIST" = x ];then
            PROBES_LIST=${PROBE_NAME}
        else
            PROBES_LIST=${PROBES_LIST}" "${PROBE_NAME}
        fi

        if [ x"$PROBES_META_LIST" = x ];then
            PROBES_META_LIST=${PROBE_PATH}/${PROBE_NAME}.meta
        else
            PROBES_META_LIST=${PROBES_META_LIST}" "${PROBE_PATH}/${PROBE_NAME}.meta
        fi
    done

    echo "PROBES_C_LIST:"
    echo ${PROBES_C_LIST}
    echo "PROBES_META_LIST:"
    echo ${PROBES_META_LIST}
    echo "LIBBPF_VER:"
    echo ${LIBBPF_VER}
    cd -
}

function compile_lib()
{
    __build_jvm_attach
    cd ${COMMON_FOLDER}
    rm -rf *.so
    make
}

function compile_lib_clean()
{
    __rm_jvm_attach
    cd ${COMMON_FOLDER}
    rm -rf *.so
}

function compile_daemon_release()
{
    cd ${DAEMON_FOLDER}
    rm -rf build
    mkdir build
    cd build

    cmake "$@" -DGOPHER_DEBUG="0" -DPROBES_C_LIST="${PROBES_C_LIST}" -DPROBES_LIST="${PROBES_LIST}" -DPROBES_META_LIST="${PROBES_META_LIST}" \
        -DLIBBPF_VER_MAJOR="${LIBBPF_VER_MAJOR}" -DLIBBPF_VER_MINOR="${LIBBPF_VER_MINOR}" ..
    make
}

function compile_daemon_debug()
{
    cd ${DAEMON_FOLDER}
    rm -rf build
    mkdir build
    cd build

    cmake "$@" -DGOPHER_DEBUG="1" -DPROBES_C_LIST="${PROBES_C_LIST}" -DPROBES_LIST="${PROBES_LIST}" -DPROBES_META_LIST="${PROBES_META_LIST}" \
        -DLIBBPF_VER_MAJOR="${LIBBPF_VER_MAJOR}" -DLIBBPF_VER_MINOR="${LIBBPF_VER_MINOR}" ..
    make
}


function compile_daemon_clean()
{
    rm -rf ${PROJECT_FOLDER}/gala-gopher
}


function clean_env()
{
    cd ${PROBES_FOLDER}
    for PROBE_PATH in ${PROBES_PATH_LIST}
    do
        PROBE_NAME=${PROBE_PATH##*/}
        PROBE_NAME=${PROBE_NAME%.*}

        rm -f ${PROBE_PATH}/${PROBE_NAME}_daemon.c
    done
}

function compile_extend_probes_clean()
{
	__rm_bpf
    # Search for build.sh in probe directory
    echo "==== Begin to clean extend probes ===="
    cd ${EXT_PROBE_FOLDER}
    for BUILD_PATH in ${EXT_PROBE_BUILD_LIST}
    do
        echo "==== BUILD_PATH: " ${BUILD_PATH}
        sh ${BUILD_PATH} --clean
    done
}

function compile_extend_probes_debug()
{
    # Search for build.sh in probe directory
    echo "==== Begin to compile debug extend probes ===="
    export BUILD_OPTS="${@:-"$DEFAULT_BUILD_OPTS"}"
    echo "BUILD_OPTS is $BUILD_OPTS"
    cd ${EXT_PROBE_FOLDER}
    for BUILD_PATH in ${EXT_PROBE_BUILD_LIST}
    do
        echo "==== BUILD_PATH: " ${BUILD_PATH}
        sh ${BUILD_PATH} --build --debug || return 1
    done
}

function compile_extend_probes_release()
{
    # Search for build.sh in probe directory
    echo "==== Begin to compile release extend probes ===="
    export BUILD_OPTS="${@:-"$DEFAULT_BUILD_OPTS"}"
    echo "BUILD_OPTS is $BUILD_OPTS"
    cd ${EXT_PROBE_FOLDER}
    for BUILD_PATH in ${EXT_PROBE_BUILD_LIST}
    do
        echo "==== BUILD_PATH: " ${BUILD_PATH}
        sh ${BUILD_PATH} --build || return 1
    done
}


# Check dependent packages and install automatically
function prepare_dependence()
{
    for dep in "${DEP_LIST[@]}" ; do
        yum install -y $dep
        if [ $? -ne 0 ];then
            echo "Error: Failed to install $dep"
            return 1
        fi
    done

    return 0
}

function help()
{
    echo build.sh --help :Show this message.
    echo build.sh --check :Check the environment including arch/os/kernel/packages.
    echo build.sh --debug :Build gala-gopher debug version.
    echo build.sh --release :Build gala-gopher release version.
    echo build.sh --clean :Clean gala-gopher build objects.
}

if [ "$1" == "--help" ]; then
    help
    exit
fi

if [ "$1" == "--check" ]; then
    prepare_dependence
    if [ $? -ne 0 ];then
        echo "Error: prepare dependence softwares failed"
        exit 1
    fi
fi

if [ "$1" = "--release" ];then
    shift;
    load_tailor
    prepare_probes
    compile_lib || exit 1
    compile_daemon_release "$@" || exit 1
    compile_extend_probes_release "$@" || exit 1
    clean_env
    exit
fi

if [ "$1" = "--debug" ];then
    shift;
    load_tailor
    prepare_probes
    compile_lib || exit 1
    compile_daemon_debug "$@"|| exit 1
    compile_extend_probes_debug "$@" || exit 1
    clean_env
    exit
fi

if [ "$1" = "--clean" ];then
    compile_lib_clean
    compile_daemon_clean
    compile_extend_probes_clean
    exit
fi
help

