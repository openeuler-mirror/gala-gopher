#!/bin/bash
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))
JAVA_TAILOR_PROBES=$EXTEND_PROBES

INSTALL_FILES=""
META_FILES=""

while getopts ":b:c:m:" opt
do
    case $opt in
        b) INSTALL_PATH=$OPTARG;;
        c) CONF_PATH=$OPTARG;;
        m) META_PATH=$OPTARG;;
        ?) echo "unknow param"; exit 1;;
    esac
done

cd ${PRJ_DIR}
prefix="Manifest-Version: "
version=$(head -n 1 jvm.probe/config/META-INF/MANIFEST.MF | \
        sed -e "s/^$prefix//" | \
        sed -r 's/[\n\r]//g' | \
        sed -r 's/\./_/g')
# tailor jvmprobe
if ! [[ $JAVA_TAILOR_PROBES =~ "jvm.probe" ]] ; then
    INSTALL_FILES+=" jvm.probe/src/jvmprobe"
    INSTALL_FILES+=" jvm.probe/JvmProbeAgent${version}.jar"
    META_FILES+=" jvm.probe/jvm_probe.meta"
fi

# tailor jsseprobe jar when tailoring l7probe
if ! [[ $JAVA_TAILOR_PROBES =~ "l7probe" ]] ; then
    INSTALL_FILES+=" jsse.probe/JSSEProbeAgent.jar"
fi

# tailor jstackprobe jar when tailoring stackprobe
if ! [[ $JAVA_TAILOR_PROBES =~ "stackprobe" ]] ; then
    INSTALL_FILES+=" jstack.probe/JstackProbeAgent.jar"
    INSTALL_FILES+=" jstack.probe/JstackPrinter.jar"
fi

mkdir -p ${INSTALL_PATH}
for file in ${INSTALL_FILES}; do
    cp ${file} ${INSTALL_PATH}
done

mkdir -p ${META_PATH}
for file in ${META_FILES}; do
    cp ${file} ${META_PATH}
done