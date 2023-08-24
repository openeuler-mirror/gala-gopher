#!/bin/bash
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))
JAVA_TAILOR_PROBES=$EXTEND_PROBES
JAVA_VER=$(java -version 2>&1 |awk 'NR==1{gsub(/"/,"");print $3}')
JAVA_VER_MAJOR=$(echo ${JAVA_VER} | awk -F'.' '{print $1}')
JAVA_VER_MINOR=$(echo ${JAVA_VER} | awk -F'.' '{print $2}')

# java version > 8u272
function check_jfr_supported()
{
    if [ "$JAVA_VER_MAJOR" -gt 1 ] || [ "$JAVA_VER_MINOR" -gt 8 ];then
        return 1
    fi

    if [ "$JAVA_VER_MINOR" -eq 8 ] && [ "$(echo ${JAVA_VER} | awk -F'_' '{print $2}')" -ge 272 ];then
        return 1
    fi

    return 0
}

function find_cmd_jar()
{
    if [ -z $(which jar 2>/dev/null) ];
    then
        echo "Error: jar command not found"
        return 1
    else
        return 0
    fi
}

function make_jstackprobe_jar()
{
    mkdir -p tmp
    cd tmp
    javac ../src/*.java -d ./ || return 1
    cd ..
    jar cfm JstackProbeAgent.jar config/META-INF/MANIFEST_AGENT.MF -C tmp/ . || return 1
    jar cfm JstackPrinter.jar config/META-INF/MANIFEST_PRINTER.MF -C tmp/ . || return 1
    rm -rf tmp 2>/dev/null
    return 0
}

function compile_jstackprobe()
{
    cd ${PRJ_DIR}/jstack.probe
    echo "Compile JstackProbeAgent...."
    make_jstackprobe_jar || return 1
    echo "JstackProbeAgent compiling completed."
    cd ${PRJ_DIR}
    return 0
}

function make_jvmprobe_agent_jar()
{
    mkdir -p tmp
    cd tmp
    javac ../src/agent/JvmProbeAgent.java -d ./ || return 1
    cd ..
    jar cfm JvmProbeAgent.jar config/META-INF/MANIFEST.MF -C tmp/ . || return 1

    rm -rf tmp 2>/dev/null
    return 0
}

function make_jvmprobe_bin()
{
    make -s -C src/ || return 1
    return 0
}

function compile_jvmprobe()
{
    cd ${PRJ_DIR}/jvm.probe
    echo "Compile jvmProbeAgent...."
    make_jvmprobe_agent_jar || return 1

    echo "Compile jvmProbe...."
    make_jvmprobe_bin || return 1
    echo "jvmProbeAgent compiling completed."
    cd ${PRJ_DIR}
    return 0
}

function make_jsseprobe_agent_jar()
{
    mkdir -p tmp
    cd tmp
    javac -XDignore.symbol.file=true ../src/*.java -d .
    cd ..
    jar cfm JSSEProbeAgent.jar config/META-INF/MANIFEST.MF -C tmp/ .

    rm -rf tmp 2>/dev/null
    return 0
}

function compile_jsseprobe()
{
    cd ${PRJ_DIR}/jsse.probe
    echo "Compile jsseProbeAgent...."
    make_jsseprobe_agent_jar
    echo "jsseProbeAgent compiling completed."
    cd ${PRJ_DIR}
    return 0
}

function compile_clean()
{
    rm -rf tmp 2>/dev/null
}

if [ "$1" == "-c"  -o  "$1" == "--clean" ];
then
    compile_clean
    find ${PRJ_DIR} -name "*.jar" -type f -delete 2>/dev/null
    for app in $(find . -name Makefile -type f); do
        make -s clean -C $(dirname $app)
    done
    exit
fi

# tailor jvmprobe
if [[ $JAVA_TAILOR_PROBES =~ "jvm.probe" ]] && [[ $JAVA_TAILOR_PROBES =~ "l7probe" ]] && [[ $JAVA_TAILOR_PROBES =~ "stackprobe" ]]; then
    exit
fi

java_link=$(which java 2>/dev/null)
javac_link=$(which javac 2>/dev/null)

if [ -z $java_link ] || [ -z $javac_link ];
then
    echo "Error: java and javac : command not found"
    exit 1
else
    find_cmd_jar
    if [ $? -eq 1 ];
    then
        exit 1
    fi
    if ! [[ $JAVA_TAILOR_PROBES =~ "jvm.probe" ]] ; then
        compile_jvmprobe || exit 1
    fi

    if ! [[ $JAVA_TAILOR_PROBES =~ "l7probe" ]] ; then
        compile_jsseprobe || exit 1
    fi

    if ! [[ $JAVA_TAILOR_PROBES =~ "stackprobe" ]] ; then
        check_jfr_supported
        if [ $? -eq 1 ];
        then
            compile_jstackprobe || exit 1
        else
            echo "JFR not supoprted in ${JAVA_VER}. Won't compile the jstackprobe."
        fi
        
    fi

    compile_clean
    exit
fi

