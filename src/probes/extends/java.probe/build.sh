#!/bin/bash
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))

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

function make_jvmprobe_agent_jar()
{
    mkdir -p tmp
    cd tmp
    javac ../src/agent/JvmProbeAgent.java -d ./
    cd ..
    jar cfm JvmProbeAgent.jar config/META-INF/MANIFEST.MF -C tmp/ .

    rm -rf tmp 2>/dev/null
    return 0
}

function make_jvmprobe_bin()
{
    make -s -C src/
    return 0
}

function compile_jvmprobe()
{
    cd ${PRJ_DIR}/jvm.probe
    echo "Compile jvmProbeAgent...."
    make_jvmprobe_agent_jar
    
    echo "Compile jvmProbe...."
    make_jvmprobe_bin

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
    # ½ö°üº¬agent
    cd ${PRJ_DIR}/jsse.probe
    echo "Compile jsseProbeAgent...."
    make_jsseprobe_agent_jar

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
    compile_jvmprobe
    compile_jsseprobe
    compile_clean
    exit
fi

