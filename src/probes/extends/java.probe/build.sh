#!/bin/bash
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))
BUILD_FILES=${PRJ_DIR}/jvm.probe
cd ${BUILD_FILES}

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

function make_probe_agent_jar()
{
    mkdir -p tmp
    cd tmp
    javac ../src/agent/JvmProbeAgent.java -d ./
    cd ..
    jar cfm JvmProbeAgent.jar src/agent/config/META-INF/MANIFEST.MF -C tmp/ .

    rm -rf tmp 2>/dev/null
    return 0
}

function make_probe_jar()
{
    mkdir -p tmp
    cd tmp/
    javac ../src/JvmProbe.java -d .
    cd ..
    jar cfm JvmProbe.jar config/META-INF/MANIFEST.MF -C tmp/ .

    rm -rf tmp 2>/dev/null
    return 0
}

function compile_clean()
{
    rm -rf tmp 2>/dev/null
}

if [ "$1" == "-c"  -o  "$1" == "--clean" ];
then
    compile_clean
    rm -f *.jar 2>/dev/null
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

    make_probe_agent_jar
    if [ $? -eq 1 ];
    then
        exit 1
    fi

    make_probe_jar
    if [ $? -eq 1 ];
    then
        exit 1
    fi

    compile_clean
    exit
fi

