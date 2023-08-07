#!/bin/bash
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))
JAVA_TAILOR_PROBES=$EXTEND_PROBES

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
    name="JvmProbeAgent"
    new_name="${name}$1"

    mkdir -p tmp
    cd tmp

    mkdir -p class
    cp ../src/agent/JvmProbeAgent.java .
    cp ../config/META-INF/MANIFEST.MF .

    # rename JvmProbeAgent class
    sed -i "s/${name}/${new_name}/" JvmProbeAgent.java
    sed -i "s/${name}/${new_name}/" MANIFEST.MF
    mv JvmProbeAgent.java "${new_name}.java"

    javac "${new_name}.java" -d ./class/ || return 1
    cd ..
    jar cfm "${new_name}.jar" tmp/MANIFEST.MF -C tmp/class/ . || return 1

    rm -rf tmp 2>/dev/null
    return 0
}

function make_jvmprobe_bin()
{
    make JAVA_AGENT_VER=$1 -s -C src/ || return 1
    return 0
}

function compile_jvmprobe()
{
    cd ${PRJ_DIR}/jvm.probe
    prefix="Manifest-Version: "
    version=$(head -n 1 config/META-INF/MANIFEST.MF | \
              sed -e "s/^$prefix//" | \
              sed -r 's/[\n\r]//g' | \
              sed -r 's/\./_/g')

    echo "Compile jvmProbeAgent...."
    make_jvmprobe_agent_jar $version || return 1

    echo "Compile jvmProbe...."
    make_jvmprobe_bin $version || return 1

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
if [[ $JAVA_TAILOR_PROBES =~ "jvm.probe" ]] ; then
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
    compile_jvmprobe || exit 1
    compile_clean
    exit
fi

