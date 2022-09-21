#!/bin/bash
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))
BUILD_FILES=${PRJ_DIR}/jvm.probe
cd ${BUILD_FILES}

if [ "$1" == "-c"  -o  "$1" == "--clean" ];
then
    rm -rf *.class
    exit
fi

java_link=$(which java 2>/dev/null)
javac_link=$(which javac 2>/dev/null)
	
if [ -z $java_link ] && [ -z $javac_link ]; 
then
    echo "java and javac : command not found"
    exit 1
else
    if [ -z $JAVA_HOME ];
    then
        # find jdk
        link_path=$(echo $(ls -lrt $javac_link) | awk -F " " '{print $NF}' )
        link_path=$(echo $(ls -lrt $link_path) | awk -F " " '{print $NF}' )
        jdk_path=$(dirname $(dirname $link_path))
        dir=$jdk_path/lib
    else
        dir=$JAVA_HOME/lib
    fi

    #tools.jar 
    if [ -e $dir/tools.jar ]; 
    then
        javac -cp $dir/tools.jar JvmProbe.java Vm.java
    else
        echo "tools.jar not found"
        exit 1
    fi 
fi
