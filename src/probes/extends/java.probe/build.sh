#!/bin/bash
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))
BUILD_FILES=${PRJ_DIR}/jvm.probe
cd ${BUILD_FILES}

if [ !$JAVA_HOME ];then

	java_link=$(which java)
	link_path=$(echo $(ls -lrt $java_link) | awk -F " " '{print $NF}' )
	link_path=$(echo $(ls -lrt $link_path) | awk -F " " '{print $NF}' )
	jdk_path=$(dirname $(dirname $link_path))
	javac -cp $jdk_path/lib/tools.jar *.java

else
	javac -cp $JAVA_HOME/lib/tools.jar *.java

fi
