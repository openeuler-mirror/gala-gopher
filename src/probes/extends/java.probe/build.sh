#!/bin/bash
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))
BUILD_FILES=${PRJ_DIR}/jvm.probe

#copy to specify dir
cd ${BUILD_FILES}
javac -classpath $JAVA_HOME/lib/tools.jar *.java


