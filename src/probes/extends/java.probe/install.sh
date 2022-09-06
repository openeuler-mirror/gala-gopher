#!/bin/bash
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))
INSTALL_FILES=${PRJ_DIR}/jvm.probe

if [ $# -eq 1 ]; then    
   cd ${INSTALL_FILES}
   for file in ${INSTALL_FILES}/*; do
       if [ "${file##*.}" = "class" ]; 
       then
		  \cp ${file} $1
       fi
   done
fi

rm -rf *.class  
