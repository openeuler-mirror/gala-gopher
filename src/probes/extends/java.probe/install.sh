#!/bin/bash
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))
INSTALL_FILES=${PRJ_DIR}/jvm.probe
cd ${INSTALL_FILES}

	if [ $# -eq 1 ]; then    
	  	  \cp JvmProbe.jar $1
	fi
	 

