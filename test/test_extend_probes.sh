#!/bin/bash

PROGRAM=$0
PROJECT_FOLDER=$(dirname $(readlink -f "$0"))
PROBES_FOLDER=${PROJECT_FOLDER}/test_extend_probes
JVMPROBE_FOLDER=${PROBES_FOLDER}/java_probe
   
function run_java_test()
{
    cd ${JVMPROBE_FOLDER}
    echo "==== Begin to test java probes ====" 
    sh java_probes_test.sh
}

run_java_test
