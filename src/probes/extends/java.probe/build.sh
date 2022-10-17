#!/bin/bash
PROGRAM=$0
PRJ_DIR=$(dirname $(readlink -f "$0"))
BUILD_FILES=${PRJ_DIR}/jvm.probe
cd ${BUILD_FILES}

function find_jars()
{
    if [ -z $JAVA_HOME ];
	then
		# find jdk
		clink_path=$(echo $(ls -lrt $javac_link) | awk -F " " '{print $NF}' )
		link_path=$(echo $(ls -lrt $link_path) | awk -F " " '{print $NF}' )
		jdk_path=$(dirname $(dirname $link_path))
		dir=$jdk_path
	else
		dir=$JAVA_HOME
	fi

	#tools.jar 
	if [ -e $dir/lib/tools.jar ]; 
	then
		mkdir -p lib
		cp $dir/lib/tools.jar lib/
	else
		echo "Error: tools.jar not found"
		return 1
	fi 

	#management.jar 
    if [ -e $dir/jre/lib/management-agent.jar ]; 
    then
        cp $dir/jre/lib/management-agent.jar lib/
    else
        echo "Error: management-agent.jar not found"
        return 1
	fi 
	
	return 0
}

function  make_probe_jar()
{
	mkdir -p tmp
	cd tmp
	javac -cp ../lib/tools.jar ../src/*.java -d ./

	if [ -z $(which jar 2>/dev/null) ];
	then 
		echo "Error: jar command not found"	
		return 1	
	else
		jar xf ../lib/tools.jar #>/dev/null 2>&1
		cp ../lib/management-agent.jar ./
		cd ..
		jar cfm JvmProbe.jar config/META-INF/MANIFEST.MF -C tmp/ . #2>/dev/null 
	fi

	rm -rf tmp  2>/dev/null
 
	return 0
}

function compile_clean()
{
	rm -rf lib 2>/dev/null
	rm -rf tmp 2>/dev/null
}

if [ "$1" == "-c"  -o  "$1" == "--clean" ];
then
    compile_clean
    exit
fi

java_link=$(which java 2>/dev/null)
javac_link=$(which javac 2>/dev/null)
	
if [ -z $java_link ] || [ -z $javac_link ]; 
then
    echo "Error: java and javac : command not found"
    exit 1
else 
    find_jars	
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

