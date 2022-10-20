#!/bin/bash

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
	
	#find rpm
	junit_rpm=$( rpm -qa junit )
	if [ -z $junit_rpm ];
	then
        #install junit4
		yum install junit
	    junit_rpm=$( rpm -qa junit )
        if [ -z $junit_rpm ];
	    then
		    exit 1
        fi
	fi
	
	#junit.jar
	junit_jar=$( rpm -ql junit | grep junit.jar)
	if [ -e $junit_jar ];
    then
        cp $junit_jar lib/
    else
        echo "Error: junit.jar not found"
        return 1
    fi	

	#hamcrest.jar
	if [ -e $(dirname $junit_jar)/hamcrest/core.jar ];
    then
        cp $(dirname $junit_jar)/hamcrest/core.jar lib/
    else
        echo "Error: hamcrest.jar not found"
        return 1
    fi

	return 0
}

function  make_probe_jar()
{
	mkdir -p tmp
	javac -d tmp -cp lib/junit.jar:lib/core.jar:lib/tools.jar:../../../src/probes/extends/java.probe/jvm.probe/src src/*.java
	cd tmp

	if [ -z $(which jar 2>/dev/null) ];
	then 
		echo "Error: jar command not found"	
		return 1	
	else
		jar xf ../lib/tools.jar #>/dev/null 2>&1
		cp ../lib/management-agent.jar ./
		cd ..
		jar cfm JvmSuite.jar META-INF/MANIFEST.MF -C tmp/ . #2>/dev/null
        fi
	rm -rf tmp  2>/dev/null
}

function compile_clean()
{
	rm -rf lib 2>/dev/null
	rm -rf tmp 2>/dev/null
}

#main
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
  
    #install
    java -jar JvmSuite.jar
    
    rm -rf tmp 2>/dev/null
    exit
fi		
