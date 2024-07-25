#!/bin/bash
if [ "$1" == "stop" ]; then
    echo "Info: stop gala-gopher"
    systemctl stop gala-gopher
    exit
fi

if [ "$1" == "uninstall" ]; then
    echo "Info: uninstall gala-gopher"
    yum remove -y gala-gopher
    exit
fi

if [ "$1" == "start" ]; then
    echo "Info: try to start gala-gopher"
    ps -ef | grep "/usr/bin/gala-gopher" | grep -v grep 2>&1 >/dev/null
    if [ $? -ne 0 ] ; then
        echo "Info: staring gala-gopher"
        systemctl start gala-gopher
        systemctl enable gala-gopher
        sleep 3
    fi

    exit
fi

if [ "$1" == "install" ]; then
    echo "Info: try to install gala-gopher"
    rpm -qa | grep gala-gopher | grep -v grep 2>&1 >/dev/null
    if [ $? -ne 0 ] ; then
        echo "Info: installing gala-gopher"
        rm -f gala-gopher-2.0.2-1.x86_64.rpm
        wget -q http://xxxxx/gala-gopher-2.0.2-1.x86_64.rpm
        yum localinstall -y gala-gopher-2.0.2-1.x86_64.rpm
        rm -f gala-gopher-2.0.2-1.x86_64.rpm
    fi
fi

