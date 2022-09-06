#!/bin/bash

CONSUMERS_IP_LIST=
PRODUCTORS_IP_LIST=
RABBITMQ_IP=

LOOP_SECS=5
LOOP_SECS_MIN=1
LOOP_SECS_MAX=3600

function check_rabbitmq_ok()
{
    return `rabbitmqctl ping | grep succeeded | wc -l`
}

function probe_rabbitmq_info()
{
    # 检查rabbitmq状态
    check_rabbitmq_ok
    if [ $? -ne 1 ];then
        return 1
    fi
    
    # 获取rabbitmq的生产者、消费者列表
    CONS_PIDS=`rabbitmqctl list_consumers channel_pid --quiet --no-table-headers | xargs | sed 's/> </>|</'`
    #echo "CONS_PIDS: "${CONS_PIDS}

    # 获取通道信息
    CHANNELS=`rabbitmqctl list_channels name pid --quiet --no-table-headers`
    #echo ${CHANNELS}

    # rabbitmq ip为空，则获取
    if [ -z "${RABBITMQ_IP}" ];then
        RABBITMQ_IP=`echo "${CHANNELS}" | awk -F ' -> ' '{print $2}' | awk -F ' ' '{print $1}' | sort -n | uniq`
        if [ -z "${RABBITMQ_IP}" ];then
            # rabbitmq环境没有起好
            return 1
        fi
    fi
    
    # 获取消费者IP列表
    if [ -n "${CONS_PIDS}" ];then
        CONSUMERS_IP_LIST=`echo "${CHANNELS}" | grep -E ${CONS_PIDS} | awk -F ' -> ' '{print $1}' | awk -F ':' '{print $1}' | sort -n | uniq`
    fi
    #echo "CONSUMERS_IP_LIST: "${CONSUMERS_IP_LIST}

    # 获取生产者IP列表
    if [ -z "${CONS_PIDS}" ];then
        PRODUCTORS_IP_LIST=`echo "${CHANNELS}" | awk -F ' -> ' '{print $1}' | awk -F ':' '{print $1}' | sort -n | uniq`
    else
        PRODUCTORS_IP_LIST=`echo "${CHANNELS}" | grep -Ev ${CONS_PIDS} | awk -F ' -> ' '{print $1}' | awk -F ':' '{print $1}' | sort -n | uniq`
    fi
    #echo "PRODUCTORS_IP_LIST: "${PRODUCTORS_IP_LIST}

    #echo $(date "+%Y-%m-%d %H:%M:%S")"|rabbitmq_probe|"${RABBITMQ_IP}"|"${PRODUCTORS_IP_LIST}"|"${CONSUMERS_IP_LIST}
    echo "|rabbitmq_probe|"${RABBITMQ_IP}"|"${PRODUCTORS_IP_LIST}"|"${CONSUMERS_IP_LIST}

    # reset

}

function set_observe_cycle()
{
    # 按指定的观测周期探测rabbitmq $1 为观测秒数
    if [ $# = 1 ];then
        if [ "$1" -gt "${LOOP_SECS_MAX}" ] || [ "$1" -lt "${LOOP_SECS_MIN}" ];then
            echo "Error: observation period range: [${LOOP_SECS_MIN}, ${LOOP_SECS_MAX}]"
            return 1
        fi
        LOOP_SECS=$1
    fi
    return 0
}

# start observe
set_observe_cycle $@
if [ $? -ne 0 ];then
    exit
fi

while true
do
    probe_rabbitmq_info
    sleep ${LOOP_SECS}
done

