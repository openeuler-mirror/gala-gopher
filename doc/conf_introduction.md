配置文件介绍
================

gala-gopher启动必须的外部参数通过配置文件定义；主要的配置项包括：设置数据上报周期、数据库信息、探针定义、cache数据库配置等。

## 配置介绍

配置文件归档在[config目录](../config)，安装路径 `/opt/gala-gopher/gala-gopher.conf`。该文件配置项说明如下：

- global：gala-gopher全局配置信息
  - log_directory：gala-gopher日志文件名
  - log_level：gala-gopher日志级别（暂未开放此功能）
  - pin_path：ebpf探针共享map存放路径（建议维持默认配置）

- metric：指标数据metrics输出方式配置
  - out_channel：metrics输出通道，支持配置web_server|kafka，配置为空则输出通道关闭
  - kafka_topic：若输出通道为kafka，此为topic配置信息

- event：异常事件event输出方式配置
  - out_channel：event输出通道，支持配置logs|kafka，配置为空则输出通道关闭
  - kafka_topic：若输出通道为kafka，此为topic配置信息

- meta：元数据metadata输出方式配置
  - out_channel：metadata输出通道，支持logs|kafka，配置为空则输出通道关闭
  - kafka_topic：若输出通道为kafka，此为topic配置信息

- ingress：探针数据上报相关配置
  - interval：暂未使用

- egress：上报数据库相关配置
  - interval：暂未使用
  - time_range：暂未使用

- imdb：cache缓存规格配置
  - max_tables_num：最大的cache表个数，/opt/gala-gopher/meta目录下每个meta对应一个表
  - max_records_num：每张cache表最大记录数，通常每个探针在一个观测周期内产生至少1条观测记录
  - max_metrics_num：每条观测记录包含的最大的metric指标个数
  - record_timeout：cache表老化时间，若cache表中某条记录超过该时间未刷新则删除记录，单位为秒
- web_server：输出通道web_server配置
  - port：监听端口
- kafka：输出通道kafka配置
  - kafka_broker：kafka服务器的IP和port
- logs：输出通道logs配置
  - metric_dir：metrics指标数据日志路径
  - event_dir：异常事件数据日志路径
  - meta_dir：metadata元数据日志路径
  - debug_dir：gala-gopher运行日志路径

- probes：native探针配置
  - name：探针名称，要求与native探针名一致，如example.probe 探针名为example
  - param ：探针启动参数，支持的参数详见[启动参数介绍表](#启动参数介绍)
  - switch：探针是否启动，支持配置 on | off
- extend_probes ：第三方探针配置
  - name：探针名称
  - command：探针启动命令
  - param：探针启动参数，支持的参数详见[启动参数介绍表](#启动参数介绍)
  - start_check：switch为auto时，需要根据start_check执行结果判定探针是否需要启动
  - switch：探针是否启动，支持配置on | off | auto，auto会根据start_check判定结果决定是否启动探针



## 启动参数介绍

配置文件中`probes`和`extend_probes`部分`param`字段用于设置各个探针启动参数，启动参数介绍如下：

| 参数项 | 含义                                                         |
| ------ | ------------------------------------------------------------ |
| -l     | 是否开启异常事件上报                                         |
| -t     | 采样周期，单位为秒，默认配置为探针5s上报一次数据             |
| -T     | 延迟时间阈值，单位为ms，默认配置为0ms，用于异常事件          |
| -J     | 抖动时间阈值，单位为ms，默认配置为0ms，用于异常事件          |
| -O     | 离线时间阈值，单位为ms，默认配置为0ms，用于异常事件          |
| -D     | 丢包阈值，默认配置为0(个)，用于异常事件                      |
| -F     | 配置为`task`表示按照`task_whitelist.conf`过滤；配置为具体进程的pid表示仅监控此进程 |
| -P     | 指定每个探针加载的探测程序范围，目前tcpprobe、taskprobe探针涉及 |
| -U     | 资源利用率阈值(上限)，默认为0%，用于异常事件                 |
| -L     | 资源利用率阈值(下限)，默认为0%，用于异常事件                 |
| -c     | 指示探针(tcp)是否标识client_port，默认配置为0(否)            |
| -C     | 指定探针(ksliprobe)是否开启周期采样，增加该参数则连续采集数据，不加该参数则周期性(如5s)采样一次 |
| -p     | 指定待观测进程的二进制文件路径，比如nginx_probe，通过 -p /user/local/sbin/nginx指定nginx文件路径，默认配置为NULL |
| -w     | 筛选应用程序监控范围，如-w  /opt/gala-gopher/task_whitelist.conf，用户可将需要监控的程序名写入task_whitelist.conf中，默认配置为NULL表示不筛选，system_infos、taskprobe探针涉及 |
| -n     | 指定某个网卡挂载tc ebpf，默认配置为NULL表示所有网卡均挂载；示例： -n eth0 |

> 说明：上表中某些参数用于异常事件，目前异常事件范围参考[系统异常范围](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech_abnormal.md)。



## 示例

```yaml
global =
{
    log_file_name = "gopher.log";
    log_level = "debug";
    pin_path = "/sys/fs/bpf/probe";
};

metric =
{
    out_channel = "web_server";     # 设置metrics采用web上报方式
    kafka_topic = "gala_gopher";
};

event =
{
    out_channel = "kafka";          # 设置event采用kafka上报方式
    kafka_topic = "gala_gopher_event";  # kafka方式下，对应的topic信息
};

meta =
{
    out_channel = "logs";           # 设置metadata采用logs上报方式
    kafka_topic = "gala_gopher_metadata";
};

ingress =
{
    interval = 5;
};

egress =
{
    interval = 5;
    time_range = 5;
};

imdb =
{
    max_tables_num = 1024;
    max_records_num = 1024;
    max_metrics_num = 64;
    record_timeout = 60;
};

web_server =
{
    port = 8888;
};

kafka =
{
    kafka_broker = "10.137.10.xx:9092";
    batch_num_messages = 10000;
    compression_codec = "none";
    queue_buffering_max_messages = 100000;
    queue_buffering_max_kbytes = 1048576;
    queue_buffering_max_ms = 5;
};

logs =
{
    metric_dir = "/var/log/gala-gopher/metrics";
    event_dir = "/var/log/gala-gopher/event";
    meta_dir = "/var/log/gala-gopher/meta";
    debug_dir = "/var/log/gala-gopher/debug";
};

probes =                             # 仅列出switch为on的探针
(
    {
        name = "system_infos";
        param = "-t 5 -w /opt/gala-gopher/task_whitelist.conf -l warn -U 80";
        switch = "on";
    }
);

extend_probes =
(
    {
        name = "tcp";
        command = "/opt/gala-gopher/extend_probes/tcpprobe";
        param = "-l warn -c 1 -P 7";
        switch = "on";              # tcp探针默认开启
    },
    {
        name = "lvs";
        command = "/opt/gala-gopher/extend_probes/trace_lvs";
        param = "";
        start_check = "lsmod | grep ip_vs | wc -l";
        check_type = "count";
        switch = "auto";            # 仅在当前环境有ip_vs.ko的时候开启lvs探针
    },
    {
        name = "task";
        command = "/opt/gala-gopher/extend_probes/taskprobe";
        param = "-w /opt/gala-gopher/task_whitelist.conf -P 3174";
        switch = "on";
    }
);
```