配置文件介绍
================

## 介绍

gala-gopher启动必须的外部参数通过配置文件定义；主要的配置项包括：设置数据上报周期、数据库信息、探针定义、cache数据库配置等；

## 配置文件详解

配置文件开发路径归档在 `A-Ops/gala-gopher/config/gala-gopher.conf`，安装路径 `/opt/gala-gopher/gala-gopher.conf`。

配置文件各部分详解如下：

### global

```shell
global =									# gala-gopher引擎配置
{
    log_directory = "gopher.log";	   # gala-gopher引擎日志路径
    log_level = "debug";	# gala-gopher日志级别，可配置 "debug|info|error|warnning|fatal"
    pin_path = "/sys/fs/bpf/probe";	   # 共享map存放路径，建议维持默认配置
};
```

### metric

```shell
metric =									# 用于配置metrics指标数据输出方式
{
    out_channel = "web_server";  # metric输出通道，支持web_server|kafka，配置为空或者其他字符串不输出
    kafka_topic = "gala_gopher"; # 若输出通道为kafka，此为topic配置信息
};
```

### event

```shell
event =										# 用于配置异常事件数据输出方式
{
    out_channel = "kafka";       # event输出通道，支持logs|kafka，配置为空或者其他字符串则不输出
    kafka_topic = "gala_gopher_event";      # 若输出通道为kafka，此为topic配置信息
};
```

### meta

```shell
meta =										# 用于配置元数据输出方式
{
    out_channel = "kafka";       # metadata输出通道，支持logs|kafka，配置为空或者其他字符串则不输出
    kafka_topic = "gala_gopher_metadata";   # 若输出通道为kafka，此为topic配置信息
};
```

### ingress 

```shell
ingress =									# 数据采集相关配置
{
    interval = 5;		# 探针数据采集周期(s)，如每5s触发探针数据采集
};
```

### egress

```shell
egress =									# 数据上报相关配置
{
    interval = 5;		# 探针数据上报egress的周期(s)
    time_range = 5;		# 未用
};
```

### imdb

```shell
imdb =										# cache缓存规格，定义了支持的指标项规格
{
    max_tables_num = 1024;   # cache最大支持的表个数，/opt/gala-gopher/meta目录下每个meta对应一个表
    max_records_num = 1024;	 # 每张cache表最大记录数，通常每个探针在一个观测周期内产生至少1条观测记录
    max_metrics_num = 1024;	 # metric最大个数，定义了每条观测记录最大的metric指标个数
    record_timeout = 60;     # 单位为秒，cache表老化时间，若某条记录超过该时间未更新，则删除
};
```

### webServer配置

gala-gopher可以启动一个webServer，对外提供查询metric指标的接口，promethous可以基于该接口查询指标信息。

```shell
web_server =
{
    port = 8888;		# 监听端口
};
```

### kafka配置

gala-gopher支持配置为kafka客户端，作为生产者将采集的数据上送kafka，用户可以通过消费kafka数据获取采集的指标数据。

```shell
kafka =
{
    kafka_broker = "localhost:9092";
    batch_num_messages = 10000;	    # 在一个MessageSet中批处理的最大消息数
    compression_codec = "none";	    # 用于压缩消息集的压缩编解码器：none、gzip 或 snappy
    queue_buffering_max_messages = 100000;	# 生产者队列上允许的最大消息数
    queue_buffering_max_kbytes = 1048576;	# 生产者队列上允许的最大byte数(kB)
    queue_buffering_max_ms = 5;	    # 生产者队列上缓冲数据的最长时间(毫秒)
};
```

### logs配置

```shell
logs =
{
    metric_dir = "/var/log/gala-gopher/metrics";    # metrics指标数据日志路径
    event_dir = "/var/log/gala-gopher/event";       # 异常事件数据日志路径
    meta_dir = "/var/log/gala-gopher/meta";         # metadata元数据日志路径
    debug_dir = "/var/log/gala-gopher/debug";       #gala-gopher运行日志路径
};
```

### probes 

```shell
probes =								# native探针配置，定义gala-gopher需要启动的探针
(
    {
        name = "example";  # 探针名称，要求与native探针名一致，如example.probe 探针名为example
        switch = "on";     # 运行时是否启动，支持配置 on | off
        interval = 1;      # 探针执行周期(s)
    },
    {
        name = "system_net";
        switch = "on";     # 'on'表示gala-gopher运行时会启动该探针
        interval = 2;
    },
    ... ...
);
```

### extend_probes

```shell
extend_probes =							# 三方探针开关配置
(
    {
        name = "tcp";            # 探针名称
        command = "/opt/gala-gopher/extend_probes/tcpprobe";  # 探针启动命令
        param = "";              # 探针启动参数，支持设置执行周期(-t)、可执行文件路径(-p uprobe使用)
        switch = "on";           # 运行时是否启动，支持配置 on | off | auto
    },
    {
        name = "lvs";
        command = "/opt/gala-gopher/extend_probes/trace_lvs";
        param = "";
        start_check = "lsmod | grep ip_vs | wc -l"; # switch为auto时，需要根据start_check执行结果判定探针是否需要启动
        check_type = "count"；  # start_check执行结果的检查类型，count：执行结果>0，启动探针
        switch = "auto";        # auto表示根据start_check判定结果决定是否启动探针
    },
    {
        name = "task";
        command = "/opt/gala-gopher/extend_probes/taskprobe";
        param = "-w /opt/gala-gopher/task_whitelist.conf";	# -w选项用于给task探针指定白名单，用户可以将想要观测的函数名写入配置文件
        switch = "on";
    },
    ... ...
);
```
