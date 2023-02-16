配置文件介绍
================

gala-gopher启动必须的外部参数通过配置文件`gala-gopher.conf`定义；主要的配置项包括：设置数据上报周期、数据库信息、探针定义、cache数据库配置等。

gala-gopher支持用户配置观测的应用范围，即支持用户设置关注的、需要监测的具体应用，此项配置是在`gala-gopher-app.conf`配置文件中配置。

部分extend探针有自己的配置文件，开启该探针前需要设置好探针的配置文件。

## 配置介绍

配置文件归档在[config目录](../config)。

extend探针配置文件归档在探针同级目录下。目前有配置文件的探针有:

[stackprobe](../src/probes/extends/ebpf.probe/src/stackprobe)

[cadvisor.probe](../src/probes/extends/python.probe/cadvisor.probe)

[pg_stat.probe](../src/probes/extends/python.probe/pg_stat.probe)

### gala-gopher.conf

`gala-gopher.conf`文件的安装路径为 `/etc/gala-gopher/gala-gopher.conf`。该文件配置项说明如下：

- global：gala-gopher全局配置信息
  - log_directory：gala-gopher日志文件名
  - log_level：gala-gopher日志级别（暂未开放此功能）
  - pin_path：ebpf探针共享map存放路径（建议维持默认配置）

- metric：指标数据metrics输出方式配置
  - out_channel：metrics输出通道，支持配置web_server|logs|kafka，配置为空则输出通道关闭
  - kafka_topic：若输出通道为kafka，此为topic配置信息

- event：异常事件event输出方式配置
  - out_channel：event输出通道，支持配置logs|kafka，配置为空则输出通道关闭
  - kafka_topic：若输出通道为kafka，此为topic配置信息
  - timeout：同一异常事件上报间隔设置
  - desc_language：异常事件描述信息语言选择，当前支持配置zh_CN|en_US

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



### gala-gopher-app.conf

`gala-gophe-app.conf`文件的安装路径为 `/etc/gala-gopher/gala-gopher-app.conf`。该文件配置项说明如下：

- application：gala-gopher的应用观测范围配置
  - comm：应用进程的进程名
  - cmdline：应用进程的进程命令行

**该如何配置应用观测范围呢？**

1. 请将需要观测的进程信息新增到 `application` 下；默认配置提供了部分运行时、业界知名应用的配置，如果不需要观测这些应用，请删除这些配置项；
2. 对于每一个应用， `comm` 项为必须配置的项；
3. 应用进程名`comm`支持正则匹配，请提供满足正则表达式规则的进程名信息，如：配置 `comm = "redis*"`会监控所有进程名以redis开头的进程，配置`^nginx$` 则仅监控进程名为nginx的进程；
4. 应用进程命令行`cmdline`配置的最大长度不可超过128，支持模糊匹配，即支持cmdline配置部分的、连续的字符串进行匹配；如：想要监控某python进程，对应的cmdline为 `python3 test_server.py` ，则配置 `cmdline = "server"` 即可成功匹配；
5. 大部分情况下，可以仅通过应用进程名`comm`信息来唯一标识应用，那么不再需要配置`cmdline`部分，置为空表示不根据cmdline匹配；

配置示例参见 [gala-gopher-app.conf示例](#gala-gopher-app.conf示例) 。


### stackprobe.conf

`stackprobe.conf`文件的安装路径为 `/etc/gala-gopher/extend_probes/stackprobe.conf`。该文件配置项说明如下：

- general：通用设置
  - whitelist_enable：使能进程白名单
  - period：火焰图生成周期
  - log_dir：stackprobe探针日志路径
  - svg_dir：svg格式火焰图存储路径
  - flame_dir：堆栈信息存储路径
  - debug_dir：调试信息文件路径
- flame_name：各类型火焰图开关
  - oncpu：oncpu火焰图开关
  - offcpu：offcpu火焰图开关
  - io：io火焰图开关
  - memleak：内存泄漏火焰图开关
- application：暂未使用


### cadvisor_probe.conf

`cadvisor_probe.conf`文件的安装路径为 `/etc/gala-gopher/extend_probes/cadvisor_probe.conf`。该文件配置项说明如下：

- version：配置文件版本号
- measurements：待集成到gala-gopher的观测指标
  - table_name: 数据表名称
  - entity_name: 观测对象名称
  - fields：数据字段
    - description：数据字段描述信息
    - type：数据字段类型，需和cAdvisor上报数据类型一致
    - name：数据字段名称，需和cAdvisor上报数据名称一致

> 说明：cadvisor_probe.conf和cadvisor_probe.meta的字段需要一致。例外：若conf中type字段为counter，在meta中对应type字段应为gauge


### pg_stat_probe.conf

`pg_stat_probe.conf`文件的安装路径为 `/etc/gala-gopher/extend_probes/pg_stat_probe.conf`。该文件配置项说明如下：

- servers：PostgreSQL服务端配置
  - ip：服务端IP
  - port：服务端端口
  - dbname：服务端任意数据库名称
  - user：用户名
  - password：用户密码

上述配置用户需能够访问pg_stat_database视图，配置最小权限的命令如下：

PostgreSQL：
```shell
grant SELECT ON pg_stat_database to <USER>;
grant pg_monitor to <USER>;
```

GaussDB：
```shell
grant usage on schema dbe_perf to <USER>;
grant select on pg_stat_replication to <USER>;
```



## 启动参数介绍

配置文件中`probes`和`extend_probes`部分`param`字段用于设置各个探针启动参数，启动参数介绍如下：

| 参数项 | 含义                                                         |
| ------ | ------------------------------------------------------------ |
| -l     | 是否开启异常事件上报，目前仅支持warn                         |
| -t     | 上报周期，单位为秒，默认配置为探针5s上报一次数据             |
| -s     | 采样周期，单位为毫秒，默认配置为探针100ms采集一次数据        |
| -T     | 延迟时间阈值，单位为ms，默认配置为0ms，用于异常事件          |
| -J     | 抖动时间阈值，单位为ms，默认配置为0ms，用于异常事件          |
| -O     | 离线时间阈值，单位为ms，默认配置为0ms，用于异常事件          |
| -D     | 丢包阈值，默认配置为0(个)，用于异常事件                      |
| -F     | 1）配置为`task`表示按照`gala-gopher-app.conf`过滤；2）配置为具体进程的pid表示仅监控此进程；3）配置为进程名表示基于进程名范围监控。 |
| -P     | 指定每个探针加载的探测程序范围，目前tcpprobe、taskprobe探针涉及 |
| -U     | 资源利用率阈值(上限)，默认为0%，用于异常事件                 |
| -L     | 资源利用率阈值(下限)，默认为0%，用于异常事件                 |
| -c     | 指示探针(tcp)是否采集client_port，默认配置为0(否)            |
| -p     | 指定待观测进程的二进制文件路径，比如nginx_probe，通过 -p /user/local/sbin/nginx指定nginx文件路径，默认配置为NULL |
| -d     | 制定目标设备，包括磁盘、网卡等。示例：-d eth0                |
| -C     | 指定探针(ksliprobe)是否开启周期采样，增加该参数则连续采集数据，不加该参数则周期性(如5s)采样一次 |
| -w     | 筛选应用程序监控范围，如-w  /opt/gala-gopher/gala-gopher-app.conf，默认配置为NULL表示不筛选，system_infos、taskprobe探针涉及 |
| -k     | 为kafkaprobe指定消息队列kafka服务端绑定的端口号，默认值9092  |
| -i     | 为host探针指定需要展示的IP地址信息，不配置的情况下默认输出全部host ip信息 |

> 说明：上表中某些参数用于异常事件，目前异常事件范围参考[系统异常范围](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech_abnormal.md)。



## 示例

### gala-gopher.conf示例

```yaml
global =
{
    log_file_name = "gopher.log";
    log_level = "debug";
    pin_path = "/sys/fs/bpf/gala-gopher";
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
    timeout = 600;  # 10min
    desc_language = "zh_CN";        # eg: zh_CN | en_US
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
        param = "-t 5 -w /etc/gala-gopher/gala-gopher-app.conf -l warn -U 80";
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
        param = "-w /etc/gala-gopher/gala-gopher-app.conf -P 3174";
        switch = "on";
    }
);
```
### gala-gopher-app.conf示例

```yaml
application =
(
    {
        comm = "python3";			# 进程名必须配置
        cmdline = "server";			# 通过cmdline关键字信息可以精确到具体应用
    },
    {
        comm = "^taskprobe$",		    # 进程名必须配置
        cmdline = "";			    # 配置为空表示无需通过cmdline做进一步匹配
    }
);
```

