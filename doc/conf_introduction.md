配置文件介绍
================

gala-gopher启动必须的外部参数通过配置文件`gala-gopher.conf`定义；主要的配置项包括：设置数据上报周期、数据库信息、cache数据库配置等。

## 配置介绍

配置文件归档在[config目录](../config)。

extend探针配置文件归档在探针同级目录下。目前有配置文件的探针有:

[cadvisor.probe](../src/probes/extends/python.probe/cadvisor.probe)

[pg_stat.probe](../src/probes/extends/python.probe/pg_stat.probe)

### gala-gopher.conf

`gala-gopher.conf`文件的安装路径为 `/etc/gala-gopher/gala-gopher.conf`。该文件配置项说明如下：

- global：gala-gopher全局配置信息
  - log_file_name：gala-gopher日志文件名
  - log_level：gala-gopher日志级别
- metric：指标数据metrics输出方式配置
  - out_channel：metrics输出通道，支持配置web_server|logs|kafka，配置为空则输出通道关闭
  - kafka_topic：若输出通道为kafka，此为topic配置信息
- event：异常事件event输出方式配置
  - out_channel：event输出通道，支持配置logs|kafka，配置为空则输出通道关闭
  - kafka_topic：若输出通道为kafka，此为topic配置信息
  - timeout：同一异常事件上报间隔设置
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
  - bind_addr: 监听地址，默认监听127.0.0.1。
  - port：监听端口
  - ssl_auth：设置web server开启https加密以及鉴权，on为开启，off为不开启，建议用户在实际生产环境开启
  - private_key：用于web server https加密的服务端私钥文件绝对路径，当ssl_auth为“on”必配
  - cert_file：用于web server https加密的服务端证书绝对路径，当ssl_auth为“on”必配
  - ca_file：用于web server对客户端进行鉴权的CA中心证书绝对路径，当ssl_auth为“on”必配
- rest_api_server
  - bind_addr: 监听地址，默认监听127.0.0.1。
  - port：RestFul API监听端口
  - ssl_auth：设置RestFul API开启https加密以及鉴权，on为开启，off为不开启，建议用户在实际生产环境开启
  - private_key：用于RestFul API https加密的服务端私钥文件绝对路径，当ssl_auth为“on”必配
  - cert_file：用于RestFul API https加密的服务端证书绝对路径，当ssl_auth为“on”必配
  - ca_file：用于RestFul API对客户端进行鉴权的CA中心证书绝对路径，当ssl_auth为“on”必配
- kafka：输出通道kafka配置
  - kafka_broker：kafka服务器的IP和port
  - batch_num_messages：每个批次发送的消息数量
  - compression_codec：消息压缩类型
  - queue_buffering_max_messages：生产者缓冲区中允许的最大消息数
  - queue_buffering_max_kbytes：生产者缓冲区中允许的最大字节数
  - queue_buffering_max_ms：生产者在发送批次之前等待更多消息加入的最大时间
- logs：输出通道logs配置
  - metric_total_size：metrics指标数据日志文件总大小的上限，单位为MB
  - metric_dir：metrics指标数据日志路径
  - event_dir：异常事件数据日志路径
  - meta_dir：metadata元数据日志路径
  - debug_dir：gala-gopher运行日志路径

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

> 说明：cadvisor_probe.conf和cadvisor_probe.meta的字段需要一致。例外：若conf中type字段为counter，在meta中对应type字段应为gauge；若conf中type字段为label，在meta中对应type字段应为key


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

## 示例

### gala-gopher.conf示例

```yaml
global =
{
    log_file_name = "gopher.log";
    log_level = "debug";
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
    bind_addr = "0.0.0.0";
    port = 8888;
};

rest_api_server =
{
    bind_addr = "0.0.0.0";
    port = 9999;
    ssl_auth = "off";
    private_key = "";
    cert_file = "";
    ca_file = "";
};
kafka =
{
    kafka_broker = "10.137.10.xx:9092";
    batch_num_messages = 10000;
    compression_codec = "none";
    queue_buffering_max_messages = 100000;
    queue_buffering_max_kbytes = 1048576;
    queue_buffering_max_ms = 5;
    username = "";
    password = "";
};

logs =
{
    metric_dir = "/var/log/gala-gopher/metrics";
    event_dir = "/var/log/gala-gopher/event";
    meta_dir = "/var/log/gala-gopher/meta";
    debug_dir = "/var/log/gala-gopher/debug";
};
```
