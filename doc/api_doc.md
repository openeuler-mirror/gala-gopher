# API介绍

gala-gopher共对外提供三类数据：观测指标数据、异常事件数据、元数据，每类数据都有单独的获取接口。

## 1. 指标数据获取接口

gala-gopher支持将采集到的数据上报到Promethous、Kafka等数据库；可以通过配置文件开启/关闭某个数据上报通道，具体参考[配置文件](conf_introduction.md)中 `metric`部分。

### 1.1 http方式(默认)

采用本方式每条采集数据是基于指标粒度上报的，通常gala-gopher部署在1个到多个普通节点，管理节点的Promethous可以配置定时拉取各个普通节点的指标数据。

#### 默认提供的URL地址

```http
http://localhost:8888
```

http监听IP和端口支持自定义配置，详情参考[配置文件](conf_introduction.md)中 `web_server`部分。

#### 输出数据格式

指标数据遵循以下格式：

```basic
metric_name {"key1"="xx","key2"="xx","label1"="xx","label2"="xx",...} metric_value timestamp
```

metirc_name即指标名，遵循如下指标命名规范：gala_gopher_<entity_name>_<metric_name>。metric_value即指标的值是一个float格式的数据。timestamp默认为当前时间(从1970-01-01 00:00:00以来的毫秒数)。每条数据由指标名metric_name和标签{key..label..}组合唯一确定。

#### 请求示例

##### 输入示例

```shell
curl http://localhost:8888
```

##### 输出示例

```basic
gala_gopher_thread_fork_count{pid="2494",tgid="2494",comm="hello",major="8",minor="0",machine_id="xxxxx",hostname="localhost.master"} 2 1656060116000
gala_gopher_thread_task_io_time_us{pid="2494",tgid="2494",comm="hello",major="8",minor="0",machine_id="xxxxx",hostname="localhost.master"} 3 1656060116000
```

### 1.2 kafka方式

本方式输出的数据是基于观测对象粒度的，即每条数据是观测对象的一个实例信息，包含了：观测对象名(entity_name)和全量的keys、lables和metrics信息。

#### 默认提供的topic

```basic
gala_gopher
```

支持自定义配置，详情参考[配置文件](conf_introduction.md)中 ` metric`的`kafka_topic`部分。

#### 输出数据格式

```json
{
    "timestamp": 1234567890,
    "machine_id": "xxxxx",
    "entity_name": "xxxx",
    "key1": "xx",
    "key2": "xx",
    ...,
    "label1": "xx",
    "label2": "xx",
    ...,
    "metric1": "xx",
    "metric2": "xx",
    ...
}
```

#### 请求示例

##### 输入示例

```shell
./bin/kafka-console-consumer.sh --bootstrap-server 10.10.10.10:9092 --topic gala_gopher
```

##### 输出示例

```json
 {"timestamp": 165606384400, "machine_id": "xxxxx", "hostname": "localhost.master", "entity_name": "thread", "pid": "2494", "tgid": "2494", "comm": "hello", "major": "8", "minor": "0", "fd_count": "2", "task_io_wait_time_us": "1", "task_io_count": "2", "task_io_time_us": "3", "task_hang_count": "4"}
```

### 1.3 命令行方式

gala-gopher 支持通过命令行工具 gopher-ctl 来获取指标数据。当 gala-gopher 配置文件中 "global" 部分的 ”listen_on“ 项的值为 false 时，则使用该方式进行配置。

gopher-ctl 命令行的语法格式如下：

```shell
gopher-ctl metric
```



## 2. 元数据获取接口

元数据主要描述了每个观测对象的基本信息，如：数据表名(table_name)、观测对象名(entity_name)、版本号，以及键值keys有哪些、标签labels有哪些、指标metrics有哪，gala分析组件需要元数据对观测指标数据进行解析。元数据会上报到kafka。

#### 默认提供的topic

```basic
gala_gopher_metadata
```

支持自定义配置，详情参考[配置文件](conf_introduction.md)中 ` meta`部分。

#### 输出数据格式

```json
{
	"timestamp": 1234567890,
	"meta_name": "xxx",
	"entity_name": "yyy",
	"version": "1.0.0",
	"keys": ["key1", "key2", ...],
	"labels": ["label1", "label2", ...],
	"metrics": ["metric1", "metric2", ...]
}
```

其中，meta_name即数据表名，entity_name即观测对象名。同一个观测对象可能包含多个观测数据表，这种情况下属于同一个观测对象的观测对象名entity_name一致、数据表名table_name不重复、键值keys一致，而且metrics指标名在整个观测对象范围内唯一。

#### 请求示例

##### 输入示例

```shell
./bin/kafka-console-consumer.sh --bootstrap-server 10.10.10.10:9092 --topic gala_gopher_metadata
```

##### 输出示例

```json
{"timestamp": 1655888408000, "meta_name": "thread", "entity_name": "thread", "version": "1.0.0", "keys": ["machine_id", "pid"], "labels": ["hostname", "tgid", "comm", "major", "minor"], "metrics": ["fork_count", "task_io_wait_time_us", "task_io_count", "task_io_time_us", "task_hang_count"]}
{"timestamp": 1655888408000, "meta_name": "tcp_link_info", "entity_name": "tcp_link", "version": "1.0.0", "keys": ["machine_id", "tgid", "role", "client_ip", "server_ip", "client_port", "server_port", "protocol"], "labels": ["hostname"], "metrics": ["rx_bytes", "tx_bytes", ...]}
{"timestamp": 1655888408000, "meta_name": "tcp_link_health", "entity_name": "tcp_link", "version": "1.0.0", "keys": ["machine_id", "tgid", "role", "client_ip", "server_ip", "client_port", "server_port", "protocol"], "labels": ["hostname"], "metrics": ["segs_in", "segs_out", "retran_packets", ...]}
```



## 3. 异常事件获取接口

gala-gopher运行中，如果开启了异常上报功能，就会在探测到数据根据入参阈值后进行检查，超出阈值就会上报异常事件到kafka，上报通道是单独的。

#### 默认提供的topic

```basic
gala_gopher_event
```

支持自定义配置，详情参考[配置文件](conf_introduction.md)中 ` event`部分。

#### 输出数据格式

```json
{
	"Timestamp": 1661088145000,
    "event_id": "<timestamp>_<entity_id>",
	"Attributes": {
		"entity_id": "<machine_id>_<entity_name>_<key1>_<key2>_...",
		"event_id": "<timestamp>_<entity_id>",
		"event_type": "sys"
	},
	"Resource": {
		"metrics": "<metric_name>"
	},
	"SeverityText": "WARN",
	"SeverityNumber": 13,
	"Body": "descriptions."
}
```

输出数据解释：

1、数据要满足JSON格式，可以通过在线JSON校验格式化工具校验；

2、entity_id和event_id字符串长度要在1~254bytes之间，支持a-z、A-Z、0-9字符，支持如下标点符号： `_` `-` `:` `.` `@` `(` `)` `+` `,` `=` `;` `$` `!` `*` `'` `%`，其他标点符号全部用 `:` 代替； 

示例如下：

原本的输出数据：

```json
{"Attributes": { "entity_id": "xxxxx_system_disk_/honme"}}
```

可见entity_id中有 `/` 这个特殊符号，则将 `/` 替换为 `:` 后的输出数据为：

```json
{"Attributes": { "entity_id": "xxxxx_system_disk_:honme"}}
```

3、Timestamp时间戳使用13位long型数字，不使用字符串；

| 输出参数                    | 参数含义 | 描述                                                    |
| --------------------------- | -------- | ------------------------------------------------------- |
| Timestamp                   | 时间戳   | 时间戳，13位long型数据                                  |
| entity_id                   | 实体ID   | 命名规则：`<machine_id>_<entity_name>_<key1>_<key2>_..` |
| event_id                    | 事件ID   | 命名规则：`<timestamp>_<entity_id>`                     |
| event_type                  | 事件类型 | sys / app                                               |
| metrics                     | 指标名   | 命名规则：`gala_gopher_<entity_name>_<metric_name>`     |
| SeverityText/SeverityNumber | 异常事件 | INFO/9 WARN/13 ERROR/17 FATAL/21                        |
| Body                        | 事件信息 | 字符串，描述了当前时间、异常事件等级以及具体时间信息    |

##### 输入示例

```shell
./bin/kafka-console-consumer.sh --bootstrap-server 10.10.10.10:9092 --topic gala_gopher_event
```

##### 输出示例

```json
{
	"Timestamp": 1661088145000,
    "event_id": "1661088145000_1fd37xxxxx_thread_12302",
	"Attributes": {
		"entity_id": "1fd37xxxxx_thread_12302",
		"event_id": "1661088145000_1fd37xxxxx_thread_12302",
		"event_type": "sys"
	},
	"Resource": {
		"metrics": "gala_gopher_thread_off_cpu_ns"
	},
	"SeverityText": "WARN",
	"SeverityNumber": 13,
	"Body": "Sun Aug 21 21:22:25 2022 WARN Entity(12302) Process(COMM:redis-server TID:12302) is preempted(COMM:migration/1 PID:16) and off-CPU 4556 ns."
}
{
	"Timestamp": 1661418870000,
	"event_id": "1661418870000_e473bxxxxx_system_df_:tmp",
	"Attributes": {
		"entity_id": "e473bxxxxx_system_df_:tmp",
		"event_id": "1661418870000_e473bxxxxx_system_df_:tmp",
		"event_type": "sys"
	},
	"Resource": {
		"metrics": "gala_gopher_system_df_inode_userd_per"
	},
	"SeverityText": "WARN",
	"SeverityNumber": 13,
	"Body": "Thu Aug 25 17:14:30 2022 WARN Entity(/tmp) Too many Inodes consumed(95%)."
}
```

