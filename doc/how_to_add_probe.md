开发指南
============
## 逻辑视图

gala-gopher主要包括探针框架和探针程序两部分，探针由Native probe、Extend probe两类，前者只能使用C语言实现，后者不限定编程语言。

目前gala-gopher支持探针上报两类数据至框架：Metrics、Event. 

![logic_frm](pic/logic_frm.png)

其中探针框架包括：

- API：提供REST接口管理gala-gopher。
- probe-mng：负责探针生命周期管理，包括启动、停止、保活等能力。 
- ipc：负责给探针下发配置参数。

- ingress：负责接收探针上报的数据，将数据结构化后录入IMDB。

- egress：负责将结构化的数据通过kafka、prometheus等接口形式输出；

- imdb：数据缓存处理模块；


## 开发视图

gala-gopher开发目录结构如下：

```
gala-gopher
	├── build
	│   ├── build.sh					# 项目构建脚本
	│   ├── Dockerfile_2003_sp1_aarch64 # arm容器镜像dockerfile
	│   ├── Dockerfile_2003_sp1_x86_64	# x86容器镜像dockerfile
	│   ├── entrypoint.sh				# 容器启动脚本
	│   └── install.sh					# 项目安装脚本
	├── config
	│   ├── gala-gopher.conf			# gala-gopher框架配置参数
	│   └── probes.init					# gala-gopher默认启动参数配置文件
	├── COPYRIGHT
	├── doc
	├── k8s
	│   ├── daemonset.yaml.tmpl			# gala-gopher daemonset 模板
	│   └── README.md
	├── LICENSE
	├── res
	│   └── event_multy_language.rc		# 多语言资源文件
	├── script
	│   └── init_probes.sh				# gala-gopher设置默认启动参数脚本
	├── service
	│   └── gala-gopher.service			# systemd service
	├── src
	│   ├── api							# API 模块
	│   ├── cmd							# gala-gopher ctl模块
	│   ├── common						# gala-gopher框架与probe之间的公共模块
	│   ├── daemon						
	│   ├── egress						
	│   ├── ingress
	│   ├── lib
	│   │   ├── config
	│   │   ├── fifo
	│   │   ├── imdb					# imdb模块
	│   │   ├── jvm						# jvm attach模块
	│   │   ├── kafka					# kafka client模块
	│   │   ├── meta					# probes meta文件管理模块
	│   │   └── probe					# probe-mng模块
	│   ├── resource
	│   └── web_server
	│   ├── probes
	│   │   ├── extends
	│   │   │   ├── ebpf.probe			# eBPF探针
	│   │   │   ├── java.probe			# java语言探针（比如jvm probe）
	│   │   │   ├── python.probe		# python语言探针
	│   │   │   └── sh.probe			# shell语言探针
	│   │   ├── system_infos.probe		# native探针
	├── test
```



## 探针与框架之间的协议约束

### meta约束规范

gala-gopher使用meta文件描述探针与框架之间metrics、event上报规范约束，探针框架会按照各个探针meta文件定义的格式解析探针输出数据，各个探针需要严格按照meta文件定义的格式打印输出。

**基本概念：**

- 表：数据库表，每张表必须有KEY，KEY可以由多个字段构成。
- 实体：观测实体，由1张或多张表组成。多张表的KEY字段（数量、名称、含义）必须报错一致。
- 数据字段：表里面的字段，支持key、label、gauge、counter和histogram几种类型。
- KEY: 数据库表的Key，是一种字段类型。

**meta文件配置项说明如下：**

- version：meta文件版本号
- measurements：数据库表list，同一个list可以配置多张数据库表
  - table_name：数据库表名称
  - entity_name：观测实体名称
  - fields：数据字段
    - description：数据字段描述信息
    - type：数据字段类型，目前只支持key、label、gauge、counter和histogram几种类型
    - name：数据字段名称

**meta文件定义规范如下：**

- meta文件基本格式固定，归档位置为各个探针的第一层目录
- 每个table_name的定义必须有key字段，label可选，至少有一个metric，metric即最终输出的指标名称

- 同一个entity_name可以对应多个table_name，约束如下：
  - 每张数据表要保证`entity_name`一致、`table_name`唯一
  - 每张数据表数据字段的key数量、名字必须一致
  - 多张数据表的label可以不一致

**示例文件：**

```conf
version = "1.0.0"

measurements:
(
    {
        table_name: "tcp_tx_rx",
        entity_name: "tcp_link",
        fields:
        (
            {
                description: "id of process",
                type: "key"
                name: "tgid",
            },
            {
                description: "comm of the process",
                type: "label",
                name: "comm",
            },
            {
                description: "rx bytes",
                type: "counter",
                name: "rx_bytes",
            },
        )
    },
    {
        table_name: "tcp_rtt",
        entity_name: "tcp_link",
        fields:
        (
            {
                description: "id of process",
                type: "key",
                name: "tgid",
            },
            {
                description: "Smoothed Round Trip Time(us).",
                type: "gauge",
                name: "srtt",
            },
        )
    }
)
```

> 说明：示例meta文件中配置了两张数据表：`tcp_tx_rx`和`tcp_rtt`，两张数据表的观测对象名`entity_name`一致，均为`tcp_link`。数据字段中`key`一致，均为`tgid`；`tcp_tx_rx`数据表有`label`而`tcp_rtt`数据表没有label字段。

### Metrics上报数据格式

native、extend探针以相同数据格式上报：

- 打印输出的每个数据字段按照 `|` 分割；
- 首字段固定为`<table_name>`；
- 第二个及后面的每个数据字段**必须**和meta文件定义的数据字段一一对应，打印输出时，key类型的数据字段**不可为空**，其他类型的数据字段可以为空，框架会过滤且不上报值为空的标签和指标。

比如：tcp_tx_rx表的输出格式为：|tcp_tx_rx|1001(进程号)|test(进程名)|8712(rx_bytes)|

（翻译下：进程test（进程号1001）接收方向收到8712个字节）。

```
#extend probe 示例
    (void)fprintf(stdout,
        "|%s|%u|%s|%s|%s|%u|%u"
        "|%llu|%llu|%llu|%llu|\n",
        TCP_TBL_TXRX,
        tracker->id.tgid,
        tracker->stats[BYTES_RECV];

#native probe 示例
    (void)nprobe_fprintf(stdout,
        "|%s|%u|%s|%s|%s|%u|%u"
        "|%llu|%llu|%llu|%llu|\n",
        TCP_TBL_TXRX,
        tracker->id.tgid,
        tracker->stats[BYTES_RECV];
*注意两者仅API不同，前者使用PIPE方式，后者使用 Function API方式。
```



### event上报约束规范

gala-gopher框架提供 event 上报SDK，目前仅提供C语言 SDK，其他语言待提供。

```
参见 ./src/common/event.h
# event级别
enum evt_sec_e {
    EVT_SEC_INFO = 0,
    EVT_SEC_WARN,
    EVT_SEC_ERROR,
    EVT_SEC_FATAL,

    EVT_SEC_MAX
};

#define EVT_IP_LEN      128
struct event_info_s {
    const char *entityName;	# 实体名称（参见meta文件定义），必须字段
    const char *entityId;	# 实体ID（由数据库表KEY字段的组合而成），必须字段
    const char *metrics;	# 数据库表内的字段（参见meta文件定义），必须字段
    const char *dev;		# 产生事件的设备名称（比如nic、disk等），可选字段
    char ip[EVT_IP_LEN];	# 产生事件的IP信息（比如IP、Port、Proto等），可选字段
    int pid;				# 产生事件的进程ID，可选字段
};

void report_logs(const struct event_info_s* evt, enum evt_sec_e sec, const char * fmt, ...);

示例：
    report_logs((const struct event_info_s *)&evt,
                EVT_SEC_WARN,
                "IO errors occured."
                "(Disk %s(%d:%d), COMM %s, PID %u, op: %s, datalen %u, "
                "blk_err(%d) '%s', scsi_err(%d) '%s', timestamp %f)",
                .....);

```

### IPC约束规范

gala-gopher框架提供 IPC消息通道，给探针下发配置参数，并且提供IPC消息相关C语言SDK，其他语言待提供。

```
# 探针创建、接收IPC消息代码示例，SDK参见 ./src/common/ipc.h

int msq_id = create_ipc_msg_queue(IPC_EXCL); # 必须是IPC_EXCL方式，可以避免多个探针重复创建IPC通道；
...
# 接收IPC消息并进行格式化
struct ipc_body_s ipc_body;
int ret = recv_ipc_msg(msq_id, (long)PROBE_SOCKET /* 探针类型 */, &ipc_body);

# 处理 ipc_body 消息体，参见下面定义
...

# 销毁 ipc_body，避免资源泄漏
destroy_ipc_body(&ipc_body);

```



- IPC消息类型定义：定义参见 [enum probe_type_e](https://gitee.com/openeuler/gala-gopher/blob/dev/src/common/ipc.h#L91), 不同的探针使用不同的IPC消息类型
- IPC消息格式：参见[struct ipc_body_s](https://gitee.com/openeuler/gala-gopher/blob/dev/src/common/ipc.h#L158)

```
IPC msg format:
                    1byte           2byte           3byte             4byte
         ---|----------------|----------------|----------------|----------------|
        /   |                     msg_type(enum probe_type_e)                   |
        |   |----------------|----------------|----------------|----------------|
        |   |                               msg_len                             |
    ----|---|----------------|----------------|----------------|----------------|
   /    |   |              type(100)          |           len(FIX 4 Bytes)      |
   |    |   |----------------|----------------|----------------|----------------|
   |    |   |                      value(probe_range_flags)                     |
   |    |   |----------------|----------------|----------------|----------------|
   |    |   |              type(101)          | len(sizeof(struct probe_params))|
   |   FIX  |----------------|----------------|----------------|----------------|
   |    |   |                                                                   |
   |    |   |                                                                   |
   |    |   ~                  value(struct probe_params)                       ~
   |    |   |                                                                   |
msg_len |   |                                                                   |
   |    |   |----------------|----------------|----------------|----------------|
   |    |   |              type(102)          |           len(FIX 4 Bytes)      |
   |    |   |----------------|----------------|----------------|----------------|
   |    |   |                          value(probe_flags)                       |
   |    |   |----------------|----------------|----------------|----------------|
   |    |   |              type(103)          |           len(FIX 4 Bytes)      |
   |    |   |----------------|----------------|----------------|----------------|
   |    \   |                         value(snooper_num)                        |
   |     ---|----------------|----------------|----------------|----------------|
   |    /   |    type(eg:proc,container,db)   |     len(eg:proc,container,db)   |
   |    |   |----------------|----------------|----------------|----------------|
   |    |   |                         value(snooper_info)                       |
   | Option |             sub_type            |             sub_len             |
   |    |   ~                                                                   ~
   |    |   |                 sub_value(eg: container_id, db_name...)           |
   \    \   |                                                                   |
    ----|---|----------------|----------------|----------------|----------------|

```



### 探针参数

探针参数由数据结构  `struct ipc_body_s` 描述，其中包括四部分信息： 

- 探针子功能：由成员 `probe_range_flags`表达，不同的探针有其自身的定义，具体可以参考`probe_range_define`。
- 变更内容标记：由成员 `probe_flags`表达IPC内容，范围变更`IPC_FLAGS_SNOOPER_CHG`、监控参数变更`IPC_FLAGS_PARAMS_CHG`。
  - `IPC_FLAGS_SNOOPER_CHG`：表达监控范围发生变更，比如新增监控的进程。
  - `IPC_FLAGS_PARAMS_CHG`：表达监控参数、探针子功能发生变更，比如 l7 探针新开启 `l7_rpc_metrics`子功能。
- 监控范围：由成员 `snooper_objs`、`snooper_obj_num` 表达，目前gala-gopher框架主要提供进程、容器两种类型的监控对象。容器类型的监控对象，可以通过REST配置容器ID方式，也可以配置POD ID方式产生。
- 监控参数：由成员`probe_param`表达探针参数，如果需要新增参数，可以新增`param_keys`中的参数类型定义。

  `struct ipc_body_s` 数据结构参考如下：

```
// refer to ./src/common/ipc.h
#define IPC_FLAGS_SNOOPER_CHG   0x00000001
#define IPC_FLAGS_PARAMS_CHG    0x00000002
struct ipc_body_s {
    u32 probe_range_flags;                              // Refer to flags defined [PROBE_RANGE_XX_XX]
    u32 snooper_obj_num;
    u32 probe_flags;
    struct probe_params probe_param;
    struct snooper_obj_s snooper_objs[SNOOPER_MAX];
};
```

## 如何新增探针

### 定义探针目录

不同语言实现的探针，可以相应的目录下面创建探针目录，比如extend探针直接在 ./src/probes/extends/[xxx.probe]目录新增对应的探针文件夹。命名规范：“probename.probe”。目前支持eBPF、java、shell、python四类语言探针

```
.
├── extends
│   ├── ebpf.probe   # eBPF探针目录
│   ├── java.probe	 # java语言探针目录
│   ├── python.probe	# python语言探针目录
│   └── sh.probe		# shell语言探针目录
├── system_infos.probe	# native探针，直接在probes目录下定义
└── virtualized_infos.probe	# native探针，直接在probes目录下定义

```

### 新增探针类型

新增探针时，需要在gala-gopher探针框架内新增探针类型定义，便于框架进行探针生命周期管理：

```
// refer to ./src/common/ipc.h
enum probe_type_e {
    PROBE_BASEINFO = 1,
    PROBE_VIRT,

    /* The following are extended probes. */
    PROBE_FG,
    PROBE_L7,
    ...
    PROBE_SCHED,
    
    // If you want to add a probe, add the probe type.

    PROBE_TYPE_MAX
};
```

### 定义探针REST API

新增探针时，需要在gala-gopher探针框架内新增探针的REST API，便于框架进行探针配置管理：

```
// refer to ./src/lib/probe/pod_mng.c
struct probe_define_s probe_define[] = {
    {"baseinfo",            "system_infos",                         PROBE_BASEINFO},
    {"virt",                "virtualized_infos",                    PROBE_VIRT},
    {"flamegraph",          "$gala-gopher-dir/stackprobe",          PROBE_FG},
    {"l7",                  "$gala-gopher-dir/l7probe",             PROBE_L7},
    ....
    {"ksli",                "$gala-gopher-dir/ksliprobe",           PROBE_KSLI},
    {"sched",               "$gala-gopher-dir/schedprobe",          PROBE_SCHED}

    // If you want to add a probe, add the probe define.
};
```

例如：l7探针的REST API就是  http://localhost:9999/l7

通常，单个探针会产生多个数据表，每个数据表可以单独控制开关能力，可以通过定义探针子功能开关（与数据表一一对应）来加以控制：

```
// refer to ./src/lib/probe/pod_mng.c
struct probe_range_define_s probe_range_define[] = {
    {PROBE_FG,     "oncpu",               PROBE_RANGE_ONCPU},
    {PROBE_FG,     "offcpu",              PROBE_RANGE_OFFCPU},
    {PROBE_FG,     "mem",                 PROBE_RANGE_MEM},
    {PROBE_FG,     "io",                  PROBE_RANGE_IO},

    {PROBE_L7,     "l7_bytes_metrics",    PROBE_RANGE_L7BYTES_METRICS},
    {PROBE_L7,     "l7_rpc_metrics",      PROBE_RANGE_L7RPC_METRICS},
    {PROBE_L7,     "l7_rpc_trace",        PROBE_RANGE_L7RPC_TRACE},
    ...
    {PROBE_SCHED,  "sched_systime",       PROBE_RANGE_SCHED_SYSTIME},
    {PROBE_SCHED,  "sched_syscall",       PROBE_RANGE_SCHED_SYSCALL},

    // If you want to add a probe, add the probe range.
};

```

例如：l7探针提供三个子功能：`l7_bytes_metrics`、`l7_rpc_metrics`、`l7_rpc_trace`。

REST API可以使用如下方式配置：

```
curl -X PUT http://localhost:9999/l7 --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/l7probe",
        "check_cmd": "",
        "probe": [
            "l7_bytes_metrics",
            "l7_rpc_metrics"
        ]
    }
}
```

### 定义探针

- native探针：必须要有main函数（实际上编译时会将其main函数替换成probename_main），main函数要以`int main()`形式，不支持使用`int main(int argc, char *argv[])`。

  以example.c作参考:

  ```c
  int main()
  {
      example_collect_data();
      return 0;
  }
  ```

- extend探针：没有实现约束，开发者可以自行定义探针内的代码目录，Makefile工程等。

### 定义meta文件

meta文件用于gala-gopher探针框架与探针之间数据上报的协议约束，定义规范详见[meta约束规范](#meta约束规范)。

meta文件要求与放至与探针目录的第一级目录内。

### 开发探针功能

- 探针开发过程首先要建立IPC通道详见[IPC约束规范](#IPC约束规范)，并从IPC通道获取IPC消息，并在IPC消息解析[探针参数](#探针参数)。
- 基于运行参数，探针执行自身逻辑，完成数据采集。
- 将数据通过SDK或PIPE上送至gala-gopher探针框架。

### 定义build.sh

native探针不涉及此项。

如果探针涉及编译，需要定义build.sh（编译脚本名称必须为`build.sh`，探针框架编译时会强匹配脚本名称），如果不需要可以不定义（如shell探针）；build.sh负责该类型探针的编译过程。

### 定义install.h

native探针不涉及此项。

脚本名称必须为`install.sh`，install.sh用于安装编译出的探针程序。

install.sh参数如下：

| 参数     | 含义         | 必选 | 使用场景                                                     |
| -------- | ------------ | ---- | ------------------------------------------------------------ |
| 安装路径 | 指定安装路径 | N    | gala-gopher集成编译时会指定，install.sh中需处理该参数，将程序安装到指定目录下，否则按install.sh默认安装路径安装； |

## 如何开发eBPF探针

对于eBPF探针，考虑到方便探针程序开发，集成了一个轻量的eBPF开发框架，详细了解请点击[进入](../src/probes/extends/ebpf.probe/README.md)。

## 如何裁剪探针

gala-gopher探针架构支持构建时将部分探针裁剪，参考[如何实现探针编译裁剪](how_to_tail_probe.md)

