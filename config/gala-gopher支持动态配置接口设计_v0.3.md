

# 探针动态配置接口说明

gala-gopher支持通过两种方式来实现探针的动态配置：

1. 通过 Restful API 接口。当 gala-gopher 配置文件中 "global" 部分的 ”rest_api_on“ 项的值为 true 时，则可使用该方式；否则，无法使用该方式。
2. 通过命令行工具 gopher-ctl。该方式默认支持。

使用命令行工具的方式参见章节：[使用命令行工具进行探针动态配置](##使用命令行工具进行探针动态配置) 。这里首先介绍通过 Restful API 接口的配置方式。

gala-gopher启动后会提供Restful API配置接口，其URL格式为：**http://[API监听IP]:[API监听端口]/[采集特性名]**。其中：

- API监听IP：可在gala-gopher配置文件中"rest_server"部分的”bind_addr“项进行配置，详情见[配置文件说明](../doc/conf_introduction.md#gala-gopherconf)。由于默认为全0监听，因此可使用gala-gopher所在节点的任意IP（后文均使用localhost为例）；
- API监听端口：可在gala-gopher配置文件中"rest_server"部分的”port“项进行配置，详情见[配置文件说明](../doc/conf_introduction.md#gala-gopherconf)，默认为9999；
- 采集特性名：与采集探针一一对应，例如tcp对应tcpprobe探针，flamegraph对应stackprobe探针。

Restful API只接收用户发起的PUT和GET请求，分别对应如下两类功能：

- 查询探针配置：GET请求

- 动态配置探针属性、观测范围、参数、运行状态（无需重启gala-gopher）：PUT请求，请求体格式如下：

  ```
  json='
  {
      "cmd": {
          "probe": []
      },
      "snoopers": {
          "proc_id": [],
          "proc_name": [{}],
          "pod_id": [],
          "container_id": [],
          "container_name": [],
          "custom_labels": {}
      },
      "params": {},
      "state": "running"
  }'
  ```

  1. ”cmd“字段用于[配置探针基本属性](#配置探针基本属性)，包括探针采集子项；
  2. ”snoopers“字段从进程号、进程名、pod ID、容器 ID、容器名五个维度来[配置观测范围](#配置探针观测范围)，同时支持[拓展标签匹配](#配置探针扩展标签)；
  3. ”params“字段用于[配置探针运行参数](#配置探针运行参数)；
  4. ”state“字段用于配置探针运行状态， 即[启动/停止探针](#启动停止探针)。

## 配置探针接口说明

### 配置探针基本属性

探针的基本属性包括探针的探针文件路径和采集子项，例如以下设置火焰图同时开启oncpu, offcpu采集特性的API举例：

```
curl -X PUT http://localhost:9999/flamegraph -d json='
{
    "cmd": {
        "probe": [
        	"oncpu",
        	"offcpu"
        ]
    }
}'
```

- bin: 探针的可执行文件的完整绝对路径。非必配，未指定时，会自动选择探针默认的安装路径；
- probe：设置探针运行时开启的子功能（即采集子项）。详细说明见下文。

目前所有探针支持采集的全量采集特性说明如下：

| 采集特性      | 采集特性说明                                 | 采集子项范围                                                 | 支持监控对象范围                         | 启动文件                           | 启动条件                  |
| ------------- | -------------------------------------------- | ------------------------------------------------------------ | ---------------------------------------- | ---------------------------------- | ------------------------- |
| flamegraph    | 在线性能火焰图观测能力                       | oncpu, offcpu, mem                                           | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/stackprobe        |                           |
| l7            | 应用7层协议观测能力                          | l7_bytes_metrics,l7_rpc_metrics,l7_rpc_trace                 | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/l7probe           |                           |
| tcp           | TCP异常、状态观测能力                        | tcp_abnormal, tcp_rtt, tcp_windows, tcp_rate, tcp_srtt, tcp_sockbuf, tcp_stats,tcp_delay | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/tcpprobe          |                           |
| socket        | Socket(TCP/UDP)异常观测能力                  | tcp_socket, udp_socket                                       | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/endpoint          |                           |
| io            | Block层I/O观测能力                           | io_trace, io_err, io_count, page_cache                       | NA                                       | /opt/gala-gopher/extend_probes/ioprobe           |                           |
| proc          | 进程系统调用、I/O、DNS、VFS、ioctl等观测能力 | proc_syscall, proc_fs, proc_io, proc_dns,proc_pagecache,proc_net,proc_offcpu,proc_ioctl | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/taskprobe        |                           |
| jvm           | JVM层GC, 线程, 内存, 缓存等观测能力          | NA                                                           | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/jvmprobe          |                           |
| ksli          | Redis性能SLI（访问时延）观测能力             | NA                                                           | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/ksliprobe         |                           |
| postgre_sli   | PG DB性能SLI（访问时延）观测能力             | NA                                                           | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/pgsliprobe        |                           |
| opengauss_sli | openGauss访问吞吐量观测能力                  | NA                                                           | [ip, port, dbname, user,password]        | /opt/gala-gopher/extend_probes/pg_stat_probe.py  |                           |
| dnsmasq       | DNS会话观测能力                              | NA                                                           | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/rabbitmq_probe.sh |                           |
| lvs           | lvs会话观测能力                              | NA                                                           | NA                                       | /opt/gala-gopher/extend_probes/trace_lvs         | lsmod\|grep ip_vs\| wc -l |
| nginx         | Nginx L4/L7层会话观测能力                    | NA                                                           | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/nginx_probe       |                           |
| haproxy       | Haproxy L4/7层会话观测能力                   | NA                                                           | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/trace_haproxy     |                           |
| kafka         | kafka 生产者/消费者topic观测能力             | NA                                                           | NA                                       | /opt/gala-gopher/extend_probes/kafkaprobe        |                           |
| baseinfo      | 系统基础信息                                 | cpu, mem, nic, disk, net, fs, proc, host, con                | proc_id, proc_name, pod_id, container_id | system_infos                       | NA                        |
| virt          | 虚拟化管理信息                               | NA                                                           | NA                                       | virtualized_infos                  | NA                        |
| tprofiling    | 线程级性能profiling观测能力                  | oncpu, syscall_file, syscall_net, syscall_lock, syscall_sched | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/tprofiling        | NA                        |
| container     | 容器信息                                     | NA                                                           | proc_id, proc_name, container_id         | /opt/gala-gopher/extend_probes/cadvisor_probe.py | NA                        |
| sermant       | Java应用7层协议观测能力，当前已支持dubbo协议 | l7_bytes_metrics、l7_rpc_metrics、                           | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/sermant_probe.py  |                           |

每个探针支持的采集子项的详细说明如下：

| 采集特性      | 采集特性说明                          | 采集子项范围                                                 | 采集子项详细说明                                             |
| ------------- | ------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| flamegraph    | 在线性能火焰图观测能力                | oncpu, offcpu, mem                                           | oncpu：采集应用程序允许在cpu上时的状态，可以帮助识别出线程是如何消耗cpu资源的，以及主要耗时的函数调用<br/> offcpu：采集应用程序线程不在cpu上运行时的状态，帮助分析获取线程因执行什么操作（如等待I/O、锁）而进入offcpu<br/> mem：采集应用程序线程查询的时间范围内的内存申请的堆栈，获取内存使用情况 |
| l7            | 应用7层协议观测能力                   | l7_bytes_metrics，l7_rpc_metrics，l7_rpc_trace               | l7_bytes_metrics：采集应用程序接收及发送的数据字节数和接收和发送的数据包个数<br/> l7_rpc_metrics：采集应用程序线程接收的请求个数、发送的响应个数、请求的吞吐量、响应的吞吐量、平均时延、总时延、错误率等<br/> l7_rpc_trace：暂未支持 |
| tcp           | TCP异常、状态观测能力                 | tcp_abnormal, tcp_rtt, tcp_windows, tcp_rate, tcp_srtt, tcp_sockbuf, tcp_stats,tcp_delay | tcp_abnormal：tcp异常信息<br/> tcp_rtt：tcp连接数据传输的往返时间<br/> tcp_windows：tcp窗口相关信息<br/> tcp_rate：tcp传输速率<br/> tcp_srtt：tcp连接的srtt时间<br/> tcp_sockbuf：接收和发送数据的缓冲区的大小<br/> tcp_stats：tcp连接状态<br/> tcp_delay：tcp传输时延信息 |
| socket        | Socket(TCP/UDP)异常观测能力           | tcp_socket, udp_socket                                       | tcp_socket：tcp socket信息<br/> udp_socket：udp socket信息   |
| io            | Block层I/O观测能力                    | io_trace, io_err, io_count, page_cache                       | io_trace：I/O请求数<br/> io_err：I/O错误信息<br/> io_count：I/O操作读和写的字节数<br/> page_cache：缓冲I/O信息 |
| proc          | 进程系统调用、I/O、DNS、VFS等观测能力 | proc_syscall, proc_fs, proc_io, proc_dns,proc_pagecache，proc_net，proc_offcpu, proc_ioctl | proc_syscall：进程系统调用信息<br/> proc_fs：进程调用文件系统信息<br/> proc_io：进程I/O信息<br/> proc_dns：dns访问监控<br/> proc_pagecache：进程使用内存页的信息<br/>proc_net:进程收发网络报文时长统计<br/>proc_offcpu:进程IO_wait、offcpu时长统计<br/>proc_ioctl:进程ioctl大小、时长统计 |
| jvm           | JVM层GC, 线程, 内存, 缓存等观测能力   | NA                                                           | NA                                                           |
| ksli          | Redis性能SLI（访问时延）观测能力      | NA                                                           | NA                                                           |
| postgre_sli   | PG DB性能SLI（访问时延）观测能力      | NA                                                           | NA                                                           |
| opengauss_sli | openGauss访问吞吐量观测能力           | NA                                                           | NA                                                           |
| dnsmasq       | DNS会话观测能力                       | NA                                                           | NA                                                           |
| lvs           | lvs会话观测能力                       | NA                                                           | NA                                                           |
| nginx         | Nginx L4/L7层会话观测能力             | NA                                                           | NA                                                           |
| haproxy       | Haproxy L4/7层会话观测能力            | NA                                                           | NA                                                           |
| kafka         | kafka 生产者/消费者topic观测能力      | NA                                                           | NA                                                           |
| baseinfo      | 系统基础信息                          | cpu, mem, nic, disk, net, fs, proc, host, con                | cpu：cpu性能<br/> mem：内存性能<br/> nic：网卡性能<br/> disk：磁盘性能<br/> net：协议栈统计信息<br/> fs：文件系统信息<br/> proc：进程信息<br/> host：主机信息<br/> con: 容器信息 |
| virt          | 虚拟化管理信息                        | NA                                                           | NA                                                           |
| tprofiling    | 线程级性能profiling观测能力           | oncpu, syscall_file, syscall_net, syscall_lock, syscall_sched | oncpu：应用程序线程运行在cpu上时的状态，帮助识别出线程是如何消耗cpu资源，以及主要耗时的函数调用<br/> syscall_file：系统调用文件系统的信息<br/> syscall_net：系统调用的网络性能<br/> syscall_lock：系统调用死锁的次数<br/> syscall_sched：系统调用的次数 |
| container     | 容器信息                              | NA                                                           | NA                                                           |

### 配置探针观测范围

以火焰图探针为例，配置其观测范围的命令如下：

```
curl -X PUT http://localhost:9999/flamegraph -d json='
{
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ],
        "container_name": [
            "container_name1"
        ]
    }
}'

```

- proc_id：proc_id代表进程id，进程id可以使用ps -ef命令查询到；
- proc_name：proc_name中的一个对象包含comm、cmdline和debugging_dir，假设这一个对象的进程id已知为101，则该进程的comm值为/proc/101/comm文件中的内容，cmdline值为/proc/101/cmdline文件中的内容，debugging_dir的含义是预留给探针设置debug目录（暂未实现相关功能）；
- pod_id：pod 是可以在 Kubernetes 中创建和管理的、最小的可部署的计算单元，可以使用了kubectl run创建pod并获取pod_name，然后使用kubectl get pods -n <namespace> <pod-name> -o jsonpath='{.metadata.uid}'获取pod_id；
- container_id：可以使用docker容器，通过docker run运行一个容器，通过docker ps查看container_id。
- container_name：可以使用docker容器，通过docker run运行一个容器，通过docker ps查看container_name。

### 配置探针扩展标签

探针上报指标数据时会根据meta文件上报相应的标签信息。此外，用户也可以通过动态配置接口增加一些扩展的标签信息进行上报。当前支持的拓展标签有：

- 固定标签

  固定标签是指具有固定值的标签，用户可以在 `snoopers` 配置选项中添加 `custom_labels` 进行配置，该标签会在探针的指标数据上报时填充进去。

  例如，通过下面的配置为 proc 探针添加一个 `task="task1"` 的标签。

  ```
  curl -X PUT http://localhost:9999/proc -d json='
  {
      "snoopers": {
          "custom_labels": {
          	"task": "task1"
          }
      }
  }'
  ```

- Pod级标签

  Pod级标签是指 k8s 附加到 Pod 对象上的键值对，一个 Pod 对象一般包含多个 Pod 标签。用户可以在 `snoopers` 配置选项中添加 `pod_labels` 配置项来指定需要上报哪些 Pod 标签。

  例如，通过下面的配置为 proc 探针指定需要上报的 Pod 标签包括 "app" 和 "test"。如果配置的 Pod 标签不存在，则填充一个默认值 "not found" 。

  ```
  curl -X PUT http://localhost:9999/proc -d json='
  {
      "snoopers": {
          "pod_labels": ["app", "test"]
      }
  }'
  ```

  注：flamegraph探针不会根据meta文件上报标签信息，配置探针扩展标签这里不适用于flamegraph探针

### 配置探针运行参数

探针在启动时或运行期间可以设置一些参数，这些参数同样控制了探针的行为，如果希望指定探针的采样周期和上报周期，则可以设置tcp探针的采样周期sample_period和上报周期report_period，sample_period和report_period都是配置的探针参数

```
curl -X PUT http://localhost:9999/tcp -d json='
{
    "params": {
        "report_period": 60,
        "sample_period": 200,
    }
}'
```

详细参数运行参数如下：

|        参数         |                含义                |                         缺省值&范围                          |  单位   |               支持的采集特性                | 是否已支持 |
| :-----------------: | :--------------------------------: | :----------------------------------------------------------: | :-----: | :-----------------------------------------: | :--------: |
|    sample_period    |              采样周期              |                      5000, [100~10000]                       |   ms    |                   io, tcp                   |     Y      |
|    report_period    |              上报周期              |                         60, [5~600]                          |    s    |                     ALL                     |     Y      |
|     latency_thr     |            时延上报门限            |                        0, [10~100000]                        |   ms    |             tcp, io, proc, ksli             |     Y      |
|     offline_thr     |          进程离线上报门限          |                        0, [10~100000]                        |   ms    |                    proc                     |     Y      |
|      drops_thr      |            丢包上送门限            |                        0, [10~100000]                        | package |                  tcp, nic                   |     Y      |
|    res_lower_thr    |           资源百分比下限           |                          0, [0~100]                          | percent |                     ALL                     |     Y      |
|    res_upper_thr    |           资源百分比上限           |                          0, [0~100]                          | percent |                     ALL                     |     Y      |
|    report_event     |            上报异常事件            |                          0, [0, 1]                           |         |                     ALL                     |     Y      |
|    metrics_type     |       上报telemetry metrics        |                 "raw", ["raw", "telemetry"]                  |         |                     ALL                     |     N      |
|         env         |            工作环境类型            |           "node", ["node", "container", "kubenet"]           |         |                     ALL                     |     N      |
|     l7_protocol     |            L7层协议范围            | "",["http", "pgsql", "redis","mysql", "kafka",  "mongo", "dns"] |         |                     l7                      |     Y      |
|     support_ssl     |        支持SSL加密协议观测         |                          0, [0, 1]                           |         |                     l7                      |     Y      |
|   multi_instance    |     是否每个进程输出独立火焰图     |                          0, [0, 1]                           |         |                 flamegraph                  |     Y      |
|    native_stack     | 是否显示本地语言堆栈(针对JAVA进程) |                          0, [0, 1]                           |         |                 flamegraph                  |     Y      |
| cluster_ip_backend  |     执行Cluster IP backend转换     |                          0, [0, 1]                           |         |                   tcp，l7                   |     Y      |
|  pyroscope_server   |       设置火焰图UI服务端地址       |                       "localhost:4040"                       |         |                 flamegraph                  |     Y      |
|     svg_period      |       火焰图svg文件生成周期        |                        180, [30, 600]                        |    s    |                 flamegraph                  |     Y      |
| perf_sample_period  |   oncpu火焰图采集堆栈信息的周期    |                        10, [10, 1000]                        |   ms    |                 flamegraph                  |     Y      |
|       svg_dir       |       火焰图svg文件存储目录        |              "/var/log/gala-gopher/stacktrace"               |         |                 flamegraph                  |     Y      |
|      flame_dir      |     火焰图原始堆栈信息存储目录     |              "/var/log/gala-gopher/flamegraph"               |         |                 flamegraph                  |     Y      |
|      dev_name       |       观测的网卡/磁盘设备名        |                              ""                              |         | io, kafka, ksli, postgre_sli，baseinfo, tcp |     Y      |
| continuous_sampling |            是否持续采样            |                          0, [0, 1]                           |         |                    ksli                     |     Y      |
|      elf_path       |      要观测的可执行文件的路径      |                              ""                              |         |      baseinfo, nginx, haproxy, dnsmasq      |     Y      |
|     kafka_port      |        要观测的kafka端口号         |                       9092, [1, 65535]                       |         |                    kafka                    |     Y      |
|    cadvisor_port    |        启动的cadvisor端口号        |                       8083, [1, 65535]                       |         |                  container                  |     Y      |

注：探针参数只能配置在支持的监控范围中的探针才能生效，例如，参数sample_period对应的支持的监控范围为io和tcp，则表明参数sample_period只能配置在io探针和tcp探针，参数report_period对应的支持的监控范围为ALL，则表明参数report_period可以配置在gala-gopher支持的所有参数的参数中。

### 启动/停止探针

"state"为running时代表开启探针，"state"为stopped时代表关闭探针。开启探针时请求参数中必须带有"state"：running，否则探针不能被开启，
停止探针时请求参数中必须带有"state"："stopped"，否则探针不能被停止

```
curl -X PUT http://localhost:9999/flamegraph -d json='
{
    "state": "running"
}'
```

### 接口约束与注意点

1. 接口为无状态形式，每次上传的设置为该探针的最终运行结果，包括状态、参数、监控范围。
2. 属性、观测范围、参数、状态可以分开单独设置或者修改，不会影响未指定的项。
3. 监控对象可以任意组合，监控范围取合集。
4. 接口每次最多接收1M字节长度的数据

## 查询探针配置接口说明

使用GET方法，获取名为flamegraph的探针的信息，请求命令为：

```
curl -X GET http://localhost:9999/flamegraph
```

GET请求的响应如下，"state"为探针的运行状态，running代表探针是运行中的状态，其余信息均为探针的配置信息

```
curl -X GET http://localhost:9999/flamegraph
{
    "cmd": {
        "probe": [
            "oncpu",
            "offcpu"
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params": {
        "report_period": 180,
        "sample_period": 180,
        "metrics_type": [
            "raw",
            "telemetry"
        ]
    },
    "state": "running"
}
```



## 探针配置示例

### 火焰图探针配置
看看火焰图探针配置的全集

```
curl -X PUT http://localhost:9999/flamegraph -d json='
{
    "cmd": {
        "probe": [
            "oncpu",
            "offcpu",
            "mem"
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "multi_instance": 1,
        "native_stack": 1,
        "pyroscope_server": "localhost:4040",
        "svg_period": 180,
        "perf_sample_period": 10,
        "svg_dir": "/var/log/gala-gopher/stacktrace",
        "flame_dir": "/var/log/gala-gopher/flamegraph"
    },
    "state":"running"
}'

```

启动火焰图探针的PUT请求中可以配置很多参数，这些参数共同控制着火焰图探针的行为，由上往下分析一下请求中的各个重要组成部分：

1. 使用curl命令发起PUT请求
2. 请求的URL为http://localhost:9999/flamegraph，9999是Rest server处理启动探针请求监听的端口号，flamegraph为探针的名称
3. cmd内容中的probe对应着探针的采集子项，火焰图探针probe的内容为oncpu、offcpu和mem，代表火焰图探针可以采集oncpu、offcpu和mem这三种数据类型的数据
4. snoopers内容中的配置探针监听对象有四个维度，proc_id、proc_name、pod_id和container_id，分别是进程id，进程名称，pod id和容器id，其中任意
   一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定
5. params内容中的参数，示例中的参数都是火焰图探针支持的参数
       multi_instance控制着每个进程是否独立输出火焰图，为1时代表每个进程独立输出火焰图
       native_stack控制着是否显示本地语言堆栈（针对Java进程），值为1的含义是显示Java进程的本地语言堆栈
       pyroscope_server控制着火焰图UI服务端地址，值为localhost:4040的含义为火焰图UI服务端地址为localhost:4040
       svg_period是控制着火焰图svg文件生成的周期，值为180的含义为每隔180s生成火焰图svg文件
       perf_sample_period控制着oncpu火焰图采集堆栈信息的周期，值为10的含义是每个10ms采集oncpu火焰图堆栈信息
       svg_dir控制着火焰图svg文件的存储目录，值为/var/log/gala-gopher/stacktrace的含义是火焰图svg文件存储在/var/log/gala-gopher/stacktrace目录
       flame_dir控制着火焰图原始堆栈信息的存储目录，值为/var/log/gala-gopher/flamegraph的含义是火焰图原始堆栈信息存储在/var/log/gala-gopher/flamegraph目录
       注：尽量不配置火焰图探针不支持的参数，主要要看探针在实现时是否忽略了用户配置的火焰图探针不支持的参数，否则可能会影响探针采集的结果
6. state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped


### 应用7层协议探针配置
```
curl -X PUT http://localhost:9999/l7 -d json='
{
    "cmd": {
        "probe": [
            "l7_bytes_metrics",
            "l7_rpc_metrics",
            "l7_rpc_trace"
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "report_period": 60,
        "l7_protocol": [
            "http",
            "pgsql"
        ],
        "support_ssl": 1,
    },
    "state":"running"
}'

```

启动l7探针的PUT请求中可以配置很多参数，这些参数共同控制着l7探针的行为，由上往下分析一下请求中的各个重要组成部分

1. 使用curl命令发起PUT请求
2. 请求的URL为http://localhost:9999/l7，9999是Rest server处理启动探针请求监听的端口号，l7为探针的名称
3. cmd内容中的probe对应着探针的采集子项，l7探针probe的内容为l7_bytes_metrics、l7_rpc_metrics和l7_rpc_trace，代表火焰图探针可以采集l7_bytes_metrics、l7_rpc_metrics和l7_rpc_trace这三种数据类型的数据，
   具体每种数据类型的含义在下文的采集子项详细说明可以查询到
4. snoopers内容中的配置探针监听对象有四个维度，proc_id、proc_name、pod_id和container_id，分别是进程id，进程名称，pod id和容器id，其中任意
   一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定
5. params内容中的参数，示例中的参数都是l7探针支持的参数
       report_period是控制着采集的数据上报的周期，值为60的含义是每隔60s上报一次采集到的数据
       l7_protocol控制着l7探针采集通过什么协议传输的数据，示例中表示l7探针采集通过http和pgsql协议采集的数据
       support_ssl控制着是否支持SSL加密协议观测，为1的含义是支持SSL加密协议观测
       cluster_ip_backend控制着执行Cluster IP backend转换，为1的含义是执行Cluster IP backend转换
6. state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped

### TCP异常、状态观测探针配置
看看TCP异常、状态观测探针配置的全集

```
curl -X PUT http://localhost:9999/tcp -d json='
{
    "cmd": {
        "probe": [
            "tcp_abnormal",
            "tcp_rtt",
            "tcp_windows",
            "tcp_rate",
            "tcp_srtt",
            "tcp_sockbuf",
            "tcp_stats",
            "tcp_delay"
        ]
    },
    "snoopers": {
        "proc_id": [],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "sample_period": 200,
        "report_period": 60,
        "latency_thr": 60,
        "drops_thr": 10,
        "res_lower_thr": 20,
        "res_upper_thr": 40,
        "report_event": 1,
        "cluster_ip_backend": 1,
    },
    "state":"running"
}'

```

启动tcp探针的PUT请求中可以配置很多参数，这些参数共同控制着tcp探针的行为，由上往下分析一下请求中的各个重要组成部分

1. 使用curl命令发起PUT请求
2. 请求的URL为http://localhost:9999/tcp，9999是Rest server处理启动探针请求监听的端口号，tcp为探针的名称
3. cmd内容中的probe对应着探针的采集子项，tcp探针probe的内容为tcp_abnormal、tcp_rtt、tcp_windows、tcp_rate、tcp_srtt、tcp_sockbuf、tcp_stats和tcp_delay， 代表火焰图探针可以采集tcp_abnormal、tcp_rtt、tcp_windows、tcp_rate、tcp_srtt、tcp_sockbuf、tcp_stats和tcp_delay这些数据类型的数据，
   具体每种数据类型的含义在下文的采集子项详细说明可以查询到
4. snoopers内容中的配置探针监听对象有四个维度，proc_id、proc_name、pod_id和container_id，分别是进程id，进程名称，pod id和容器id，其中任意
   一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定
5. params内容中的参数，示例中的参数都是tcp探针支持的参数
       sample_period控制着探针采集数据的周期，值为200的含义是每隔200ms进行数据的采集
       report_period是控制着采集的数据上报的周期，值为60的含义是每隔60s上报一次采集到的数据
       latency_thr控制着时延上报的门限，值为60的含义是时延需要超过60ms才进行上报
       drops_thr控制着丢包上送门限，值为10的含义是丢包需要大于10 package时才进行丢包上送
       res_lower_thr是控制着资源的百分比下限
       res_upper_thr是控制着资源的百分比上限
       report_event是控制着探针是否上报异常事件，为1时代表上报异常事件
       metrics_type控制着上报telemetry的metrics类型
       env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据
       report_source_port控制着是否上报源端口，为1代表上报源端口
       cluster_ip_backend控制着执行Cluster IP backend转换，为1的含义是执行Cluster IP backend转换
       dev_name控制着观测的网卡/磁盘的设备名，值为io和kafka的含义是观测设备名为io与kafka的设备
6. state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped


### Socket观测探针配置
```
curl -X PUT http://localhost:9999/socket -d json='
{
    "cmd": {
        "probe": [
            "tcp_socket",
            "udp_socket"
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "report_period": 60,
        "res_lower_thr": 20,
        "res_upper_thr": 40,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node"
    },
    "state":"running"
}'

```

启动socket探针的PUT请求中可以配置很多参数，这些参数共同控制着socket探针的行为，由上往下分析一下请求中的各个重要组成部分

1. 使用curl命令发起PUT请求
2. 请求的URL为http://localhost:9999/socket, 9999是Rest server处理启动探针请求监听的端口号，socket为探针的名称
3. cmd内容中的probe对应着探针的采集子项，socket探针probe的内容为tcp_socket, udp_socket, 代表socket探针可以采集tcp_socket和udp_socket数据类型的数据,
   具体每种数据类型的含义在下文的采集子项详细说明可以查询到
4. snoopers内容中的配置探针监听对象有四个维度,proc_id、proc_name、pod_id和container_id, 分别是进程id，进程名称，pod id和容器id，其中任意
   一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定
5. params内容中的参数，示例中的参数都是socket探针支持的参数
       report_period是控制着采集的数据上报的周期
       res_lower_thr是控制着资源的百分比下限
       res_upper_thr是控制着资源的百分比上限
       report_event是控制着探针是否上报异常事件，为1时代表上报异常事件
       metrics_type控制着上报telemetry的metrics类型
       env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据
6. state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped


### Block层I/O观测探针配置
看看Block层I/O观测探针配置的全集

```
curl -X PUT http://localhost:9999/io -d json='
{
    "cmd": {
        "probe": [
            "io_trace",
            "io_err",
            "io_count",
            "page_cache"
        ]
    },
    "snoopers": {},
    "params":{
        "sample_period": 200,
        "report_period": 60,
        "latency_thr": 180,
        "res_lower_thr": 20
        "res_upper_thr": 40,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node",
        "dev_name": [
            "io",
            "kafka"
        ]
    },
    "state":"running"
}'

```

启动io探针的PUT请求中可以配置很多参数，这些参数共同控制着io探针的行为，由上往下分析一下请求中的各个重要组成部分

1. 使用curl命令发起PUT请求
2. 请求的URL为http://localhost:9999/io, 9999是Rest server处理启动探针请求监听的端口号，io为探针的名称
3. cmd内容中的bin为io探针的二进制可执行文件的绝对路径
4. cmd内容中的probe对应着探针的采集子项，io探针probe的内容为io_trace、io_err、io_count和page_cache, 代表io探针可以采集io_trace、io_err、io_count和page_cache数据类型的数据,
   具体每种数据类型的含义在下文的采集子项详细说明可以查询到
5. snoopers内容中的配置探针监听对象有四个维度,proc_id、proc_name、pod_id和container_id, 分别是进程id，进程名称，pod id和容器id，其中任意
   一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定
6. params内容中的参数，示例中的参数都是io探针支持的参数
        sample_period控制着采样周期，值为200的含义是每隔200ms进行一次数据的采样
        report_period是控制着采集的数据上报的周期，值为60的含义是每60s上报一次采集到的数据
        latency_thr控制着时延上报的门限，值为180的含义是时延大于180ms时进行时延的上报
        res_lower_thr是控制着资源的百分比下限
        res_upper_thr是控制着资源的百分比上限
        report_event是控制着探针是否上报异常事件，为1时代表上报异常事件
        metrics_type控制着上报telemetry的metrics类型
        env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据
        dev_name控制着观测的网卡/磁盘的设备名，值为io和kafka的含义是观测设备名为io与kafka的设备
7. state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped


### 进程系统调用、I/O、DNS、VFS等观测探针配置
```
curl -X PUT http://localhost:9999/proc -d json='
{
    "cmd": {
        "probe": [
            "proc_syscall",
            "proc_fs",
            "proc_io",
            "proc_dns",
            "proc_pagecache",
            "proc_net",
            "proc_offcpu",
            "proc_ioctl"
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20,
        "res_upper_thr": 40,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node"
    },
    "state":"running"
}'

```

启动proc探针的PUT请求中可以配置很多参数，这些参数共同控制着proc探针的行为，由上往下分析一下请求中的各个重要组成部分

1. 使用curl命令发起PUT请求
2. 请求的URL为http://localhost:9999/proc, 9999是Rest server处理启动探针请求监听的端口号，proc为探针的名称
3. cmd内容中的probe对应着探针的采集子项，proc探针probe的内容为proc_syscall、proc_fs、proc_io、proc_dns和proc_pagecache,
   代表proc探针可以采集base_metrics、proc_syscall、proc_fs、proc_io、proc_dns和proc_pagecache数据类型的数据,具体每种数据类型的含义在下文的采集子项详细说明可以查询到
4. snoopers内容中的配置探针监听对象有四个维度,proc_id、proc_name、pod_id和container_id, 分别是进程id，进程名称，pod id和容器id，其中任意
   一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定
5. params内容中的参数，示例中的参数都是proc探针支持的参数
       report_period是控制着采集的数据上报的周期，值为180的含义是每隔180s上报一次采集到的数据
       res_lower_thr是控制着资源的百分比下限
       res_upper_thr是控制着资源的百分比上限
       report_event是控制着探针是否上报异常事件，为1时代表上报异常事件
       metrics_type控制着上报telemetry的metrics类型
       env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据
6. state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped


### JVM层GC，线程，内存，缓冲等观测探针配置
```
curl -X PUT http://localhost:9999/jvm -d json='
{
    "cmd": {
        "probe": [
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20,
        "res_upper_thr": 40,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node"
    },
    "state":"running"
}'

```

启动jvm探针的PUT请求中可以配置很多参数，这些参数共同控制着jvm探针的行为，由上往下分析一下请求中的各个重要组成部分

1. 使用curl命令发起PUT请求
2. 请求的URL为http://localhost:9999/jvm, 9999是Rest server处理启动探针请求监听的端口号，jvm为探针的名称
3. cmd内容中的probe对应着探针的采集子项，jvm探针probe的内容为空
4. snoopers内容中的配置探针监听对象有四个维度,proc_id、proc_name、pod_id和container_id, 分别是进程id，进程名称，pod id和容器id，其中任意
   一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定
5. params内容中的参数，示例中的参数都是jvm探针支持的参数
       report_period是控制着采集的数据上报的周期，值为180的含义是每隔180s上报一次采集到的数据
       res_lower_thr是控制着资源的百分比下限
       res_upper_thr是控制着资源的百分比上限
       report_event是控制着探针是否上报异常事件，为1时代表上报异常事件
       metrics_type控制着上报telemetry的metrics类型
       env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据
6. state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped


### Redis性能SLI（访问时延）观测探针配置
```
curl -X PUT http://localhost:9999/ksli -d json='
{
    "cmd": {
        "probe": []
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "report_period": 180,
        "latency_thr": 60,
        "res_lower_thr": 20,
        "res_upper_thr": 40,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node",
        "dev_name": [
            "io",
            "kafka"
        ],
        "continuous_sampling": 1
    },
    "state":"running"
}'

```

启动ksli探针的PUT请求中可以配置很多参数，这些参数共同控制着ksli探针的行为，由上往下分析一下请求中的各个重要组成部分

1. 使用curl命令发起PUT请求
2. 请求的URL为http://localhost:9999/ksli, 9999是Rest server处理启动探针请求监听的端口号，jvm为探针的名称
3. cmd内容中的probe对应着探针的采集子项，ksli探针probe的内容为空，表示上报对应的meta文件的相关指标数据全采集
4. snoopers内容中的配置探针监听对象有四个维度,proc_id、proc_name、pod_id和container_id, 分别是进程id，进程名称，pod id和容器id，其中任意
   一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定
5. params内容中的参数，示例中的参数都是ksli探针支持的参数
       report_period是控制着采集的数据上报的周期，值为180的含义是每隔180s上报一次采集到的数据
       latency_thr控制着时延上报的门限，值为180的含义是时延大于180ms时进行时延的上报
       res_lower_thr是控制着资源的百分比下限
       res_upper_thr是控制着资源的百分比上限
       report_event是控制着探针是否上报异常事件，为1时代表上报异常事件
       metrics_type控制着上报telemetry的metrics类型
       env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据
       dev_name控制着观测的网卡/磁盘的设备名，值为io和kafka的含义是观测设备名为io与kafka的设备
       continuous_sampling控制着是否持续采样，为1的含义是持续采样
6. state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped


### PG DB性能SLI（访问时延）观测探针配置
```
curl -X PUT http://localhost:9999/postgre_sli -d json='
{
    "cmd": {
        "probe": [
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20,
        "res_upper_thr": 40,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node",
        "dev_name": [
            "io",
            "kafka"
        ]
    },
    "state":"running"
}'

```

启动postgre_sli探针的PUT请求中可以配置很多参数，这些参数共同控制着postgre_sli探针的行为，由上往下分析一下请求中的各个重要组成部分

1. 使用curl命令发起PUT请求
2. 请求的URL为http://localhost:9999/postgre_sli, 9999是Rest server处理启动探针请求监听的端口号，postgre_sli为探针的名称
3. cmd内容中的probe对应着探针的采集子项，postgre_sli探针probe的内容为空，代表对应的meta文件的指标数据全采集
4. snoopers内容中的配置探针监听对象有四个维度,proc_id、proc_name、pod_id和container_id, 分别是进程id，进程名称，pod id和容器id，其中任意
   一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定
5. params内容中的参数，示例中的参数都是postgre_sli探针支持的参数
       report_period是控制着采集的数据上报的周期，值为180的含义是每隔180s上报一次采集到的数据
       res_lower_thr是控制着资源的百分比下限
       res_upper_thr是控制着资源的百分比上限
       report_event是控制着探针是否上报异常事件，为1时代表上报异常事件
       metrics_type控制着上报telemetry的metrics类型
       env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据
       dev_name控制着观测的网卡/磁盘的设备名，值为io和kafka的含义是观测设备名为io与kafka的设备
6. state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped


### openGauss访问吞吐量观测探针
```
curl -X PUT http://localhost:9999/opengauss_sli -d json='
{
    "cmd": {
        "probe": [
        ]
    },
    "snoopers": {
        "ip": [
            "ip1",
            "ip2"
        ],
        "port": [
            "port1",
            "port2"
        ],
        "dbname": [
            "dbname1",
            "dbname2"
        ],
        "user": [
            "user1",
            "user2"
        ],
        "password": [
            "password1",
            "password2"
        ]
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20,
        "res_upper_thr": 40,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node"
    },
    "state":"running"
}'

```

启动opengauss_sli探针的PUT请求中可以配置很多参数，这些参数共同控制着opengauss_sli探针的行为，由上往下分析一下请求中的各个重要组成部分

1. 使用curl命令发起PUT请求
2. 请求的URL为http://localhost:9999/opengauss_sli, 9999是Rest server处理启动探针请求监听的端口号，opengauss_sli为探针的名称
3. cmd内容中的probe对应着探针的采集子项，opengauss_sli探针probe的内容为空时代表opengauss探针对应的meta文件的指标数据全采集
4. snoopers内容中的配置探针监听对象有四个维度,proc_id、proc_name、pod_id和container_id, 分别是进程id，进程名称，pod id和容器id，其中任意
   一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定
5. params内容中的参数，示例中的参数都是opengauss_sli探针支持的参数
       report_period是控制着采集的数据上报的周期，值为180的含义是每隔180s上报一次采集到的数据
       res_lower_thr是控制着资源的百分比下限
       res_upper_thr是控制着资源的百分比上限
       report_event是控制着探针是否上报异常事件，为1时代表上报异常事件
       metrics_type控制着上报telemetry的metrics类型
       env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据
6. tate控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped


### Nginx L4/L7层会话观测探针配置
```
curl -X PUT http://localhost:9999/nginx -d json='
{
    "cmd": {
        "probe": [
        ]
    },
    "snoopers": {},
    "params":{
        "report_period": 180,
        "res_lower_thr": 20,
        "res_upper_thr": 40,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node",
        "elf_path": "/usr/lib/bin/log"
    },
    "state":"running"
}'

```

启动nginx探针的PUT请求中可以配置很多参数，这些参数共同控制着nginx探针的行为，由上往下分析一下请求中的各个重要组成部分

1. 使用curl命令发起PUT请求
2. 请求的URL为http://localhost:9999/nginx, 9999是Rest server处理启动探针请求监听的端口号，nginx为探针的名称
3. cmd内容中的probe对应着探针的采集子项，nginx探针probe的内容为空时代表nginx探针对应的meta文件中的指标数据全采集
4. snoopers内容中的配置探针监听对象为空
5. params内容中的参数，示例中的参数都是nginx探针支持的参数
       report_period是控制着采集的数据上报的周期，值为180的含义是每隔180s上报一次采集到的数据
       res_lower_thr是控制着资源的百分比下限
       res_upper_thr是控制着资源的百分比上限
       report_event是控制着探针是否上报异常事件，为1时代表上报异常事件
       metrics_type控制着上报telemetry的metrics类型
       env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据
       elf_path控制着要观测的可执行文件的路径
6. state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped


### Kafka 生产者/消费者topic观测探针配置
```
curl -X PUT http://localhost:9999/kafka -d json='
{
    "cmd": {
        "probe": [
        ]
    },
    "snoopers": {
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20,
        "res_upper_thr": 40,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node"
    },
    "state":"running"
}'

```

启动kafka探针的PUT请求中可以配置很多参数，这些参数共同控制着kafka探针的行为，由上往下分析一下请求中的各个重要组成部分

1. 使用curl命令发起PUT请求
2. 请求的URL为http://localhost:9999/haproxy, 9999是Rest server处理启动探针请求监听的端口号，kafka为探针的名称
3. cmd内容中的bin为kafka探针的二进制可执行文件的绝对路径
4. cmd内容中的probe对应着探针的采集子项，kafka探针probe的内容为空时代表kafka探针对应的meta文件的指标数据全采集
5. snoopers内容中的配置探针监听对象为空
6. params内容中的参数，示例中的参数都是kafka探针支持的参数
       report_period是控制着采集的数据上报的周期，值为180的含义是每隔180s上报一次采集到的数据
       res_lower_thr是控制着资源的百分比下限
       res_upper_thr是控制着资源的百分比上限
       report_event是控制着探针是否上报异常事件，为1时代表上报异常事件
       metrics_type控制着上报telemetry的metrics类型
       env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据
7. state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped


### 系统基础信息观测探针配置
```
curl -X PUT http://localhost:9999/baseinfo -d json='
{
    "cmd": {
        "probe": [
            "cpu",
            "mem",
            "nic",
            "disk",
            "net",
            "fs",
            "proc",
            "host",
            "con"
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20,
        "res_upper_thr": 40,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node",
        "dev_name": [
            "io",
            "kafka"
        ]
    },
    "state":"running"
}'

```

启动baseinfo探针的PUT请求中可以配置很多参数，这些参数共同控制着baseinfo探针的行为，由上往下分析一下请求中的各个重要组成部分

1. 使用curl命令发起PUT请求
2. 请求的URL为http://localhost:9999/baseinfo, 9999是Rest server处理启动探针请求监听的端口号，baseinfo为探针的名称
3. cmd内容中的probe对应着探针的采集子项，baseinfo探针probe的内容为空cpu，mem，nic，disk，net，fs，proc，host，代表着baseinfo探针会采集
   cpu，mem，nic，disk，net，fs，proc，host, con这些类型的数据
4. snoopers内容中的配置探针监听对象有四个维度，proc_id、proc_name、pod_id和container_id，分别是进程id，进程名称，pod id和容器id，其中任意
   一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定
5. params内容中的参数，示例中的参数都是baseinfo探针支持的参数
       report_period是控制着采集的数据上报的周期，值为180的含义是每隔180s上报一次采集到的数据
       res_lower_thr是控制着资源的百分比下限
       res_upper_thr是控制着资源的百分比上限
       report_event是控制着探针是否上报异常事件，为1时代表上报异常事件
       metrics_type控制着上报telemetry的metrics类型
       env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据
       elf_path参数仅当开启了con采集子项，且配置了container_id监听对象时有效。表示要监控容器下的对应目录
6. state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped


### 虚拟化观测探针配置
```
curl -X PUT http://localhost:9999/virt -d json='
{
    "cmd": {
        "probe": [
        ]
    },
    "snoopers": {
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20,
        "res_upper_thr": 40,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node"
    },
    "state":"running"
}'

```

启动virt探针的PUT请求中可以配置很多参数，这些参数共同控制着virt探针的行为，由上往下分析一下请求中的各个重要组成部分

1. 使用curl命令发起PUT请求
2. 请求的URL为http://localhost:9999/virt, 9999是Rest server处理启动探针请求监听的端口号，virt为探针的名称
3. cmd内容中的probe对应着探针的采集子项，virt探针的probe对应着探针的采集子项为空时代表virt对应的meta文件的指标数据全采集
4. snoopers内容中的配置探针监听对象为空
5. params内容中的参数，示例中的参数都是virt探针支持的参数
       report_period是控制着采集的数据上报的周期，值为180的含义是每隔180s上报一次采集到的数据
       res_lower_thr是控制着资源的百分比下限
       res_upper_thr是控制着资源的百分比上限
       report_event是控制着探针是否上报异常事件，为1时代表上报异常事件
       metrics_type控制着上报telemetry的metrics类型
       env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据
6. state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped


### 线程级性能profiling探针（tprofiling）配置
```
curl -X PUT http://localhost:9999/tprofiling -d json='
{
    "cmd": {
        "probe": [
            "oncpu",
            "syscall_file",
            "syscall_net",
            "syscall_lock",
            "syscall_sched"
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20,
        "res_upper_thr": 40,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node"
    },
    "state":"running"
}'

```

启动tprofiling探针的PUT请求中可以配置很多参数，这些参数共同控制着tprofiling探针的行为，由上往下分析一下请求中的各个重要组成部分

1. 使用curl命令发起PUT请求
2. 请求的URL为http://localhost:9999/tprofiling, 9999是Rest server处理启动探针请求监听的端口号，tprofiling为探针的名称
3. cmd内容中的probe对应着探针的采集子项，tprofiling探针的probe对应着探针的采集子项为oncpu、syscall_file、syscall_net、syscall_lock、
   syscall_sched,代表tprofiling探针会采集这些类型的数据
4. snoopers内容中的配置探针监听对象有四个维度,proc_id、proc_name、pod_id和container_id, 分别是进程id，进程名称，pod id和容器id，其中任意
   一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定
5. params内容中的参数，示例中的参数都是virt探针支持的参数
       report_period是控制着采集的数据上报的周期，值为180的含义是每隔180s上报一次采集到的数据
       res_lower_thr是控制着资源的百分比下限
       res_upper_thr是控制着资源的百分比上限
       report_event是控制着探针是否上报异常事件，为1时代表上报异常事件
       metrics_type控制着上报telemetry的metrics类型
       env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据
6. state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped


### 容器信息探针配置
```
curl -X PUT http://localhost:9999/container -d json='
{
    "cmd": {
        "probe": []
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "report_period": 60,
    },
    "state":"running"
}'

```

启动container探针的PUT请求中可以配置很多参数，这些参数共同控制着container探针的行为，由上往下分析一下请求中的各个重要组成部分

1. 使用curl命令发起PUT请求
2. container为探针的名称
3. cmd内容中的probe对应着探针的采集子项，container探针的probe对应着探针的采集子项为空
4. snoopers内容中的配置探针监听对象有四个维度,proc_id、proc_name、pod_id和container_id, 分别是进程id，进程名称，pod id和容器id，其中任意
   一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定
5. params内容中的参数，示例中的参数都是container探针支持的参数
       report_period是控制着采集的数据上报的周期，值为60的含义是每隔60s上报一次采集到的数据
       采集周期无需配置，其值与 report_period 数据相同。
6. state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped



## 使用命令行工具进行探针动态配置

gala-gopher 支持通过命令行工具 gopher-ctl 进行探针的动态配置。

gopher-ctl 命令行的语法格式如下：

```shell
gopher-ctl probe get <probe_name>
gopher-ctl probe set <probe_name> <probe_config>
```

操作说明：

- `get`：获取探针的动态配置信息
- `set`：设置探针的动态配置信息

参数说明：

- `<probe_name>`：指定探针名，范围参见 [配置探针接口说明](##配置探针接口说明) 。
- `<probe_config>`：指定探针的配置信息，json 格式，内容与 Restful API 的方式一致，详情参见  [配置探针接口说明](##配置探针接口说明) 。