

# Rest API说明

启动gala- gopher时会启动Rest server, 该Rest server负责接收用户的发起的PUT和GET清求， PUT请求用于启动探针并配置监控范围，GET请求用于获取探针的相关信息，同一采集特性对应同一个探针和请求的URL。
可以使用curl命令发起请求，请求的URL的组织方式为http://[gala-gopher所在节点ip] + [端口号] + function（采集特性），Rest server服务所占用的端口号可配置（缺省时为9999），例如，
采集火焰图的URL为：http://localhost:9999/flamegraph。 

探针默认关闭，可以通过curl命令发送PUT请求给Rest server动态开启并设置监控范围。
以火焰图为例，看看可以对火焰图探针进行哪些操作


## 开启探针
为了开启火焰图探针，需要先启动gala-gopher,之后发送请求给Rest server, 以下面的启动探针请求为例, 介绍一下开启探针时需要注意的几点
（1）请求方法为PUT方法
（2）端口号默认为9999，也可以在gala-gopher.conf配置文件中进行配置
（3）flamegraph为探针的名字，bin为探针的二进制可执行文件的二选制文件的绝对文件路径
（4）probe数组：probe数组中的内容控制了探针会采集哪些数据，火焰图探针的probe数组中的内容可以为"oncpu"、"offcpu"和"mem", 代表着火焰图探针可以采集"oncpu"、"offcpu"和"mem"类型的数据。
如果probe数组为空则代表火焰图探针不会采集任何数据
(5)snoopers数组：snoopers数组中的内容为探针所监控的对象，可以通过配置proc_ id(进程1d)、proc_name (进程名称)、pod_id、container_id (容器id)指定探针监控的对象，
snoopers为空时代表探针不会监控任何对象
(6)state为探针的状态，由于需要开启探针，所以state必须为running才能开启探针

开启火焰图探针的命令如下：

```
curl -X PUT http://localhost:9999/flamegraph --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/stackprobe",
        "check_cmd": "",
        "probe": [
        ]
    },
    "snoopers": {
        "proc_id": [
        ],
        "proc_name": [
        ],
        "pod_id": [
        ],
        "container_id": [
        ]
    },
    "state":"running"
}'

```


## 配置探针监控范围

探针的监控范围可以在开启探针时设置或者在开启探针后设置。探针监控范围由snoopers数组下的监控对象和probe数组下的需要采集的数据类型决定。

（1）配置snoopers数组下的监控对象（进程ID、进程名、容器ID、POD四个维度）
以配置proc_id为例，可以尝试简单的配置监控某一个进程，假设你已经知晓该进程的进程id，如果该进程id为101和102，则配置火焰图探针监测该进程可以
将进程id填入snoopers数组下的proc_id

配置探针监测指定进程实例如下：

```
curl -X PUT http://localhost:9999/flamegraph --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/stackprobe",
        "check_cmd": "",
        "probe": [
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
        ],
        "pod_id": [
        ],
        "container_id": [
        ]
    }
}'
```

由于前面已经开启了flamegraph探针，配置flamegraph探针的监控范围可不带state状态，配置了proc_id之后可以不配置proc_name，flamegraph
探针可以根据proc_id识别到指定的进程

（2）配置probe数组下的需要采集的数据类型
flamegraph探针支持采集的数据类型有三种，分别是oncpu、offcpu和mem，可以选择你希望采集的数据类型，可以是oncpu、offcpu和mem的任意组合

下面是火焰图同时开启oncpu, offcpu采集特性的API举例：

```
curl -X PUT http://localhost:9999/flamegraph --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/stackprobe",
        "check_cmd": "",
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
    }
}'

```

以上，正确地开启并配置了flamegraph探针的监控范围


## 扩展

下面，我们再多了解一些探针相关的信息

gala-gopher支持采集多种特性，每种特性对应一个探针，你可以按照上面的步骤尝试使用指定的探针，目前所有探针支持采集的全量采集特性说明如下：

| 采集特性          | 采集特性说明                      | 采集子项范围                                                 | 监控对象                                 | 启动文件                               | 启动条件                  |
|---------------|-----------------------------| ------------------------------------------------------------ | ---------------------------------------- |------------------------------------| ------------------------- |
| flamegraph    | 在线性能火焰图观测能力                 | oncpu, offcpu, mem                                           | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/stackprobe        |                           |
| l7            | 应用7层协议观测能力                  | l7_bytes_metrics、l7_rpc_metrics、l7_rpc_trace               | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/l7probe           |                           |
| tcp           | TCP异常、状态观测能力                | tcp_abnormal, tcp_rtt, tcp_windows, tcp_rate, tcp_srtt, tcp_sockbuf, tcp_stats,tcp_delay | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/tcpprobe          |                           |
| socket        | Socket(TCP/UDP)异常观测能力       | tcp_socket, udp_socket                                       | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/endpoint          |                           |
| io            | Block层I/O观测能力               | io_trace, io_err, io_count, page_cache                       | NA                                       | $gala-gopher-dir/ioprobe           |                           |
| proc          | 进程系统调用、I/O、DNS、VFS等观测能力     | base_metrics, proc_syscall, proc_fs, proc_io, proc_dns,proc_pagecache | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/taskprobe         |                           |
| jvm           | JVM层GC, 线程, 内存, 缓存等观测能力     | NA                                                           | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/jvmprobe          |                           |
| ksli          | Redis性能SLI（访问时延）观测能力        | NA                                                           | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/ksliprobe         |                           |
| postgre_sli   | PG DB性能SLI（访问时延）观测能力        | NA                                                           | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/pgsliprobe        |                           |
| opengauss_sli | openGauss访问吞吐量观测能力          | NA                                                           | [ip, port, dbname, user,password]        | $gala-gopher-dir/pg_stat_probe.py  |                           |
| dnsmasq       | DNS会话观测能力                   | NA                                                           | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/rabbitmq_probe.sh |                           |
| lvs           | lvs会话观测能力                   | NA                                                           | NA                                       | $gala-gopher-dir/trace_lvs         | lsmod\|grep ip_vs\| wc -l |
| nginx         | Nginx L4/L7层会话观测能力          | NA                                                           | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/nginx_probe       |                           |
| haproxy       | Haproxy L4/7层会话观测能力         | NA                                                           | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/trace_haproxy     |                           |
| kafka         | kafka 生产者/消费者topic观测能力      | NA                                                           | dev, port                                | $gala-gopher-dir/kafkaprobe        |                           |
| baseinfo      | 系统基础信息                      | cpu, mem, nic, disk, net, fs, proc,host                      | proc_id, proc_name, pod_id, container_id | system_infos                       | NA                        |
| virt          | 虚拟化管理信息                     | NA                                                           | NA                                       | virtualized_infos                  | NA                        |
| tprofiling    | 线程级性能profiling观测能力          | oncpu, syscall_file, syscall_net, syscall_lock, syscall_sched | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/tprofiling        | NA                        |
| container     | 容器信息                        | NA                                                           | proc_id, proc_name, container_id         | $gala-gopher-dir/cadvisor_probe.py | NA                        |
| sermant       | Java应用7层协议观测能力，当前已支持dubbo协议 | l7_bytes_metrics、l7_rpc_metrics、               | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/sermant_probe.py  |                           |

每个探针支持的采集子项的详细说明如下：

| 采集特性          | 采集特性说明                      | 采集子项范围                                                 | 采集子项详细说明                                 |
|---------------|-----------------------------| ------------------------------------------------------------ | ---------------------------------------- |
| flamegraph    | 在线性能火焰图观测能力                 | oncpu, offcpu, mem                                           | oncpu：采集应用程序允许在cpu上时的状态，可以帮助识别出线程是如何消耗cpu资源的，以及主要耗时的函数调用<br/> offcpu：采集应用程序线程不在cpu上运行时的状态，帮助分析获取线程因执行什么操作（如等待I/O、锁）而进入offcpu<br/> mem：采集应用程序线程查询的时间范围内的内存申请的堆栈，获取内存使用情况 |
| l7            | 应用7层协议观测能力                  | l7_bytes_metrics、l7_rpc_metrics、l7_rpc_trace               | l7_bytes_metrics：采集应用程序接收及发送的数据字节数和接收和发送的数据包个数<br/> l7_rpc_metrics：采集应用程序线程接收的请求个数、发送的响应个数、请求的吞吐量、响应的吞吐量、平均时延、总时延、错误率等<br/> l7_rpc_trace：目前功能还不支持 |
| tcp           | TCP异常、状态观测能力                | tcp_abnormal, tcp_rtt, tcp_windows, tcp_rate, tcp_srtt, tcp_sockbuf, tcp_stats,tcp_delay | tcp_abnormal：tcp异常信息<br/> tcp_rtt：tcp连接数据传输的往返时间<br/> tcp_windows：tcp窗口相关信息<br/> tcp_rate：tcp传输速率<br/> tcp_srtt：tcp连接的srtt时间<br/> tcp_sockbuf：接收和发送数据的缓冲区的大小<br/> tcp_stats：tcp连接状态<br/> tcp_delay：tcp传输时延信息 |
| socket        | Socket(TCP/UDP)异常观测能力       | tcp_socket, udp_socket                                       | tcp_socket：tcp socket信息<br/> udp_socket：udp socket信息 |
| io            | Block层I/O观测能力               | io_trace, io_err, io_count, page_cache                       | io_trace：I/O请求数<br/> io_err：I/O错误信息<br/> io_count：I/O操作读和写的字节数<br/> page_cache：缓冲I/O信息 |
| proc          | 进程系统调用、I/O、DNS、VFS等观测能力     | proc_syscall, proc_fs, proc_io, proc_dns,proc_pagecache | proc_syscall：进程系统调用信息<br/> proc_fs：进程调用文件系统信息<br/> proc_io：进程I/O信息<br/> proc_dns：dns访问监控<br/> proc_pagecache：进程使用缓冲的信息 |
| jvm           | JVM层GC, 线程, 内存, 缓存等观测能力     | NA                                                           | NA |
| ksli          | Redis性能SLI（访问时延）观测能力        | NA                                                           | NA |
| postgre_sli   | PG DB性能SLI（访问时延）观测能力        | NA                                                           | NA |
| opengauss_sli | openGauss访问吞吐量观测能力          | NA                                                           | NA |
| dnsmasq       | DNS会话观测能力                   | NA                                                           | NA |
| lvs           | lvs会话观测能力                   | NA                                                           | NA |
| nginx         | Nginx L4/L7层会话观测能力          | NA                                                           | NA |
| haproxy       | Haproxy L4/7层会话观测能力         | NA                                                           | NA |
| kafka         | kafka 生产者/消费者topic观测能力      | NA                                                           | NA |
| baseinfo      | 系统基础信息                      | cpu, mem, nic, disk, net, fs, proc,host                      | cpu：cpu性能<br/> mem：内存性能<br/> nic：网卡性能<br/> disk：磁盘性能<br/> net：协议栈统计信息<br/> fs：文件系统信息<br/> proc：进程信息<br/> host：主机信息 |
| virt          | 虚拟化管理信息                     | NA                                                           | NA                                       |
| tprofiling    | 线程级性能profiling观测能力          | oncpu, syscall_file, syscall_net, syscall_lock, syscall_sched | oncpu：应用程序线程运行在cpu上时的状态，帮助识别出线程是如何消耗cpu资源，以及主要耗时的函数调用<br/> syscall_file：系统调用文件系统的信息<br/> syscall_net：系统调用的网络性能<br/> syscall_lock：系统调用死锁的次数<br/> syscall_sched：系统调用的次数 |
| container     | 容器信息                        | NA                                                           | NA |


## 配置探针扩展标签

探针上报指标数据时会根据meta文件上报相应的标签信息。此外，用户也可以通过动态配置接口增加一些扩展的标签信息进行上报。当前支持的拓展标签有：

- 固定标签

  固定标签是指具有固定值的标签，用户可以在 `snoopers` 配置选项中添加 `custom_labels` 进行配置，该标签会在探针的指标数据上报时填充进去。

  例如，通过下面的配置为 proc 探针添加一个 `task="task1"` 的标签。

  ```
  curl -X PUT http://localhost:9999/proc --data-urlencode json='
  {
      "snoopers": {
          "custom_labels": {
          	"task": "task1"
          }
      }
  }'

- Pod级标签

  Pod级标签是指 k8s 附加到 Pod 对象上的键值对，一个 Pod 对象一般包含多个 Pod 标签。用户可以在 `snoopers` 配置选项中添加 `pod_labels` 配置项来指定需要上报哪些 Pod 标签。
  
  例如，通过下面的配置为 proc 探针指定需要上报的 Pod 标签包括 "app" 和 "test"。如果配置的 Pod 标签不存在，则填充一个默认值 "not found" 。
  
  ```
  curl -X PUT http://localhost:9999/proc --data-urlencode json='
  {
      "snoopers": {
          "pod_labels": ["app", "test"]
      }
  }'
  ```
  
  注：flamegraph探针不会根据meta文件上报标签信息，配置探针扩展标签这里不适用于flamegraph探针


## 配置探针参数

探针在启动时或运行期间可以设置一些参数，这些参数同样控制了探针的行为，如果希望指定探针的采样周期和上报周期，则可以设置火焰图的采样
周期sample_period和上报周期report_period，sample_period和report_period都是配置的探针参数

```
curl -X PUT http://localhost:9999/flamegraph --data-urlencode json='
{
    "params": {
        "report_period": 180,
        "sample_period": 180,
        "metrics_type": [
            "raw",
            "telemetry"
        ]
    }
}'
```

详细参数运行参数如下：

| 参数               | 含义                                                   | 缺省值&范围                                                  | 单位    | 支持的监控范围           | gala-gopher是否支持 |
| ------------------ | ------------------------------------------------------ | ------------------------------------------------------------ | ------- | ------------------------ | ------------------- |
| sample_period      | 采样周期                                               | 5000, [100~10000]                                             | ms      | io, tcp                  | Y                   |
| report_period      | 上报周期                                               | 60, [5~600]                                                 | s       | ALL                      | Y                   |
| latency_thr        | 时延上报门限                                           | 0, [10~100000]                                               | ms      | tcp, io, proc, ksli      | Y |
| offline_thr | 进程离线上报门限 | 0, [10~100000] | ms | proc | Y |
| drops_thr          | 丢包上送门限                                           | 0, [10~100000]                                               | package | tcp, nic                 | Y                   |
| res_lower_thr      | 资源百分比下限                                         | 0%, [0%~100%]                                                | percent | ALL                      | Y                   |
| res_upper_thr      | 资源百分比上限                                         | 0%, [0%~100%]                                                | percent | ALL                      | Y                   |
| report_event       | 上报异常事件                                           | 0, [0, 1]                                                    |         | ALL                      | Y                   |
| metrics_type       | 上报telemetry metrics                                  | raw, [raw, telemetry]                                        |         | ALL                      | N                   |
| env                | 工作环境类型                                           | node, [node, container, kubenet]                             |         | ALL                      | N                   |
| report_source_port | 是否上报源端口                                         | 0, [0, 1]                                                    |         | tcp                      | Y                   |
| l7_protocol        | L7层协议范围                                           | http, [http, pgsql, mysql, redis, kafka,  mongo, rocketmq, dns] |         | l7                       | Y                   |
| support_ssl        | 支持SSL加密协议观测                                    | 0, [0, 1]                                                    |         | l7                       | Y                   |
| multi_instance | 是否每个进程输出独立火焰图 | 0, [0, 1] |  | flamegraph | Y |
| native_stack | 是否显示本地语言堆栈(针对JAVA进程) | 0, [0, 1] | | flamegraph | Y |
| cluster_ip_backend | 执行Cluster IP backend转换 | 0, [0, 1] | | tcp，l7 | Y |
| pyroscope_server   | 设置火焰图UI服务端地址                                 | localhost:4040                                               |         | flamegraph               | Y                   |
| svg_period | 火焰图svg文件生成周期 | 180, [30, 600] | s | flamegraph | Y |
| perf_sample_period | oncpu火焰图采集堆栈信息的周期 | 10, [10, 1000] | ms | flamegraph | Y |
| svg_dir | 火焰图svg文件存储目录 | "/var/log/gala-gopher/stacktrace" | | flamegraph | Y |
| flame_dir | 火焰图原始堆栈信息存储目录 | "/var/log/gala-gopher/flamegraph" | | flamegraph | Y |
| dev_name | 观测的网卡/磁盘设备名 | "" |  | io, kafka, ksli, postgre_sli，baseinfo, tcp | Y |
| continuous_sampling | 是否持续采样 | 0, [0, 1] | | ksli | Y |
| elf_path | 要观测的可执行文件的路径 | "" | | nginx, haproxy, dnsmasq | Y |
| kafka_port | 要观测的kafka端口号 | 9092, [1, 65535] | | kafka | Y |
| cadvisor_port | 启动的cadvisor端口号 | 8080, [1, 65535] | | cadvisor | Y |

注：探针参数只能配置在支持的监控范围中的探针，例如，参数sample_period对应的支持的监控范围为io和tcp，则表明参数sample_period只能配置在
io探针和tcp探针，参数report_period对应的支持的监控范围为ALL，则表明参数report_period可以配置在gala-gopher支持的所有参数的参数中


## 启动、停止探针

"state"为running时代表开启探针，"state"为stopped时代表关闭探针。开启探针时请求参数中必须带有"state"：running，否则探针不能被开启，
停止探针时请求参数中必须带有"state"："stopped"，否则探针不能被停止
```
curl -X PUT http://localhost:9999/flamegraph --data-urlencode json='
{
    "state": "running" // optional: running,stopped
}'
```



## 约束与限制说明

```
1. 接口为无状态形式，每次上传的设置为该探针的最终运行结果，包括状态、参数、监控范围。
2. 监控对象可以任意组合，监控范围取合集。
3. 启动文件必须真实有效。
4. 采集特性可以按需开启全部/部分能力，关闭时只能整体关闭某个采集特性。
5. opengauss监控对象是DB实例（IP/Port/dbname/user/password）
6. 接口每次最多接收2048长度的数据
```



## 获取探针配置与运行状态

使用GET方法，获取名为flamegraph的探针的信息，请求命令为：

```
curl -X GET http://localhost:9999/flamegraph
```

GET请求的响应如下，"state"为探针的运行状态，running代表探针是运行中的状态，其余信息均为探针的配置信息

```
curl -X GET http://localhost:9999/flamegraph
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/stackprobe",
        "check_cmd": ""
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
