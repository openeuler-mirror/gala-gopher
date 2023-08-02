# Rest API设计

 WEB server端口可配置（缺省9999），URL组织方式 http://[gala-gopher所在节点ip] + [端口号] + function（采集特性），比如火焰图的URL：http://localhost:9999/flamegraph



## 探针监控范围API

探针默认关闭，可以通过API动态开启、设置监控范围。以火焰图为例，通过REST分别开启oncpu/offcpu/mem火焰图能力。并且监控范围支持进程ID、进程名、容器ID、POD四个维度来设置。

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

通过REST开启、关闭火焰图的采集能力

```
curl -X PUT http://localhost:9999/flamegraph --data-urlencode json='
{
    "state": "running" // optional: running,stopped
}'
```

详细采集能力REST接口定义如下：

```
1. 接口为无状态形式，每次上传的设置为该探针的最终运行结果，包括状态、参数、监控范围。
2. 监控对象可以任意组合，监控范围取合集。
3. 启动文件必须真实有效。
4. 采集特性可以按需开启全部/部分能力，关闭时只能整体关闭某个采集特性。
5. opengauss监控对象是DB实例（IP/Port/dbname/user/password）
6. 接口每次最多接收2048长度的数据
```

| 采集特性      | 采集特性说明                          | 采集子项范围                                                 | 监控对象                                 | 启动文件                           | 启动条件                  |
| ------------- | ------------------------------------- | ------------------------------------------------------------ | ---------------------------------------- | ---------------------------------- | ------------------------- |
| flamegraph    | 在线性能火焰图观测能力                | oncpu, offcpu, mem                                           | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/stackprobe        |                           |
| l7            | 应用7层协议观测能力                   | l7_bytes_metrics、l7_rpc_metrics、l7_rpc_trace               | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/l7probe           |                           |
| tcp           | TCP异常、状态观测能力                 | tcp_abnormal, tcp_rtt, tcp_windows, tcp_rate, tcp_srtt, tcp_sockbuf, tcp_stats | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/tcpprobe          |                           |
| socket        | Socket(TCP/UDP)异常观测能力           | tcp_socket, udp_socket                                       | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/endpoint          |                           |
| io            | Block层I/O观测能力                    | io_trace, io_err, io_count, page_cache                       | NA                                       | $gala-gopher-dir/ioprobe           |                           |
| proc          | 进程系统调用、I/O、DNS、VFS等观测能力 | base_metrics, proc_syscall, proc_fs, proc_io, proc_dns,proc_pagecache | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/taskprobe         |                           |
| jvm           | JVM层GC, 线程, 内存, 缓存等观测能力   | NA                                                           | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/jvmprobe          |                           |
| ksli          | Redis性能SLI（访问时延）观测能力      | NA                                                           | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/ksliprobe         |                           |
| postgre_sli   | PG DB性能SLI（访问时延）观测能力      | NA                                                           | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/pgsliprobe        |                           |
| opengauss_sli | openGauss访问吞吐量观测能力           | NA                                                           | [ip, port, dbname, user,password]        | $gala-gopher-dir/pg_stat_probe.py  |                           |
| dnsmasq       | DNS会话观测能力                       | NA                                                           | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/rabbitmq_probe.sh |                           |
| lvs           | lvs会话观测能力                       | NA                                                           | NA                                       | $gala-gopher-dir/trace_lvs         | lsmod\|grep ip_vs\| wc -l |
| nginx         | Nginx L4/L7层会话观测能力             | NA                                                           | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/nginx_probe       |                           |
| haproxy       | Haproxy L4/7层会话观测能力            | NA                                                           | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/trace_haproxy     |                           |
| kafka         | kafka 生产者/消费者topic观测能力      | NA                                                           | dev, port                                | $gala-gopher-dir/kafkaprobe        |                           |
| baseinfo      | 系统基础信息                          | cpu, mem, nic, disk, net, fs, proc,host                      | NA                                       | system_infos                       | NA                        |
| virt          | 虚拟化管理信息                        | NA                                                           | NA                                       | virtualized_infos                  | NA                        |
| tprofiling    | 线程级性能profiling观测能力           | oncpu, syscall_file, syscall_net, syscall_lock, syscall_sched | proc_id, proc_name                       | $gala-gopher-dir/tprofiling        | NA                        |

## 探针运行参数

探针在运行期间还需要设置一些参数设置，例如：设置火焰图的采样周期、上报周期

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
| sample_period      | 采样周期                                               | 100, [100~10000]                                             | ms      | io                       | Y                   |
| report_period      | 上报周期                                               | 5, [5~600]                                                   | s       | ALL                      | Y                   |
| latency_thr        | 时延上报门限                                           | 0, [10~100000]                                               | ms      | tcp, io, proc, ksli      |                     |
| drops_thr          | 丢包上送门限                                           | 0, [10~100000]                                               | package | tcp, nic                 | Y                   |
| res_lower_thr      | 资源百分比下限                                         | 0%, [0%~100%]                                                | percent | ALL                      | Y                   |
| res_upper_thr      | 资源百分比上限                                         | 0%, [0%~100%]                                                | percent | ALL                      | Y                   |
| report_event       | 上报异常事件                                           | 0, [0, 1]                                                    |         | ALL                      | Y                   |
| metrics_type       | 上报telemetry metrics                                  | raw, [raw, telemetry]                                        |         | ALL                      | N                   |
| env                | 工作环境类型                                           | node, [node, container, kubenet]                             |         | ALL                      | N                   |
| report_source_port | 是否上报源端口                                         | 0, [0, 1]                                                    |         | tcp                      | Y                   |
| l7_protocol        | L7层协议范围                                           | http, [http, postgresql, mysql, redis, kafka,  mongodb, rocketmq, dns] |         | l7                       | Y                   |
| support_ssl        | 支持SSL加密协议观测                                    | 0, [0, 1]                                                    |         | l7                       | Y                   |
| multi_instance | 是否每个进程输出独立火焰图 | 0, [0, 1] |  | flamegraph | Y |
| native_stack | 是否显示本地语言堆栈(针对JAVA进程) | 0, [0, 1] | | flamegraph | Y |
| pyroscope_server   | 设置火焰图UI服务端地址                                 | localhost:4040                                               |         | flamegraph               | Y                   |
| svg_period | 火焰图svg文件生成周期 | 180, [30, 600] | s | flamegraph | Y |
| perf_sample_period | oncpu火焰图采集堆栈信息的周期 | 10, [10, 1000] | ms | flamegraph | Y |
| svg_dir | 火焰图svg文件存储目录 | "/var/log/gala-gopher/stacktrace" | | flamegraph | Y |
| flame_dir | 火焰图原始堆栈信息存储目录 | "/var/log/gala-gopher/flamegraph" | | flamegraph | Y |
| dev_name | 观测的网卡/磁盘设备名 | "" |  | io, kafka, ksli, postgre_sli，baseinfo | Y |
| continuous_sampling | 是否持续采样 | 0, [0, 1] | | ksli | Y |
| elf_path | 要观测的可执行文件的路径 | "" | | nginx, haproxy, dnsmasq | Y |
| kafka_port | 要观测的kafka端口号 | 9092, [1, 65535] | | kafka | Y |



## 探针运行状态

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
    }
}
```





# 代码框架设计

src

   | --- api

​         | --- rest_server.c   // rest 服务端

   | --- lib

​         | --- probe

​                     | --- probe_mng.c  	// 探针生命周期管理

​                     | --- snooper.c  	// 监控对象管理，包括处理内核侧收集的动态生成的监控对象信息

​                     | --- snooper.bpf.c  // 内核侧eBPF代码，用于侦听动态生成的监控对象



# 逻辑设计



![./design.png]()



