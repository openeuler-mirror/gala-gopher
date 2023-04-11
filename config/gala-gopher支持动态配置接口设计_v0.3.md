# Rest API设计

 WEB server端口可配置（缺省9999），URL组织方式 http://gala-gopher + [端口号] + function（采集特性），比如火焰图的URL：http://gala-gopher:9999/flamegraph/



## 探针监控范围API

探针默认关闭，可以通过API动态开启、设置监控范围。以火焰图为例，通过REST分别开启oncpu/offcpu/mem火焰图能力。并且监控范围支持进程ID、进程名、容器ID、POD四个维度来设置。

下面是火焰图同时开启oncpu, offcpu采集特性的API举例：

```
curl -X POST http://gala-gopher:9999/flamegraph/
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/stackprobe", 
        "check_cmd": ""
    }, 
    "probes": [
        {
            "probe": [
                "oncpu", 
                "offcpu"
            ], 
            "proc_id": [
                101, 
                102
            ], 
            "proc_name": [
                {
                    "comm": "app1", 
                    "cmdline": "",
                    "debuing_dir": ""
                }, 
                {
                    "comm": "app2", 
                    "cmdline": "",
                    "debuing_dir": ""
                }
            ], 
            "pod": [
                "pod1", 
                "pod2"
            ], 
            "container_id": [
                "container1", 
                "container2"
            ]
        }
    ]
}
```

通过REST关闭火焰图的采集能力

```
curl -X POST http://gala-gopher:9999/flamegraph/
{
    "switch": "off"
}
```

详细采集能力REST接口定义如下：

```
1. 监控对象可以任意组合，监控范围取合集。
2. 启动文件必须真实有效。
3. 采集特性可以按需开启全部/部分能力，关闭时只能整体关闭某个采集特性。
4. opengauss监控对象是DB实例（IP/Port/dbname/user/password）
```

| 采集特性      | 采集特性说明                                             | 采集子项范围                                                 | 监控对象                              | 启动文件                           | 启动条件                  |
| ------------- | -------------------------------------------------------- | ------------------------------------------------------------ | ------------------------------------- | ---------------------------------- | ------------------------- |
| flamegraph    | 在线性能火焰图观测能力                                   | oncpu, offcpu, mem                                           | proc_id, proc_name, pod, container_id | $gala-gopher-dir/stackprobe        |                           |
| l7            | 应用7层协议观测能力                                      | l7_bytes_metrics、l7_rpc_metrics、l7_rpc_trace               | proc_id, proc_name, pod, container_id | $gala-gopher-dir/l7probe           |                           |
| tcp           | TCP异常、状态观测能力                                    | tcp_abnormal, tcp_rtt, tcp_windows, tcp_rate, tcp_srtt, tcp_sockbuf, tcp_stats | proc_id, proc_name, pod, container_id | $gala-gopher-dir/tcpprobe          |                           |
| socket        | Socket(TCP/UDP)异常观测能力                              | tcp_socket, udp_socket                                       | proc_id, proc_name, pod, container_id | $gala-gopher-dir/endpoint          |                           |
| io            | Block层I/O观测能力                                       | io_trace, io_err, io_count, page_cache                       | NA                                    | $gala-gopher-dir/ioprobe           |                           |
| proc          | 进程系统调用、I/O、DNS、VFS等观测能力                    | base_metrics, proc_syscall, proc_fs, proc_io, proc_dns,proc_pagecache | proc_id, proc_name, pod, container_id | $gala-gopher-dir/taskprobe         |                           |
| jvm           | JVM层GC, 线程, 内存, 缓存等观测能力                      | NA                                                           | proc_id, proc_name, pod, container_id | $gala-gopher-dir/JvmProbe.jar      |                           |
| redis_sli     | Redis性能SLI（访问时延）观测能力                         | NA                                                           | proc_id, proc_name, pod, container_id | $gala-gopher-dir/ksliprobe         |                           |
| postgre_sli   | PG DB性能SLI（访问时延）观测能力                         | NA                                                           | proc_id, proc_name, pod, container_id | $gala-gopher-dir/pgsliprobe        |                           |
| opengauss_sli | openGauss访问吞吐量观测能力                              | NA                                                           | [ip, port, dbname, user,password]     | $gala-gopher-dir/pg_stat_probe.py  |                           |
| dnsmasq       | DNS会话观测能力                                          | NA                                                           | proc_id, proc_name, pod, container_id | $gala-gopher-dir/rabbitmq_probe.sh |                           |
| lvs           | lvs会话观测能力                                          | NA                                                           | NA                                    | $gala-gopher-dir/trace_lvs         | lsmod\|grep ip_vs\| wc -l |
| nginx         | Nginx L4/L7层会话观测能力                                | NA                                                           | proc_id, proc_name, pod, container_id | $gala-gopher-dir/nginx_probe       |                           |
| haproxy       | Haproxy L4/7层会话观测能力                               | NA                                                           | proc_id, proc_name, pod, container_id | $gala-gopher-dir/trace_haproxy     |                           |
| kafka         | kafka 生产者/消费者topic观测能力                         | NA                                                           | dev, port                             | $gala-gopher-dir/kafkaprobe        |                           |
| baseinfo      | 系统基础信息（包括cpu, mem, nic, disk, net, fs, host等） | NA                                                           | NA                                    | system_infos                       | NA                        |
| virt          | 虚拟化管理信息                                           | NA                                                           | NA                                    | virtualized_infos                  | NA                        |

## 探针运行参数

探针在运行期间还需要设置一些参数设置，例如：设置火焰图的采样周期、上报周期

```
curl -X POST http://gala-gopher:9999/flamegraph/
{
    "params": [
        {
            "report_period": 180
        }
    ]
}
```

详细参数运行参数如下：

| 参数               | 含义                                                   | 缺省值&范围                                                  | 单位    | 支持的监控范围           | gala-gopher是否支持 |
| ------------------ | ------------------------------------------------------ | ------------------------------------------------------------ | ------- | ------------------------ | ------------------- |
| sample_period      | 采样周期                                               | 100, [100~10000]                                             | ms      | io                       | Y                   |
| report_period      | 上报周期                                               | 5, [5~600]                                                   | s       | ALL                      | Y                   |
| latency_thr        | 时延上报门限                                           | 0, [10~100000]                                               | ms      | tcp, io, proc, redis_sli |                     |
| drops_thr          | 丢包上送门限                                           | 0, [10~100000]                                               | package | tcp, nic                 | Y                   |
| res_lower_thr      | 资源百分比下限                                         | 0%, [0%~100%]                                                | percent | ALL                      | Y                   |
| res_upper_thr      | 资源百分比上限                                         | 0%, [0%~100%]                                                | percent | ALL                      | Y                   |
| report_event       | 上报异常事件                                           | 0, [0, 1]                                                    |         | ALL                      | Y                   |
| metrics_type       | 上报telemetry metrics                                  | raw, [raw, telemetry]                                        |         | ALL                      | N                   |
| env                | 工作环境类型                                           | [node, container, kubenet]                                   |         | ALL                      | N                   |
| report_source_port | 是否上报源端口                                         | 0, [0, 1]                                                    |         | tcp                      | Y                   |
| l7_protocol        | L7层协议范围                                           | http1.x, [http1.x, postgresql, mysql, redis, kafka, http2.0, mongodb, rocketmq, dns] |         | l7                       | Y                   |
| support_ssl        | 支持SSL加密协议观测                                    | 0, [0, 1]                                                    |         | l7                       | Y                   |
| svg_dir            | 设置火焰图svg文件存储路径                              | /var/log/gala-gopher/stacktrace                              |         | flamegraph               | Y                   |
| flame_dir          | 设置火焰图flame graph文件存储路径                      | /var/log/gala-gopher/stacktrace/logs                         |         | flamegraph               | Y                   |
| pyroscope_server   | 设置火焰图UI服务端地址                                 | localhost:4040                                               |         | flamegraph               | Y                   |
| debuging_dir       | 设置系统debuging文件目录（用于查找火焰图内的函数符号） |                                                              |         | flamegraph               | Y                   |
| log_dir            | 设置探针日志目录                                       | /var/log/gala-gopher/[probe]/logs                            |         | ALL                      | Y                   |



## 探针运行状态

```
curl -X GET http://gala-gopher:9999/probe_status
{
    "probes": [
        {
            "probe": [
                "oncpu", 
                "offcpu"
            ], 
            "proc_id": [
                101, 
                102
            ], 
            "proc_name": [
                {
                    "comm": "app1", 
                    "cmdline": ""
                }, 
                {
                    "comm": "app2", 
                    "cmdline": ""
                }
            ], 
            "pod": [
                "pod1", 
                "pod2"
            ], 
            "container_id": [
                "container1", 
                "container2"
            ]
        }
    ]
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



  