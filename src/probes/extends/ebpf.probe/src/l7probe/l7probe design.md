# L7Probe探针设计

## 基本信息

定位：L7流量观测，覆盖常见的HTTP1.X、PG、MySQL、Redis、Kafka、HTTP2.0、MongoDB、RocketMQ协议，支持加密流观测。

场景：覆盖Node、Container、Pod（K8S）三类场景。



## 代码框架设计

L7Probe

   | --- included  //  公共头文件

​         | --- connect.h   // L7 connect对象定义

​         | --- pod.h   // pod/container对象定义

​         | --- conn_tracker.h   // L7协议跟踪对象定义

   | --- protocol  // L7协议解析

​          | --- http   // HTTP1.X L7 message结构定义及解析

​          | --- mysql // mysql L7 message结构定义及解析

​          | --- pgsql // pgsql L7 message结构定义及解析

   | --- bpf  // 内核bpf代码

​         | --- L7.h   // BPF程序解析L7层协议类型

​         | --- kern_sock.bpf.c   // 内核socket层观测

​         | --- libssl.bpf.c   // openSSL层观测

​         | --- gossl.bpf.c   // GO SSL层观测

​         | --- cgroup.bpf.c   // pod 生命周期观测

   | --- pod_mng.c   // pod/container实例管理（感知pod/container生命周期）

   | --- conn_mng.c   // L7 Connect实例管理（处理BPF观测事件，比如Open/Close事件、Stats统计）

   | --- conn_tracker.c   // L7 流量跟踪（跟踪BPF观测数据，比如send/write、read/recv等系统事件产生的数据）

​   | --- bpf_mng.c   // BPF程序生命周期管理（按需、实时open、load、attach、unload BPF程序，包括uprobe BPF程序）

​   | --- L7Probe.c   // 探针主程序



## 探针输出

### l7_link

| metrics_name   | table_name | metrics_type | unit  | metrics description |
| -------------- | ---------- | ------------ | ----- | ------------------- |
| tgid           |            | key          |       | 进程ID              |
| remote_ip      |            | key          |       |                     |
| remote_port    |            | key          |       |                     |
| endpoint_ip    |            | key          |       |                     |
| endpoint_port  |            | key          |       |                     |
| comm           |            | label        |       | 进程名              |
| container_id   |            | label        |       | 容器ID              |
| pod_name       |            | label        |       | k8s POD名           |
| pod_ip         |            | label        |       | k8s POD IP          |
| role           |            | label        |       | 客户端/服务端       |
| protocol       |            | label        |       | L7协议类型          |
| ssl            |            | label        |       | 是否是SSL加密连接   |
| bytes_sent     |            | Gauge        | bytes | L7连接发生字节数量  |
| bytes_received |            | Gauge        | bytes | L7连接接收字节数量  |

### l7_rpc

| metrics_name   | table_name | metrics_type | unit | metrics description                            |
| -------------- | ---------- | ------------ | ---- | ---------------------------------------------- |
| tgid           |            | key          |      | 进程ID                                         |
| remote_ip      |            | key          |      |                                                |
| remote_port    |            | key          |      |                                                |
| endpoint_ip    |            | key          |      |                                                |
| endpoint_port  |            | key          |      |                                                |
| comm           |            | label        |      | 进程名                                         |
| container_id   |            | label        |      | 容器ID                                         |
| pod_name       |            | label        |      | k8s POD名                                      |
| pod_ip         |            | label        |      | k8s POD IP                                     |
| role           |            | label        |      | 客户端/服务端                                  |
| protocol       |            | label        |      | L7协议类型                                     |
| ssl            |            | label        |      | 是否是SSL加密连接                              |
| req_throughput |            | Gauge        | x/s  | L7连接request吞吐量（包括HTTP/DB/REDIS）       |
| rsp_throughput |            | Gauge        | x/s  | L7连接response吞吐量（包括HTTP/DB/REDIS）      |
| latency        |            | Gauge        | ms   | L7连接request访问时延（包括HTTP/DB/REDIS）     |
| p50_latency    |            | Gauge        | ms   | L7连接P50 request访问时延（包括HTTP/DB/REDIS） |
| p90_latency    |            | Gauge        | ms   | L7连接P90 request访问时延（包括HTTP/DB/REDIS） |
| p99_latency    |            | Gauge        | ms   | L7连接P99 request访问时延（包括HTTP/DB/REDIS） |
| error_rate     |            | Gauge        | %    | L7连接Request访问错误率（包括HTTP/DB/REDIS）   |

### l7_trace

| metrics_name  | table_name | metrics_type | unit | metrics description                      |
| ------------- | ---------- | ------------ | ---- | ---------------------------------------- |
| tgid          |            | key          |      | 进程ID                                   |
| remote_ip     |            | key          |      |                                          |
| remote_port   |            | key          |      |                                          |
| endpoint_ip   |            | key          |      |                                          |
| endpoint_port |            | key          |      |                                          |
| comm          |            | label        |      | 进程名                                   |
| container_id  |            | label        |      | 容器ID                                   |
| pod_name      |            | label        |      | k8s POD名                                |
| pod_ip        |            | label        |      | k8s POD IP                               |
| role          |            | label        |      | 客户端/服务端                            |
| protocol      |            | label        |      | L7协议类型                               |
| ssl           |            | label        |      | 是否是SSL加密连接                        |
| req_method    |            | label        |      | L7连接request方法名（包括HTTP/DB/REDIS） |
| req_path      |            | label        |      | L7连接request path（包括HTTP/DB/REDIS）  |
| resp_code     |            | label        |      | L7连接response code（包括HTTP/DB/REDIS） |
| resp_body     |            | label        |      | L7连接response body（包括HTTP/DB/REDIS） |

### pod

| metrics_name  | table_name | metrics_type | unit  | metrics description    |
| ------------- | ---------- | ------------ | ----- | ---------------------- |
| pod_name      |            | key          |       | k8s POD名              |
| pod_ip        |            | label        |       | k8s POD IP             |
| container_cnt |            | Gauge        |       | K8S pod内容器数量      |
| cpu           |            | Gauge        |       | CPU占用率              |
| network_tx    |            | Gauge        | bytes | K8S Pod 网络发送字节数 |
| network_rx    |            | Gauge        | bytes | K8S Pod 网络接收字节数 |
| bytes_read    |            | Gauge        | bytes | K8S Pod I/O读取字节数  |
| bytes_write   |            | Gauge        | bytes | K8S Pod I/O写入字节数  |
| vm            |            | Gauge        | bytes | K8S Pod 虚拟内存字节数 |
| rss           |            | Gauge        | bytes | K8S Pod 物理内存字节数 |

## 动态控制

### 控制观测Pod范围

1. REST->gala-gopher
1. gala-gopher->L7Probe
1. L7Probe 基于Pod获取相关Container
2. L7Probe 基于Container获取其 CGroup id（cpuacct_cgrp_id），并写入object模块（API: cgrp_add）
2. Socket系统事件上下文中，获取进程所属CGroup（cpuacct_cgrp_id），参考Linux代码（task_cgroup）
2. 观测过程中，通过object模块过滤（API: is_cgrp_exist）



### 控制观测能力

1. REST->gala-gopher
2. gala-gopher->L7Probe
3. L7Probe根据输入参数动态的开启、关闭BPF观测能力（包括吞吐量、时延、Trace、协议类型）





 