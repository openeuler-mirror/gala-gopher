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

   | --- bpf_mng.c   // BPF程序生命周期管理（按需、实时open、load、attach、unload BPF程序，包括uprobe BPF程序）

   | --- session_conn.c   // 管理jsse Session（记录jsse Session和sock连接的对应关系，上报jsse连接信息）

   | --- L7Probe.c   // 探针主程序


## 探针输出

### l7_link

| metrics_name | table_name | metrics_type | unit  | metrics description                               |
|--------------| ---------- | ------------ | ----- |---------------------------------------------------|
| tgid         |            | key          |       | 进程ID                                              |
| client_ip    |            | key          |       | 客户端IP                                             |
| server_ip    |            | key          |       | 服务端IP<br/>备注：k8s场景支持Cluster IP转换成Backend IP       |
| server_port  |            | key          |       | 服务端Port<br/>备注：k8s场景支持Cluster Port转换成Backend Port |
| l4_role      |            | key          |       | l4角色（tcp_client/tcp_server/udp                    |
| l7_role      |            | key          |       | l7角色（client/server)                               |
| protocol     |            | key          |       | l7协议（http/http2/pgsql/mysql/...）                  |
| comm         |            | label        |       | 进程名                                               |
| container_id |            | label        |       | 容器ID                                              |
| pod_name     |            | label        |       | k8s POD名                                          |
| pod_ip       |            | label        |       | k8s POD IP                                        |
| ssl          |            | label        |       | 是否是SSL加密连接                                        |
| machine_id   |            | label        |       | 节点实例id                                            |
| bytes_sent   |            | Gauge        | bytes | L7连接发送字节数量                                        |
| bytes_recv   |            | Gauge        | bytes | L7连接接收字节数量                                        |
| segs_sent    |            | label        |       | l7连接发送segs数量                                      |
| segs_recv    |            | label        |       | l7连接接收segs数量                                      |

### l7_rpc

| metrics_name   | table_name | metrics_type | unit | metrics description                               |
|----------------| ---------- |--------------|------|---------------------------------------------------|
| tgid           |            | key          |      | 进程ID                                              |
| client_ip      |            | key          |      | 客户端IP                                             |
| server_ip      |            | key          |      | 服务端IP<br/>备注：k8s场景支持Cluster IP转换成Backend IP       |
| server_port    |            | key          |      | 服务端Port<br/>备注：k8s场景支持Cluster Port转换成Backend Port |
| l4_role        |            | key          |      | l4角色（tcp_client/tcp_server/udp                    |
| l7_role        |            | key          |      | l7角色（client/server)                               |
| protocol       |            | key          |      | l7协议（http/http2/pgsql/mysql/...）                  |
| comm           |            | label        |      | 进程名                                               |
| container_id   |            | label        |      | 容器ID                                              |
| pod_name       |            | label        |      | k8s POD名                                          |
| pod_ip         |            | label        |      | k8s POD IP                                        |
| ssl            |            | label        |      | 是否是SSL加密连接                                        |
| machine_id     |            | label        |      | 节点实例id                                            |
| req_throughput |            | Gauge        | qps  | L7连接request吞吐量（包括HTTP/DB/REDIS）                   |
| rsp_throughput |            | Gauge        | qps  | L7连接response吞吐量（包括HTTP/DB/REDIS）                  |
| latency_avg    |            | Gauge        | ns   | L7连接request平均访问时延（包括HTTP/DB/REDIS）                |
| latency        |            | Histogram    | ns   | L7连接request访问时延（包括HTTP/DB/REDIS）                  |
| latency_sum    |            | Gauge        | ns   | L7连接P50 request访问时延总和（包括HTTP/DB/REDIS）            |
| error_ratio    |            | Gauge        | %    | L7连接Request访问错误率（包括HTTP/DB/REDIS）                 |
| error_count    |            | Gauge        |      | L7连接Request访问错误总数（包括HTTP/DB/REDIS）                |


### l7_trace

| metrics_name  | table_name | metrics_type | unit | metrics description                      |
| ------------- | ---------- | ------------ | ---- | ---------------------------------------- |
| tgid           |            | key          |      | 进程ID                                              |
| client_ip      |            | key          |      | 客户端IP                                             |
| server_ip      |            | key          |      | 服务端IP<br/>备注：k8s场景支持Cluster IP转换成Backend IP       |
| server_port    |            | key          |      | 服务端Port<br/>备注：k8s场景支持Cluster Port转换成Backend Port |
| l4_role        |            | key          |      | l4角色（tcp_client/tcp_server/udp                    |
| l7_role        |            | key          |      | l7角色（client/server)                               |
| protocol       |            | key          |      | l7协议（http/http2/pgsql/mysql/...）                  |
| comm           |            | label        |      | 进程名                                               |
| container_id   |            | label        |      | 容器ID                                              |
| pod_name       |            | label        |      | k8s POD名                                          |
| pod_ip         |            | label        |      | k8s POD IP                                        |
| ssl            |            | label        |      | 是否是SSL加密连接                                        |
| machine_id     |            | label        |      | 节点实例id                                            |
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





## 观测点

### 内核Socket系统调用

TCP相关系统调用

// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

// int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

// int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);

// ssize_t write(int fd, const void *buf, size_t count);

// ssize_t send(int sockfd, const void *buf, size_t len, int flags);

// ssize_t read(int fd, void *buf, size_t count);

// ssize_t recv(int sockfd, void *buf, size_t len, int flags);

// ssize_t writev(int fd, const struct iovec *iov, int iovcnt);

// ssize_t readv(int fd, const struct iovec *iov, int iovcnt);



TCP&UDP相关系统调用

// ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);

// ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);

// ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);

// ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);

// int close(int fd);



注意点：

1. read/write、readv/writev 与普通的文件I/O操作会混淆，通过观测内核security_socket_sendmsg函数区分FD是否属于socket操作。
2. sendto/recvfrom、sendmsg/recvmsg  TCP/UDP均会使用，参考下面手册的介绍。
3. sendmmsg/recvmmsg、sendfile 暂不支持。

[sendto manual](https://man7.org/linux/man-pages/man2/send.2.html)  ：If sendto() is used on a connection-mode (SOCK_STREAM, SOCK_SEQPACKET) socket, the arguments dest_addr and addrlen are ignored (and the error EISCONN may be returned when they are not       NULL and 0), and the error ENOTCONN is returned when the socket was not actually connected.  otherwise, the address of the target is given by dest_addr with addrlen specifying its size.

sendto 判断dest_addr参数为NULL则为TCP，否则为UDP。



[recvfrom manual](https://linux.die.net/man/2/recvfrom)：The recvfrom() and recvmsg() calls are used to receive messages from a socket, and may be used to receive data on a socket whether or not it is connection-oriented.

recvfrom判断src_addr参数为NULL则为TCP，否则为UDP。



[sendmsg manual](https://man7.org/linux/man-pages/man3/sendmsg.3p.html)：The sendmsg() function shall send a message through a connection-mode or connectionless-mode socket. If the socket is a connectionless-mode socket, the message shall be sent to the address specified by msghdr if no pre-specified peer address has been set. If a peer address has been pre-specified, either themessage shall be sent to the address specified in msghdr (overriding the pre-specified peer address), or the function shall return -1 and set errno to [EISCONN].  If the socket is       connection-mode, the destination address in msghdr shall be ignored.

sendmsg判断msghdr->msg_name参数为NULL则为TCP，否则为UDP。



[recvmsg manual](https://man7.org/linux/man-pages/man3/recvmsg.3p.html): The recvmsg() function shall receive a message from a connection-mode or connectionless-mode socket. It is normally used with connectionless-mode sockets because it permits the application to retrieve the source address of received data.

recvmsg判断msghdr->msg_name参数为NULL则为TCP，否则为UDP。

### libSSL API

SSL_write

SSL_read

### Go SSL API

### JSSE API

sun/security/ssl/SSLSocketImpl$AppInputStream

sun/security/ssl/SSLSocketImpl$AppOutputStream

## JSSE观测方案

### 加载JSSEProbe探针

main函数中通过l7_load_jsse_agent加载JSSEProbe探针。

轮询观测白名单(g_proc_obj_map_fd)中的进程，若为java进程，则通过jvm_attach将JSSEProbeAgent.jar加载到此观测进程上。加载成功后，该java进程会在指定观测点（参见[JSSE API](###JSSE-API)）将观测信息输出到jsse-metrics输出文件（/tmp/java-data-<pid>/jsse-metrics.txt）中。

### 处理JSSEProbe消息

l7_jsse_msg_handler线程中处理JSSEProbe消息。

轮询观测白名单(g_proc_obj_map_fd)中的进程，若该进程有对应的jsse-metrics输出文件，则按行读取此文件并解析、转换、上报jsse读写信息。

#### 1. 解析jsse读写信息

jsse-metrics.txt的输出格式如下，从中解析出一次jsse请求的pid, sessionId, time, read/write操作, IP, port, payload信息：
```|jsse_msg|662220|Session(1688648699909|TLS_AES_256_GCM_SHA384)|1688648699989|Write|127.0.0.1|58302|This is test message|```

解析出的原始信息存储于session_data_args_s中。

#### 2. 转换jsse读写信息

将session_data_args_s中的信息转换为sock_conn和conn_data。

转化时需要查询如下两个hash map：

session_head：记录jsse连接的session Id和sock connection Id的对应关系。若进程id和四元组信息一致，则认为session和sock connection对应。

file_conn_head：记录java进程的最后一个sessionId，以备L7probe读jsseProbe输出时，没有从请求开头开始读取，找不到sessionId信息。

#### 3. 上报jsse读写信息

将sock_conn和conn_data上报到map中。







