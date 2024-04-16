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
```|jsse_msg|662220|Session(1688648699909|TLS_AES_256_GCM_SHA384)|1688648699989|Write|s|127.0.0.1|58302|This is test message|```

解析出的原始信息存储于session_data_args_s中。

#### 2. 转换jsse读写信息

将session_data_args_s中的信息转换为sock_conn和conn_data。

转化时需要查询如下两个hash map：

session_head：记录jsse连接的session Id和sock connection Id的对应关系。若进程id和四元组信息一致，则认为session和sock connection对应。

file_conn_head：记录java进程的最后一个sessionId，以备L7probe读jsseProbe输出时，没有从请求开头开始读取，找不到sessionId信息。

#### 3. 上报jsse读写信息

将sock_conn和conn_data上报到map中。



## libSSL 应用场景

在基于 libSSL 的加密应用场景中，可以通过添加 eBPF 程序挂载 SSL_read\SSL_write 钩子点来获取解密后的网络数据。但是，在 SSL_read\SSL_write 的 eBPF 程序执行过程中，有时候会出现从 SSL 结构体中获取的 socket fd （对于 SSL_read 函数，对应 `s->rbio->num` 的值）为 0 的情况，从而导致无法关联到对应的 tcp 连接上。一个实际的问题场景就是监控 apache 的 httpd 应用程序时，获取的 socket fd 值就是 0。

```c
int SSL_read(SSL *s, void *buf, int num);
int SSL_write(SSL *s, const void *buf, int num);
```

这里先给出分析结论：以 SSL_read 函数为例，它在执行的过程中最终会调用 SSL 结构体的 BIO 结构体中的 bread 函数来读取 tcp 连接的网络数据。bread 是一个钩子函数，上层应用可以根据自己的实现方案来改变 bread 函数的行为，这就导致了使用 libSSL 库的不同上层应用可以以不同的实现方式读取 tcp 连接数据。

- 在通用的应用场景下，应用在初始化 SSL 结构体时会关联一个 tcp 连接的 socket fd，最终在 bread 函数中使用这个 socket fd 来读取 tcp 连接数据。因此，在该场景下可以成功获取到 socket fd 的值。
- 在一些应用场景下，以 apache httpd 应用程序为例，应用在初始化 SSL 结构体时不会设置 socket fd，而是将其封装到一个连接上下文中。此外，httpd 会实现自定义的 bread 函数，并从中读取连接上下文信息，最终读取 tcp 连接数据。因此，在这种场景下获取到 socket fd 的值就是 0，此时需要根据上层应用的具体实现来间接地获取 socket fd 的值。

在 l7 探针中，目前只支持了基于 libSSL 的通用加密应用场景，对于非通用加密应用场景，后续会根据实际的上层应用场景的需要进行扩展。

下面分别介绍一下基于通用应用场景和基于 httpd 应用场景的分析流程。

### 通用应用场景下的 libSSL tcp 通信流程

以服务端为例，一个 tcp 连接的 SSL 加密通信的接收流程大致为：

1. 创建 tcp 监听 socket，启动监听服务，接收客户端连接：socket()->bind()->listen()->accept()，获取 tcp 连接的 socket fd。

   ```c
   sockfd = socket(PF_INET, SOCK_STREAM, 0));
   bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr);
   listen(sockfd, lisnum);
   new_fd = accept(sockfd, (struct sockaddr *) &client_addr, &len));
   ```

2. 建立 SSL 连接

   ```c
   // 初始化 SSL 上下文
   ctx = SSL_ctx_new(SSLv3_server_method());
   // 基于 ctx 产生一个新的 SSL
   ssl = SSL_new(ctx);
   // 将 tcp 连接的 socket fd 加入到 SSL
   SSL_set_fd(ssl, new_fd);
   // 建立 SSL 连接
   SSL_accept(ssl);
   ```

3. 接收客户端消息

   ```c
   SSL_read(ssl, buf, MAXBUF);
   ```

其中，在建立 SSL 连接时，一个关键的步骤是调用 SSL_set_fd 函数将当前 tcp 连接的 socket fd 加入到 SSL 结构体中。SSL_set_fd 在 libSSL 库中实现，代码为，

```c
// OpenSSL_1_1_1f
int SSL_set_fd(SSL *s, int fd)
{
    int ret = 0;
    BIO *bio = NULL;

    bio = BIO_new(BIO_s_socket());

    if (bio == NULL) {
        SSLerr(SSL_F_SSL_SET_FD, ERR_R_BUF_LIB);
        goto err;
    }
    BIO_set_fd(bio, fd, BIO_NOCLOSE);
    SSL_set_bio(s, bio, bio);
    ret = 1;
 err:
    return ret;
}
```

它调用 BIO_new() 并传入 BIO_s_socket() 参数来初始化 bio->method ，前面提到的 bread 函数会在这里初始化为BIO_s_socket() 提供的  sock_read() 函数。同时，它会将当前 tcp 连接的 socket fd 赋值到 `bio->num` 中去。

sock_read() 函数的部分代码如下，它会调用 read 函数读取 `bio->num` 指定的 tcp 连接的网络数据。

```c
// OpenSSL_1_1_1f
#  define readsocket(s,b,n)           read((s),(b),(n))

static int sock_read(BIO *b, char *out, int outl)
{
    int ret = 0;

    if (out != NULL) {
        ...
        ret = readsocket(b->num, out, outl);
        ...
    }
    return ret;
}
```

**总结一下，SSL_read 最终会调用 SSL 结构体的 BIO 结构体中的 bread 函数（对于socket通信场景即为 sock_read函数），读取当前 tcp 连接的网络数据。每个tcp连接初始化一个 SSL 结构体变量，并通过设置 socket fd 关联到对应的 tcp 连接。**

### httpd 应用场景下的 libSSL tcp 通信流程

对于 httpd 应用场景，我们主要需要关注两个点：

- 确定 bread 实际对应的函数。
- 分析 bread 函数的执行逻辑，确定它是如何关联到对应的 tcp 连接上。

考虑到 httpd 的源码比较复杂，这里直接给出 bread 实际对应的函数为 bio_filter_in_read 函数，它是 httpd 应用提供的函数。

```c
static int bio_filter_in_read(BIO *bio, char *in, int inlen)
{
    apr_size_t inl = inlen;
    bio_filter_in_ctx_t *inctx = (bio_filter_in_ctx_t *)BIO_get_data(bio);
    apr_read_type_e block = inctx->block;

    if (APR_BRIGADE_EMPTY(inctx->bb)) {

        inctx->rc = ap_get_brigade(inctx->f->next, inctx->bb,
                                   AP_MODE_READBYTES, block,
                                   inl);
		...
    }
    ...
}
```

bio_filter_in_read 函数的核心逻辑为：首先调用（libSSL提供的） BIO_get_data 函数从 bio 中获取 bio_filter_in_ctx_t 类型的过滤上下文 inctx；接下来调用 ap_get_brigade 函数。ap_get_brigade 函数的执行过程比较复杂，这里我们只需要知道它最终会读取到当前 tcp 连接的网络数据即可。

在这里我们需要弄清楚一个问题，bio_filter_in_read 函数执行过程中是如何关联到当前的 tcp 连接上？首先可以看到，它并没有使用到代表当前 tcp 连接的 fd 字段 `bio->num` ，实际上 httpd 在初始化 SSL 结构体时也确实没有设置 `bio->num` 的值。这可以从 `bio_filter_in_ctx_t *inctx` 中找到一些答案。

下面是 bio_filter_in_ctx_t 结构体以及相关的结构体的部分内容。成员 `inctx->f->c` 的类型为 struct conn_rec，其中携带了当前 tcp 连接的连接信息。

```c
typedef struct {
    SSL *ssl;
    ap_filter_t *f;
} bio_filter_in_ctx_t;

struct ap_filter_t {
    /** The internal representation of this filter.  This includes
     *  the filter's name, type, and the actual function pointer.
     */
    ap_filter_rec_t *frec;

    /** The conn_rec associated with the current filter.  This is analogous
     *  to the request_rec, except that it is used for connection filters.
     */
    conn_rec *c;
};

struct conn_rec {
    /* Information about the connection itself */
    /** local address */
    apr_sockaddr_t *local_addr;
    /** remote address; this is the end-point of the next hop, for the address
     *  of the request creator, see useragent_addr in request_rec
     */
    apr_sockaddr_t *client_addr;

    /** Client's IP address; this is the end-point of the next hop, for the
     *  IP of the request creator, see useragent_ip in request_rec
     */
    char *client_ip;

    /** server IP address */
    char *local_ip;
    /** used for ap_get_server_name when UseCanonicalName is set to DNS
     *  (ignores setting of HostnameLookups) */
    char *local_host;

    /** ID of this connection; unique at any point in time */
    long id;

    /** A list of input filters to be used for this connection */
    struct ap_filter_t *input_filters;
    /** A list of output filters to be used for this connection */
    struct ap_filter_t *output_filters;
};
```

基于此，针对 httpd 应用程序的可能的解决方案有：

1. 在 SSL_read/SSL_write 对应的eBPF程序中新增额外的逻辑。如果进程为httpd应用的话，则获取 SSL->BIO->ptr 成员对应的 inctx/outctx 信息，找到 `conn_rec *c` 成员并从中解析出tcp连接的五元组信息，这里无法直接找到 tcp 连接的 socket fd。这里的问题是如何在基于 libSSL 的 SSL_read/SSL_write 上下文中判断当前进程是否为 httpd 应用，否则无法通过指针找到正确的 tcp 连接信息。一种简单的方式是判断当前进程的 comm 的值是否为 "httpd"，但这不一定是可靠的。
2. 新增 eBPF 程序挂载 httpd 应用的 SSL 初始化相关的函数，用于保存 SSL 结构体到 socket fd 的映射关系。
