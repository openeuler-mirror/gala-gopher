# tcpprobe开发说明

## 功能描述

基于ebpf实现tcp链路观测，并周期输出链路指标信息；支持功能：

- 设置观测周期，如 `tcpprobe -t 10` -- 10s输出统计信息
- 启动tcpprobe前的tcp链路观测；（一般为长链接）
- 启动tcpprobe后的tcp链路观测；

具体指标信息参见tcp_link.meta；

## 开发思路

总体思路：

通过ebpf kprobe跟踪tcp状态变更/收发包的内核函数，周期更新链路指标信息，并在bpf用户态程序统计输出；

几个关键问题：

1. 链路指标中的链路角色如何体现

   分两种情况：

   - 探针启动后建立的链路

     - 如果是server角色收到建链请求，会触发`accept`流程；可跟踪`inet_csk_accept `判断；
     - 如果是client角色主动建链，tcp链路状态机会走到`TCP_SYN_SENT `状态，可跟踪`tcp_set_state `判断；

   - 探针启动前建立的链路

     启动前的链路无法获取链路建立过程信息；考虑通过监听端口判断链路角色；基本思路：

     1. 通过`ss -anptl `命令可以获取环境上所有的监听端口信息；
     2. 根据`ss`命令获取当前各进程链路信息，并根据`local port`是否在`listen port`范围决定进程的sockfd对应的角色（server/client）

2. 如何周期刷新链路指标信息

   在send/recv流程上挂ebpf钩子（tcp_sendmsg/tcp_recvmsg），周期获取sock信息更新到bpf map；

## 几个map

- long_link_map

  记录tcpprobe启动前环境上各进程的tcp链路信息；

  ```c
  struct bpf_map_def SEC("maps") long_link_map = {
      .type = BPF_MAP_TYPE_HASH,
      .key_size = sizeof(u32),
      .value_size = sizeof(struct long_link_info),
      .max_entries = MAX_LONG_LINK_PROCS,
  };
  ```

  - 创建时机：

    tcpprobe启动时，通过`bpf_update_long_link_info_to_map `解析`ss`命令结果添加到map中；

  - 使用时机：

    `tcp_set_state_probe ` /`inet_csk_accept_retprobe ` 钩子函数中，如果有新的主动/被动链路建立时，调用`bpf_add_long_link `将本进程上探针启动前的所有长链接sock添加到`sock_map `中，并删除进程记录；（仅第一次会触发长链接添加流程）

  - 删除时机：

    使用后立刻删除；

- sock_map 

  记录sock与进程信息的关系；链路指标上需要记录进程号、进程名、tx、rx等信息，网卡收包流程并不在业务进程上下文，通过`bpf_get_current_pid_tgid `拿到的信息可能不对；需要根据sock找到进程信息再更新；

  ```c
  struct bpf_map_def SEC("maps") sock_map = {
      .type = BPF_MAP_TYPE_HASH,
      .key_size = sizeof(struct sock *),
      .value_size = sizeof(struct proc_info),
      .max_entries = LINK_MAX_ENTRIES,
  };
  ```

  - 创建时机：

    - 作为server收到新的建链请求时`inet_csk_accept `添加
    - 作为client主动建链时`tcp_set_state `添加
    - 进程上有主动/被动链路建立过程中，添加进程上已有长链接sock信息
    - 进程上如果还没有新链路建立，已有链路触发send/recv流程， `bpf_update_link_metric `更新时如果找不到`sock_map `记录时添加

  - 使用时机：

    - send/recv流程中，根据`sock_map`判断是否到了刷新周期；

      ```c
      static void bpf_update_link_metric(struct pt_regs *ctx)
      {
          ......
          struct proc_info *p = bpf_map_lookup_elem(&sock_map, &sk);
      	if ((ts - p->ts) > TCPPROBE_INTERVAL_NS) {
      }
      ```

  - 删除时机：

    链路关闭时`tcp_set_state_probe `删除`sock_map`记录；

- listen_port_map 

  记录监听端口信息

  ```c
  struct bpf_map_def SEC("maps") listen_port_map = {
      .type = BPF_MAP_TYPE_HASH,
      .key_size = sizeof(unsigned short),	// listen port
      .value_size = sizeof(unsigned short),	// listen port
      .max_entries = MAX_LONG_LINK_FDS_PER_PROC * MAX_LONG_LINK_PROCS,
  };
  ```

  - 创建时机：

    探针启动时，根据`ss -antpl`获取所有监听端口信息，通过`bpf_add_listen_port_map`添加map记录；

  - 使用时机：

    更新链路指标信息时，如果 `sock_map`中找不到，说明是探针启动前的长链接链路的收发包消息（且在此之前该进程上没有新的链路建立，因为一旦有新链路，就会在链路建立时将进程上的历史链路信息添加到`sock_map`）

  - 删除时机：

    无

- link_map 

  tcp链路统计信息

  ```c
  struct bpf_map_def SEC("maps") link_map = {
      .type = BPF_MAP_TYPE_HASH,
      .key_size = sizeof(struct link_key),
      .value_size = sizeof(struct link_data),
      .max_entries = LINK_MAX_ENTRIES,
  };
  ```

  - 创建时机（bpf_update_link）：

    - 作为客户端主动建链
    - 作为服务端被动接收链路
    - 进程上有主动/被动链路建立过程中，添加进程上已有长链接sock信息

  - 更新时机：

    链路关闭时，叠加链路CLOSE状态；

    ```c
    void tcp_set_state_probe(struct pt_regs *ctx)
    {
        ......
        if (new_state != TCP_CLOSE) {
            return;
        }
    
        /* 2 update link data */
        bpf_update_link(sk, new_state);
    }
    ```

  - 使用时机：

    用户态程序周期从`link_map`中获取map中的链路信息，并做统计输出；（pull_probe_data）

  - 删除时机：

    pull_probe_data 中对于状态包含 `TCP_CLOSE `的链路从map中删除；即统计输出后已关闭的链路从map中移除；

## 压测报告

测试环境：openEuler-20.03-LTS + VM + 16核

测试结果：10w并发连接下，tcpprobe的cpu占用率平均为 4.0% （16核共1600%），内存占用率10%。

测试服务器程序：https://github.com/smallnest/1m-go-tcp-server/tree/master/2_epoll_server

测试客户端程序：https://github.com/smallnest/1m-go-tcp-server/tree/master/4_epoll_client

测试过程：

1. 编译 epoll_server 服务器程序：`go build .`
2. 启动 epoll_server 服务器：`./go_server`
3. 编译 epoll_client 客户端程序：`go build --tags "static netgo" -o client  .`
4. 启动 epoll_client 客户端：`./setup.sh 10000 10 172.17.0.1` ，创建10个容器，每个容器创建1w并发tcp连接，共10w并发连接。

测试环境构建：https://colobu.com/2019/02/23/1m-go-tcp-connection/