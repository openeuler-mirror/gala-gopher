# endpoint 探针开发说明

## 功能描述
基于 ebpf 实现进程的 tcp/udp 网络通信端点（endpoint）的观测，并周期输出端点的观测指标信息。支持的功能有：
- 设置观测周期，如：`endpoint -t 10` ，表示每隔10s输出统计信息。
- 启动 endpoint 探针后的进程 tcp/udp 服务端监听端口的观测。
- 启动 endpoint 探针后的进程 tcp/udp 客户端端口的观测。
具体的观测指标信息参见 `endpoint.meta` 。

## 开发思路
总体思路：通过 ebpf kprobe/tracepoint 跟踪不同类型 endpoint 的生命周期，包括 endpoint 的创建、删除、以及指标信息的更新。

### endpoint 生命周期管理
endpoint 按照 tcp/udp 、服务端/客户端，可分为4种类型：
1. SK_TYPE_LISTEN_TCP ：服务端进程的 tcp 监听端点。  
    观测粒度：进程PID + IP + port 。  
    创建：调用内核函数 `inet_listen` 成功后，endpoint 进入监听状态时创建。  
    删除：与该 endpoint 关联的 socket 对象删除时删除。  
2. SK_TYPE_LISTEN_UDP ：服务端进程的 udp 监听端点。  
   观测粒度：进程PID + IP + port 。  
   创建：调用内核函数 `inet_bind` 成功后，endpoint 绑定了 IP 和 port 时创建。  
   删除：与该 endpoint 关联的 socket 对象删除时删除。  
3. SK_TYPE_CLIENT_TCP ：客户端进程的 tcp 端点。  
   观测粒度：进程PID + IP 。也就是说，对于同一个 tcp 客户端进程，拥有相同 IP 但不同的 port 的端点，都将聚合为同一个 endpoint 。  
   创建：在第一次调用内核函数 `tcp_v4_connect/tcp_v6_connect` 时创建，此时 endpoint 的 IP 会初始化。  
   删除：与该 endpoint 关联的进程删除时删除。  
4. SK_TYPE_CLIENT_UDP ：客户端进程的 udp 端点。  
   观测粒度：进程PID + IP 。也就是说，对于同一个 udp 客户端进程，拥有相同 IP 但不同的 port 的端点，都将聚合为同一个 endpoint 。  
   创建：在第一次调用内核函数 `udp_sendmsg` 时创建，此时 endpoint 的 IP 会初始化。  
   删除：与该 endpoint 关联的进程删除时删除。  

### endpoint 观测指标开发

| 指标名 | 描述 | 跟踪点 | 支持的endpoint类型 |
| --- | --- | --- | --- |
| EP_STATS_LISTEN_DROPS | tcp监听端口丢包数统计 | tcp_conn_request/tcp_v4_syn_recv_sock/tcp_v6_syn_recv_sock/tcp_req_err | SK_TYPE_LISTEN_TCP |
| EP_STATS_ACCEPT_OVERFLOW | tcp全连接队列溢出数统计 | tcp_conn_request/tcp_v4_syn_recv_sock/tcp_v6_syn_recv_sock | SK_TYPE_LISTEN_TCP |
| EP_STATS_SYN_OVERFLOW | tcp半连接队列溢出数统计 | tcp_conn_request/tcp_v4_syn_recv_sock/tcp_v6_syn_recv_sock | SK_TYPE_LISTEN_TCP | 
| EP_STATS_PASSIVE_OPENS | tcp监听端口被动连接数统计 | tcp_create_openreq_child | SK_TYPE_LISTEN_TCP |
| EP_STATS_ACTIVE_OPENS | tcp主动连接数统计 | tcp_connect | SK_TYPE_CLIENT_TCP |
| EP_STATS_ATTEMPT_FAILS | tcp建链失败的次数（包括主动、被动）统计 | tcp_done | SK_TYPE_LISTEN_TCP/SK_TYPE_CLIENT_TCP |
| EP_STATS_ABORT_CLOSE | tcp oom事件数统计 | tcp_reset | SK_TYPE_LISTEN_TCP/SK_TYPE_CLIENT_TCP |
| EP_STATS_REQUEST_FAILS | tcp request处理失败次数统计 | tcp_check_req | SK_TYPE_LISTEN_TCP |
| EP_STATS_RMEM_SCHEDULE | tcp rmem已满次数统计 | tcp_try_rmem_schedule | SK_TYPE_LISTEN_TCP/SK_TYPE_CLIENT_TCP |
| EP_STATS_TCP_OOM | TCP oom事件数统计 | tcp_check_oom | SK_TYPE_LISTEN_TCP/SK_TYPE_CLIENT_TCP |
| EP_STATS_KEEPLIVE_TIMEOUT | tcp keeplive超时次数统计 | tcp_write_wakeup | SK_TYPE_LISTEN_TCP/SK_TYPE_CLIENT_TCP |
| EP_STATS_CONN_TRACK_FAILS | nf_conntrack 项创建失败次数统计 | init_conntrack  | SK_TYPE_LISTEN_TCP/SK_TYPE_CLIENT_TCP |

### map 说明
- s_endpoint_map  
   记录服务端进程的 endpoint 信息。  
   ```c
   struct bpf_map_def SEC("maps") s_endpoint_map = {
       .type = BPF_MAP_TYPE_HASH,
       .key_size = sizeof(struct s_endpoint_key_t),
       .value_size = sizeof(struct endpoint_val_t),
       .max_entries = MAX_ENDPOINT_LEN,
   };
   ```
   - 创建时机：  
     服务端进程的 endpoint 进入监听状态时创建。具体来说，tcp 类 endpoint 在执行 `inet_listen` 成功后创建，udp 类 endpoint 在执行 `inet_bind` 成功后创建。
   - 更新时机：  
     endpoint 指标数据更新事件触发时。
   - 使用时机：  
     用户态程序周期性从 `s_endpoint_map` 中获取 endpoint 信息时。
   - 删除时机：  
     endpoint 对应的 socket 对象删除时。  
   - 过滤策略：  
     根据进程 PID 进行过滤。若该 endpoint 所属的进程 PID 在 task map 中，则创建该 endpoint ；否则，忽略该 endpoint 。
- c_endpoint_map  
   记录客户端进程的 endpoint 信息。  
   ```c
   struct bpf_map_def SEC("maps") c_endpoint_map = {
       .type = BPF_MAP_TYPE_HASH,
       .key_size = sizeof(struct c_endpoint_key_t),
       .value_size = sizeof(struct endpoint_val_t),
       .max_entries = MAX_ENDPOINT_LEN,
   };
   ```
   - 创建时机：  
     客户端进程的 endpoint 在第一次建立连接或发送数据时创建。具体来说，tcp 类 endpoint 在第一次执行 `tcp_v4_connect/tcp_v6_connect` 成功建立连接后创建，udp 类 endpoint 在第一次执行 `udp_sendmsg` 成功发送数据后创建。
   - 更新时机：  
     endpoint 指标数据更新事件触发时。
   - 使用时机：  
     用户态程序周期性从 `c_endpoint_map` 中获取 endpoint 信息时。
   - 删除时机：  
     endpoint 对应的进程删除时。
   - 过滤策略：  
     根据进程 PID 进行过滤。若该 endpoint 所属的进程 PID 在 task map 中，则创建该 endpoint ；否则，忽略该 endpoint 。  
- listen_port_map  
   记录服务端进程的监听端口号到 socket 地址的映射信息。它的作用是用于区分当前 socket 对应的 endpoint 是属于服务端还是客户端。  
   ```c
   struct bpf_map_def SEC("maps") listen_port_map = {
       .type = BPF_MAP_TYPE_HASH,
       .key_size = sizeof(struct listen_port_key_t),
       .value_size = sizeof(unsigned long),
       .max_entries = MAX_ENDPOINT_LEN,
   };
   ```
   - 创建时机：  
     1. endpoint 探针启动前，获取系统中已有的监听端口并添加到 `listen_port_map` 中。
     2. `s_endpoint_map` 条目创建时创建对应的 `listen_port_map` 条目。  
   - 使用时机：  
     endpoint 指标数据更新事件触发时，如果无法区分当前 endpoint 是属于服务端还是客户端的时候，则根据它的端口号 port 是否在 `listen_port_map` 中来判断。  
   - 删除时机：  
     `s_endpoint_map` 条目删除时删除对应的 `listen_port_map` 条目。  