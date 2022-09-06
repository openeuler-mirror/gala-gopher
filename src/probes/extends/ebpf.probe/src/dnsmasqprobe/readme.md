# dnsmasq数据采集方案

## 功能描述

基于eBPF实现dnsmasq的链路观测，并周期输出链路指标信息，支持功能：

- 设置观测周期，如 trace_dnsmasq -t 6 -- 6s输出统计信息，默认为5s
- 启动trace_dnsmasq后的链路和指标信息，具体指标参考dnsmasq_link.meta

## 采集方案

通过eBPF uprobe跟踪dnsmasq的报文发送到服务器的处理函数，获取链路信息后周期性输出。

### 观测点

- 报文发送到服务器函数：send_from

### 几个map

dns_query_link_map

经过dnsmasq的链路统计信息

```
struct bpf_map_def SEC("maps") dns_query_link_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct link_key),
    .value_size = sizeof(struct link_value),
    .max_entries = LINK_MAX_ENTRIES,
};
```

- 新增时机(bpf程序)：
  - 在调用‘send_from’发送数据报文到服务端时；
- 使用时机(用户态)：
  - 用户态程序周期性地调用‘pull_probe_data’处理函数从‘dns_query_link_map’中获取连接信息，统计后输出；
- 删除时机(用户态)：
  - 在‘pull_probe_data’处理函数中每当处理并输出连接信息后，将连接删除；

## 约束条件

- 运行环境需要保留至少观测点函数的符号表
- 目前支持版本v2.87
