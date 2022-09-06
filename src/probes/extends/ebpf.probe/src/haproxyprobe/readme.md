# HAPROXY数据采集方案

## 功能描述

基于eBPF实现haproxy的链路观测，并周期输出链路指标信息，支持功能：

- 设置观测周期，如 trace_haproxy -t 6 -- 6s输出统计信息，默认为5s
- 启动trace_haproxy后的链路和指标信息，具体指标参考haproxy_link.meta

## 采集方案

通过eBPF uprobe跟踪haproxy的建连、断连处理函数，获取链路信息后周期性输出。

### 观测点

- 建立连接：back_establish
- 关闭连接：stream_free

### 几个map

haproxy_link_map

haproxy链路统计信息

```
struct bpf_map_def SEC("maps") haproxy_link_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct link_key),
    .value_size = sizeof(struct link_value),
    .max_entries = LINK_MAX_ENTRIES,
};
```

- 新增时机(bpf程序)：
  - 在调用‘back_establish’创建连接时；
- 更新时机(bpf程序)：
  - 在调用‘stream_free’关闭连接时；
- 使用时机(用户态)：
  - 用户态程序周期性地调用‘pull_probe_data’处理函数从‘haproxy_link_map’中获取连接信息，统计后输出；
- 删除时机(用户态)：
  - 在‘pull_probe_data’处理函数中会判断state状态，如果是CLOSE即删除连接信息；

## 约束条件

- 运行环境需要保留至少观测点函数的符号表
- 目前支持版本2.5-dev0
