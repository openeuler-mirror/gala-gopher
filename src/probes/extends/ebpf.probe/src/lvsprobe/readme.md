# LVS数据采集方案

## 功能描述

基于eBPF实现lvs的链路观测，并周期输出链路指标信息，支持功能：

- 设置观测周期，如 'trace_lvs -t 6' -- 6s输出统计信息，默认为5s
- 启动trace_lvs后的链路和指标信息，具体指标参考lvs_link.meta

## 采集方案

通过eBPF kprobe跟踪内核中连接创建和老化函数，按指定的统计周期更新链路连接情况，用户态程序进行统计输出。

### 观测点

- 连接建立：ip_vs_conn_new 
- 连接老化：ip_vs_conn_expire

### 几个map

lvs_link_map 

lvs链路统计信息

```
struct bpf_map_def SEC("maps") lvs_link_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct link_key),
    .value_size = sizeof(struct link_value),
    .max_entries = IPVS_MAX_ENTRIES,
};
```

- 新增时机(bpf程序)：
  - 连接建立时也即调用‘ip_vs_conn_new’函数时；
- 更新时机(bpf程序)：
  - 连接老化时也即调用‘ip_vs_conn_expire’函数时；
- 使用时机(用户态)：
  - 用户态程序周期性地调用‘pull_probe_data’从‘lvs_link_map’中获取连接信息，刷新统计值link_count；
- 删除时机(用户态)：
  - 'pull_probe_data'会判断连接状态，如果为CLOSE则删除map中的连接信息；

lvs_flag_map 

保存当前的lvs flag(主要判断是否为FULLNAT模式)，因为FULLNAT模式相比其他模式多了local ip信息，探针bpf程序要对此做特殊处理。

```
struct bpf_map_def SEC("maps") lvs_flag_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u16),
    .value_size = sizeof(u8),
    .max_entries = IPVS_MIN_ENTRIES,
};
```

- 新增时机(bpf程序)：
  - 在连接建立时，从‘ip_vs_conn_new’函数入参中获取当前模式信息(DR/NAT/FullNAT)并保存在此map中；
- 使用时机(bpf程序)：
  - 在连接建立处理时和老化时，先从‘lvs_flag_map’获取模式信息，并分别选择不同的处理函数；

## 约束条件

- 运行环境需要有ipvs相关ko
