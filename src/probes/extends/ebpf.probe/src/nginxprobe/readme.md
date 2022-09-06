# NGINX数据采集方案

## 功能描述

基于eBPF实现nginx的链路观测，并周期输出链路指标信息，支持功能：

- 设置观测周期，如 nginx_probe -t 6 -- 6s输出统计信息，默认为5s
- 启动nginx_probe后的链路和指标信息，具体指标参考nginx_link.meta

## 采集方案

通过eBPF uprobe跟踪nginx的建连、断连处理函数，获取链路信息后周期性输出。

### 四层

- 建立连接：ngx_stream_proxy_init_upstream
- 关闭连接：ngx_close_connection

### 七层

- 建立连接：ngx_http_upstream_handler
- 关闭连接：ngx_close_connection

### 几个map

para_hs 

保存‘ngx_stream_proxy_init_upstream’第一个入参的地址，用于kretprobe获取正确的入参中元素

```
struct bpf_map_def SEC("maps") para_hs = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(void **),
    .max_entries = HASH_ITEM_CNTS,
};
```

- 新增时机(bpf程序)：
  - 在建链'ngx_stream_proxy_init_upstream'的kprobe中，将入参的地址保存到‘para_hs’中
- 使用时机(bpf程序)：
  - 在建链‘ngx_stream_proxy_init_upstream’的kretprobe中，获取真实的入参地址，用于取相关参数值

hs

nginx链路统计信息

```
struct bpf_map_def SEC("maps") hs = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct ip_addr),
    .value_size = sizeof(struct ngx_metric),
    .max_entries = HASH_ITEM_CNTS,
};
```

- 新增时机(bpf程序)：
  - 在调用‘ngx_stream_proxy_init_upstream’或‘ngx_http_upstream_handler’创建连接时；
- 更新时机(bpf程序)：
  - 在调用‘ngx_close_connection’关闭连接时；
- 使用时机(用户态)：
  - 用户态程序周期性地调用‘pull_probe_data’处理函数从‘hs’中获取连接信息，统计后输出；
- 删除时机(用户态)：
  - 在‘pull_probe_data’处理函数中会判断finish状态，如果是finished即删除连接信息；

## 约束条件

- 运行环境需要保留至少观测点函数的符号表
- 目前支持版本1.12.1
