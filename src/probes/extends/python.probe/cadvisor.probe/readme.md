# cadvisor 探针开发说明

## 功能描述

集成容器性能分析工具[cAdvisor](https://github.com/google/cadvisor)的统计数据。支持的功能有：

- 设置cAdvisor监听端口（必需）

  通过-p参数设置，无默认值，示例：

  `python3 cadvisor_probe.py -p 8080`

  表示监控cAdvisor输出，若cAdvisor未启动，则通过`cadvisor -port 8080`启动cAdvisor

- 设置观测周期

  通过-d参数设置，单位为秒，默认值5，示例：

  `python3 cadvisor_probe.py -p 8080 -d 5`

  表示每隔5s输出统计信息

- 开启观测白名单

  通过-F参数设置，配置为`task`表示按照`gala-gopher-app.conf`过滤，配置为具体进程的pid表示仅监控此进程，不配置则观测所有进程，默认不配置，示例：

  `python3 cadvisor_probe.py -p 8080 -F task`

  表示只观测`gala-gopher-app.conf`中的进程

  `python3 cadvisor_probe.py -p 8080 -F 1234`

  表示只观测pid为1234的进程

- 设置容器观测指标

  通过cadvisor_probe.conf和cadvisor_probe.meta配置，二者需对应。配置方法详见[conf_introduction.md](../../../../../doc/conf_introduction.md#cadvisor_probe.conf)

- 容器运行信息监控，具体的观测指标信息参见`cadvisor_probe.meta`。

## 采集方案

拉起cAdvisor进程，并监控[cAdvisor原始Prometheus统计数据](https://github.com/google/cadvisor/blob/master/docs/storage/prometheus.md)，
采集cadvisor_probe.conf中配置的统计项，将数据格式转换后按照cadvisor_probe.meta输出为gala-gopher框架支持的格式。

## 约束条件

- 需要预先安装cAdvisor

