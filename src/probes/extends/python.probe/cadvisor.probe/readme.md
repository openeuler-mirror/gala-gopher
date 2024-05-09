# cadvisor 探针开发说明

## 功能描述

集成容器性能分析工具[cAdvisor](https://github.com/google/cadvisor)的统计数据。支持探针启动配置有：

- 设置cAdvisor监听端口：cadvisor_port。不设置则默认为8083

- 设置上报周期：period。单位为秒。不设置则默认为60（秒）

- 开启观测白名单：可在snoopers中设置

- 设置容器观测指标

  通过cadvisor_probe.conf和cadvisor_probe.meta配置，二者需对应。配置方法详见[conf_introduction.md](../../../../../doc/conf_introduction.md#cadvisor_probe.conf)

- 容器运行信息监控，具体的观测指标信息参见`cadvisor_probe.meta`。

## 探针启动配置示例

```
curl -X PUT http://localhost:9999/container -d json='
{
    "snoopers": {
        "proc_name": [
            {
                "comm": "app1",
            },
            {
                "comm": "app2",
            }
        ]
    },
    "params":{
        "cadvisor_port": 8083,
        "report_period": 60
    },
    "state":"running"
}'

```

## 采集方案

拉起cAdvisor进程，并监控[cAdvisor原始Prometheus统计数据](https://github.com/google/cadvisor/blob/master/docs/storage/prometheus.md)，
采集cadvisor_probe.conf中配置的统计项，将数据格式转换后按照cadvisor_probe.meta输出为gala-gopher框架支持的格式。

## 约束条件

- 需要预先安装cAdvisor

