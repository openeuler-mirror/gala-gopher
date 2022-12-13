# pg_stat 探针开发说明

## 功能描述

获取PostgreSQL Sever的TPS统计数据。支持的功能有：

- 设置被观测服务端信息

  通过pg_stat_probe.conf设置，支持多服务端，配置方法详见[conf_introduction.md](../../../../../doc/conf_introduction.md#pg_stat_probe.conf)

- 设置观测周期

  通过-d参数设置，单位为秒，默认值5，示例：

  `python3 pg_stat_probe.py -d 5`

  表示每隔5s输出统计信息

- 观测PostgreSQL Sever中各数据库的TPS统计数据，具体的观测指标信息参见`pg_stat_probe.meta`

## 采集方案

通过计算数据库已提交的事务数在单位时间内的增长来计算TPS
