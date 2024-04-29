# 规格与约束
## 1 日志文件约束
gala-gopher 日志文件配置主要涉及日志路径配置，打印等级设置，日志默认大小等
### 1.1 日志等级配置
#### 配置文件在 [config](../config/gala-gopher.conf)  
log_level 配置当前日志打印等级， 一共有4 个日志等级， 分别为 DEBUG < INFO < WARN < ERROR  
备注： 日志等级只有高于当前设置的 log_level 才会触发打印。
```
global =
{
    log_file_name = "gopher.log";
    log_level = "info";             # debug | info | warn | error
    ...
};
```


### 1.2 日志存储与备份约束
日志目前分为一下四类  
#### 1.2.1 debug 日志
- 当前允许备份次数为 1, 也就是 gopher.log 和 gopher.log.1， 当一个文件写满超过最大允许存储后， 会覆盖写入另外一个文件， 如此循环在俩个文件中覆盖写。
- debug 日志当前允许最大存储量为 100MB， 参数设置在 config 文件中的 metric_total_size, 单位 MB， 大小为当前日志和所有 debug 备份日志的总和。单个日志最大存储为： metric_total_size / 最大日志文件数
```
logs =
{
    metric_total_size = 100; # unit is MB
    ...
};
```

#### 1.2.2 metric 日志  
简介： 输出格式化的 metric 日志， 提供给数据库或 prometheus 使用
- metric 日志当前允许最大存储量为 100MB， 参数设置在 config 文件中的 metric_total_size, 单位 MB, 当前 metric 日志不允许备份， 当超过最大允许存储后会清除后重头部开始写。
```
logs =
{
    metric_total_size = 100; # unit is MB
    ...
};
```
#### 1.2.3 meta 日志
- meta 日志当前允许最大存储量为 100MB， 单位 MB, 当前meta日志不允许备份，当超过最大允许存储后会清除后重头部开始写
