# event.probe开发使用指南

Event probe是一个事件上报探针程序，上报的数据遵循OpenTelemetry Log v1规范，默认输出到kafka，topic: gala-gopher-event。


## 1. OpenTelemetry Log规范

### 1.1 OpenTelemetry规范链接
数据模型介绍：
https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/logs/data-model.md

数据结构定义：
https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/logs/v1/logs.proto

### 1.2 数据样例
样例1：
```sh
{
   "Timestamp": "1640593945000000000", 
   "SeverityText": "ERROR", 
   "Resource": {
      "host.hostname": "hh131", 
      "host.machineid": "3c4562092d9e4644b08905a2eaefa138"
   }, 
   "Body": "Dec 27 16:32:22 hh131 [/bin/bash]: [gala-gopher] return code=[130], execute failed by [root(uid=0)] from [pts/4 (10.136.119.3)]"
}
```
样例2：
```sh
{
   "Timestamp": "1586960586000000000",
   "Attributes": {
      "http.status_code": 500,
      "http.url": "http://example.com",
      "my.custom.application.tag": "hello",
   },
   "Resource": {
      "service.name": "donut_shop",
      "service.version": "2.0.0",
      "k8s.pod.uid": "1138528c-c36e-11e9-a1a7-42010a800198",
   },
   "TraceId": "f4dbb3edd765f620", // this is a byte sequence
                                  // (hex-encoded in JSON)
   "SpanId": "43222c2d51a7abe3",
   "SeverityText": "INFO",
   "SeverityNumber": 9,
   "Body": "20200415T072306-0700 INFO I like donuts"
}
```


## 2. event.probe使用

### 2.1 Event接口
event.h文件：
```sh
#define EVENT_LEVEL_INFO  "INFO"
#define EVENT_LEVEL_WARN  "WARN"
#define EVENT_LEVEL_ERROR "ERROR"
#define EVENT_LEVEL_FATAL "FATAL"

struct event_data {
    __u64 timestamp;  // UNIX Epoch time in seconds since 00:00:00 UTC on 1 January 1970.
    char level[16];   // Event level: "INFO"|"WARN"|"ERROR"|"FATAL".
    char body[MAX_DATA_STR_LEN]; 
};

void PrintEventOutput(const struct event_data *event);
```
### 2.2 Event使能开关
gala-gopher.conf，启动后默认输出系统messages异常结束进程的日志
```sh
    {
        name = "event";
        switch = "on";
        interval = 5;
    }
```

## 3. Event事件类型（待梳理）
1、执行失败事件（比如系统调用失败）；  
2、安全事件（非法访问等）；  
3、系统内部异常事件（比如OOM、task offcpu超长等）
