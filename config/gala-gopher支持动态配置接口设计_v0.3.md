

# Rest API说明

启动gala-gopher时会启动Rest server，该Rest server负责接收用户发起的PUT和GET清求，PUT请求用于启动探针并配置监控范围，GET请求用于获取探针的相关信息，同一采集特性对应同一个探针和请求的URL。
可以使用curl命令发起请求，请求的URL的组织方式为http://[gala-gopher所在节点ip] + [端口号] + function（采集特性），Rest server服务所占用的端口号可配置（缺省时为9999），例如，
采集火焰图的URL为：http://localhost:9999/flamegraph    

探针默认关闭，可以通过curl命令发送PUT请求给Rest server动态开启并设置监控范围。         

下面看看各类探针配置的示例        

## 火焰图探针配置全集     
看看火焰图探针配置的全集     

```
curl -X PUT http://localhost:9999/flamegraph --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/stackprobe",
        "check_cmd": "",
        "probe": [
            "oncpu",
            "offcpu",
            "mem"
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20%,
        "res_upper_thr": 20%,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node",
        "multi_instance": 1,
        "native_stack": 1,
        "pyroscope_server": "localhost:4040",
        "svg_period": 180,
        "perf_sample_period": 10,
        "svg_dir": "/var/log/gala-gopher/stacktrace",
        "flame_dir": "/var/log/gala-gopher/flamegraph"
    },
    "state":"running"
}'

```

启动火焰图探针的PUT请求中可以配置很多参数，这些参数共同控制着火焰图探针的行为，由上往下分析一下请求中的各个重要组成部分  
（1）使用curl命令发起PUT请求     
（2）请求的URL为http://localhost:9999/flamegraph，9999是Rest server处理启动探针请求监听的端口号，flamegraph为探针的名称     
（3）cmd内容中的bin为火焰图探针的二进制可执行文件的绝对路径，check_cmd为探针启动的条件，这里check_cmd为空时代表探针无条件启动     
（4）cmd内容中的probe对应着探针的采集子项，火焰图探针probe的内容为oncpu、offcpu和mem，代表火焰图探针可以采集oncpu、offcpu和mem这三种数据类型的数据
（5）snoopers内容中的配置探针监听对象有四个维度，proc_id、proc_name、pod_id和container_id，分别是进程id，进程名称，pod id和容器id，其中任意
一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定  
（6）params内容中的参数，示例中的参数都是火焰图探针支持的参数  
    report_period是控制着采集的数据上报的周期，值为180的含义是每隔180s上报一次采集到的数据  
    res_lower_thr是控制着资源的百分比下限  
    res_upper_thr是控制着资源的百分比上限  
    report_event是控制着探针是否上报异常事件，为1时代表上报异常事件  
    metrics_type控制着上报telemetry的metrics类型  
    env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据  
    multi_instance控制着每个进程是否独立输出火焰图，为1时代表每个进程独立输出火焰图  
    native_stack控制着是否显示本地语言堆栈（针对Java进程），值为1的含义是显示Java进程的本地语言堆栈  
    pyroscope_server控制着火焰图UI服务端地址，值为localhost:4040的含义为火焰图UI服务端地址为localhost:4040  
    svg_period是控制着火焰图svg文件生成的周期，值为180的含义为每隔180s生成火焰图svg文件  
    perf_sample_period控制着oncpu火焰图采集堆栈信息的周期，值为10的含义是每个10ms采集oncpu火焰图堆栈信息  
    svg_dir控制着火焰图svg文件的存储目录，值为/var/log/gala-gopher/stacktrace的含义是火焰图svg文件存储在/var/log/gala-gopher/stacktrace目录    
    flame_dir控制着火焰图原始堆栈信息的存储目录，值为/var/log/gala-gopher/flamegraph的含义是火焰图原始堆栈信息存储在/var/log/gala-gopher/flamegraph目录    
    注：尽量不配置火焰图探针不支持的参数，主要要看探针在实现时是否忽略了用户配置的火焰图探针不支持的参数，否则可能会影响探针采集的结果  
（7）state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped  


## 应用7层协议探针配置全集      
看看应用7层协议探针配置的全集       

```
curl -X PUT http://localhost:9999/l7 --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/l7probe",
        "check_cmd": "",
        "probe": [
            "l7_bytes_metrics",
            "l7_rpc_metrics",
            "l7_rpc_trace"
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20%,
        "res_upper_thr": 20%,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node",
        "l7_protocol": [
            "http",
            "pgsql"
        ],
        "support_ssl": 1,
        "cluster_ip_backend": 1
    },
    "state":"running"
}'

```    

启动l7探针的PUT请求中可以配置很多参数，这些参数共同控制着l7探针的行为，由上往下分析一下请求中的各个重要组成部分      
（1）使用curl命令发起PUT请求           
（2）请求的URL为http://localhost:9999/l7，9999是Rest server处理启动探针请求监听的端口号，l7为探针的名称       
（3）cmd内容中的bin为l7探针的二进制可执行文件的绝对路径，check_cmd为探针启动的条件，这里check_cmd为空时代表探针无条件启动      
（4）cmd内容中的probe对应着探针的采集子项，l7探针probe的内容为l7_bytes_metrics、l7_rpc_metrics和l7_rpc_trace，代表火焰图探针可以采集l7_bytes_metrics、l7_rpc_metrics和l7_rpc_trace这三种数据类型的数据，
具体每种数据类型的含义在下文的采集子项详细说明可以查询到  
（5）snoopers内容中的配置探针监听对象有四个维度，proc_id、proc_name、pod_id和container_id，分别是进程id，进程名称，pod id和容器id，其中任意
一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定  
（6）params内容中的参数，示例中的参数都是l7探针支持的参数  
    report_period是控制着采集的数据上报的周期，值为180的含义是每隔180s上报一次采集到的数据   
    res_lower_thr是控制着资源的百分比下限  
    res_upper_thr是控制着资源的百分比上限  
    report_event是控制着探针是否上报异常事件，为1时代表上报异常事件  
    metrics_type控制着上报telemetry的metrics类型   
    env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据  
    l7_protocol控制着l7探针采集通过什么协议传输的数据，示例中表示l7探针采集通过http和pgsql协议采集的数据  
    support_ssl控制着是否支持SSL加密协议观测，为1的含义是支持SSL加密协议观测  
    cluster_ip_backend控制着执行Cluster IP backend转换，为1的含义是执行Cluster IP backend转换  
（7）state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped  

## TCP异常、状态观测探针配置全集    
看看TCP异常、状态观测探针配置的全集     

```
curl -X PUT http://localhost:9999/tcp --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/tcpprobe",
        "check_cmd": "",
        "probe": [
            "tcp_abnormal",
            "tcp_rtt",
            "tcp_windows",
            "tcp_rate",
            "tcp_srtt",
            "tcp_sockbuf",
            "tcp_stats",
            "tcp_delay"
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "sample_period": 180,
        "report_period": 180,
        "latency_thr": 60,
        "drops_thr": 10,
        "res_lower_thr": 20%,
        "res_upper_thr": 20%,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node",
        "report_source_port": 1,
        "cluster_ip_backend": 1,
        "dev_name": [
            "io",
            "kafka"
        ]
    },
    "state":"running"
}'

```    

启动tcp探针的PUT请求中可以配置很多参数，这些参数共同控制着tcp探针的行为，由上往下分析一下请求中的各个重要组成部分  
（1）使用curl命令发起PUT请求  
（2）请求的URL为http://localhost:9999/tcp，9999是Rest server处理启动探针请求监听的端口号，tcp为探针的名称  
（3）cmd内容中的bin为tcp探针的二进制可执行文件的绝对路径，check_cmd为探针启动的条件，这里check_cmd为空时代表探针无条件启动  
（4）cmd内容中的probe对应着探针的采集子项，tcp探针probe的内容为tcp_abnormal、tcp_rtt、tcp_windows、tcp_rate、tcp_srtt、tcp_sockbuf、tcp_stats和tcp_delay， 代表火焰图探针可以采集tcp_abnormal、tcp_rtt、tcp_windows、tcp_rate、tcp_srtt、tcp_sockbuf、tcp_stats和tcp_delay这些数据类型的数据，
具体每种数据类型的含义在下文的采集子项详细说明可以查询到  
（5）snoopers内容中的配置探针监听对象有四个维度，proc_id、proc_name、pod_id和container_id，分别是进程id，进程名称，pod id和容器id，其中任意
一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定   
（6）params内容中的参数，示例中的参数都是tcp探针支持的参数      
    sample_period控制着探针采集数据的周期，值为180的含义是每隔180ms进行数据的采集        
    report_period是控制着采集的数据上报的周期，值为180的含义是每隔180s上报一次采集到的数据        
    latency_thr控制着时延上报的门限，值为10的含义是时延需要超过60ms才进行上报     
    drops_thr控制着丢包上送门限，值为10的含义是丢包需要大于10 package是才进行丢包上送          
    res_lower_thr是控制着资源的百分比下限        
    res_upper_thr是控制着资源的百分比上限        
    report_event是控制着探针是否上报异常事件，为1时代表上报异常事件        
    metrics_type控制着上报telemetry的metrics类型          
    env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据    
    report_source_port控制着是否上报源端口，为1代表上报源端口           
    cluster_ip_backend控制着执行Cluster IP backend转换，为1的含义是执行Cluster IP backend转换        
    dev_name控制着观测的网卡/磁盘的设备名，值为io和kafka的含义是观测设备名为io与kafka的设备     
（7）state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped        


## Socket异常观测探针配置全集 
看看Socket异常观测探针配置的全集           

```
curl -X PUT http://localhost:9999/socket --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/socketprobe",
        "check_cmd": "",
        "probe": [
            "tcp_socket",
            "udp_socket"
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20%,
        "res_upper_thr": 20%,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node"
    },
    "state":"running"
}'

```    

启动socket探针的PUT请求中可以配置很多参数，这些参数共同控制着socket探针的行为，由上往下分析一下请求中的各个重要组成部分     
（1）使用curl命令发起PUT请求     
（2）请求的URL为http://localhost:9999/socket, 9999是Rest server处理启动探针请求监听的端口号，socket为探针的名称    
（3）cmd内容中的bin为socket探针的二进制可执行文件的绝对路径，check_cmd为探针启动的条件，这里check_cmd为空时代表探针无条件启动     
（4）cmd内容中的probe对应着探针的采集子项，socket探针probe的内容为tcp_socket, udp_socket, 代表socket探针可以采集tcp_socket和udp_socket数据类型的数据,
具体每种数据类型的含义在下文的采集子项详细说明可以查询到  
（5）snoopers内容中的配置探针监听对象有四个维度,proc_id、proc_name、pod_id和container_id, 分别是进程id，进程名称，pod id和容器id，其中任意
一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定         
（6）params内容中的参数，示例中的参数都是socket探针支持的参数       
    report_period是控制着采集的数据上报的周期        
    res_lower_thr是控制着资源的百分比下限          
    res_upper_thr是控制着资源的百分比上限         
    report_event是控制着探针是否上报异常事件，为1时代表上报异常事件          
    metrics_type控制着上报telemetry的metrics类型           
    env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据         
（7）state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped            


## Block层I/O观测探针配置全集
看看Block层I/O观测探针配置的全集        

```
curl -X PUT http://localhost:9999/io --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/ioprobe",
        "check_cmd": "",
        "probe": [
            "io_trace",
            "io_err",
            "io_count",
            "page_cache"
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "sample_period": 180,
        "report_period": 180,
        "latency_thr": 180,
        "res_lower_thr": 20%,
        "res_upper_thr": 20%,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node",
        "dev_name": [
            "io",
            "kafka"
        ]
    },
    "state":"running"
}'

```    

启动io探针的PUT请求中可以配置很多参数，这些参数共同控制着io探针的行为，由上往下分析一下请求中的各个重要组成部分          
（1）使用curl命令发起PUT请求       
（2）请求的URL为http://localhost:9999/io, 9999是Rest server处理启动探针请求监听的端口号，io为探针的名称      
（3）cmd内容中的bin为io探针的二进制可执行文件的绝对路径，check_cmd为探针启动的条件，这里check_cmd为空时代表探针无条件启动       
（4）cmd内容中的probe对应着探针的采集子项，io探针probe的内容为io_trace、io_err、io_count和page_cache, 代表io探针可以采集io_trace、io_err、io_count和page_cache数据类型的数据,
具体每种数据类型的含义在下文的采集子项详细说明可以查询到          
（5）snoopers内容中的配置探针监听对象有四个维度,proc_id、proc_name、pod_id和container_id, 分别是进程id，进程名称，pod id和容器id，其中任意
一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定         
（6）params内容中的参数，示例中的参数都是io探针支持的参数      
     sample_period控制着采样周期，值为180的含义是每隔180ms进行一次数据的采样         
     report_period是控制着采集的数据上报的周期，值为180的含义是每个180s上报一次采集到的数据       
     latency_thr控制着时延上报的门限，值为180的含义是时延大于180ms时进行时延的上报     
     res_lower_thr是控制着资源的百分比下限     
     res_upper_thr是控制着资源的百分比上限      
     report_event是控制着探针是否上报异常事件，为1时代表上报异常事件         
     metrics_type控制着上报telemetry的metrics类型        
     env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据         
     dev_name控制着观测的网卡/磁盘的设备名，值为io和kafka的含义是观测设备名为io与kafka的设备      
（7）state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped       


## 进程系统调用、I/O、DNS、VFS等观测探针配置全集
看看进程系统调用、I/O、DNS、VFS等观测探针配置的全集         

```
curl -X PUT http://localhost:9999/proc --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/procprobe",
        "check_cmd": "",
        "probe": [
            "base_metrics", 
            "proc_syscall",
            "proc_fs", 
            "proc_io", 
            "proc_dns",
            "proc_pagecache"
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20%,
        "res_upper_thr": 20%,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node"
    },
    "state":"running"
}'

```    

启动proc探针的PUT请求中可以配置很多参数，这些参数共同控制着proc探针的行为，由上往下分析一下请求中的各个重要组成部分        
（1）使用curl命令发起PUT请求     
（2）请求的URL为http://localhost:9999/proc, 9999是Rest server处理启动探针请求监听的端口号，proc为探针的名称      
（3）cmd内容中的bin为io探针的二进制可执行文件的绝对路径，check_cmd为探针启动的条件，这里check_cmd为空时代表探针无条件启动       
（4）cmd内容中的probe对应着探针的采集子项，proc探针probe的内容为base_metrics、proc_syscall、proc_fs、proc_io、proc_dns和proc_pagecache, 
代表proc探针可以采集base_metrics、proc_syscall、proc_fs、proc_io、proc_dns和proc_pagecache数据类型的数据,具体每种数据类型的含义在下文的采集子项详细说明可以查询到     
（5）snoopers内容中的配置探针监听对象有四个维度,proc_id、proc_name、pod_id和container_id, 分别是进程id，进程名称，pod id和容器id，其中任意
一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定      
（6）params内容中的参数，示例中的参数都是proc探针支持的参数   
    report_period是控制着采集的数据上报的周期，值为180的含义是每个180s上报一次采集到的数据         
    res_lower_thr是控制着资源的百分比下限            
    res_upper_thr是控制着资源的百分比上限            
    report_event是控制着探针是否上报异常事件，为1时代表上报异常事件            
    metrics_type控制着上报telemetry的metrics类型          
    env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据          
（7）state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped         


## JVM层GC，线程，内存，缓冲等观测探针配置全集
看看JVM层GC，线程，内存，缓冲等观测探针配置的全集       

```
curl -X PUT http://localhost:9999/jvm --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/jvmprobe",
        "check_cmd": "",
        "probe": [
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20%,
        "res_upper_thr": 20%,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node"
    },
    "state":"running"
}'

```    

启动jvm探针的PUT请求中可以配置很多参数，这些参数共同控制着jvm探针的行为，由上往下分析一下请求中的各个重要组成部分     
（1）使用curl命令发起PUT请求        
（2）请求的URL为http://localhost:9999/jvm, 9999是Rest server处理启动探针请求监听的端口号，jvm为探针的名称           
（3）cmd内容中的bin为io探针的二进制可执行文件的绝对路径，check_cmd为探针启动的条件，这里check_cmd为空时代表探针无条件启动          
（4）cmd内容中的probe对应着探针的采集子项，jvm探针probe的内容为空
（5）snoopers内容中的配置探针监听对象有四个维度,proc_id、proc_name、pod_id和container_id, 分别是进程id，进程名称，pod id和容器id，其中任意
一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定      
（6）params内容中的参数，示例中的参数都是jvm探针支持的参数       
    report_period是控制着采集的数据上报的周期，值为180的含义是每个180s上报一次采集到的数据                  
    res_lower_thr是控制着资源的百分比下限                             
    res_upper_thr是控制着资源的百分比上限                                    
    report_event是控制着探针是否上报异常事件，为1时代表上报异常事件                                         
    metrics_type控制着上报telemetry的metrics类型                                              
    env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据                                           
（7）state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped             


## Redis性能SLI（访问时延）观测探针配置全集
看看Redis性能SLI（访问时延）观测探针配置的全集            

```
curl -X PUT http://localhost:9999/ksli --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/ksliprobe",
        "check_cmd": "",
        "probe": [
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "report_period": 180,
        "latency_thr": 60,
        "res_lower_thr": 20%,
        "res_upper_thr": 20%,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node",
        "dev_name": [
            "io",
            "kafka"
        ],
        "continuous_sampling": 1
    },
    "state":"running"
}'

```    

启动ksli探针的PUT请求中可以配置很多参数，这些参数共同控制着ksli探针的行为，由上往下分析一下请求中的各个重要组成部分                
（1）使用curl命令发起PUT请求               
（2）请求的URL为http://localhost:9999/ksli, 9999是Rest server处理启动探针请求监听的端口号，jvm为探针的名称               
（3）cmd内容中的bin为ksli探针的二进制可执行文件的绝对路径，check_cmd为探针启动的条件，这里check_cmd为空时代表探针无条件启动                
（4）cmd内容中的probe对应着探针的采集子项，ksli探针probe的内容为空，表示上报对应的meta文件的相关指标数据全采集             
（5）snoopers内容中的配置探针监听对象有四个维度,proc_id、proc_name、pod_id和container_id, 分别是进程id，进程名称，pod id和容器id，其中任意
一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定                              
（6）params内容中的参数，示例中的参数都是ksli探针支持的参数                      
    report_period是控制着采集的数据上报的周期，值为180的含义是每个180s上报一次采集到的数据                               
    latency_thr控制着时延上报的门限，值为180的含义是时延大于180ms时进行时延的上报                                 
    res_lower_thr是控制着资源的百分比下限                               
    res_upper_thr是控制着资源的百分比上限                                  
    report_event是控制着探针是否上报异常事件，为1时代表上报异常事件                                 
    metrics_type控制着上报telemetry的metrics类型                                      
    env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据                                                 
    dev_name控制着观测的网卡/磁盘的设备名，值为io和kafka的含义是观测设备名为io与kafka的设备                                          
    continuous_sampling控制着是否持续采样，为1的含义是持续采样                                     
（7）state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped     


## PG DB性能SLI（访问时延）观测探针配置全集
看看PG DB性能SLI（访问时延）观测探针配置的全集      

```
curl -X PUT http://localhost:9999/postgre_sli --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/postgre_sli_probe",
        "check_cmd": "",
        "probe": [
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20%,
        "res_upper_thr": 20%,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node",
        "dev_name": [
            "io",
            "kafka"
        ]
    },
    "state":"running"
}'

```    

启动postgre_sli探针的PUT请求中可以配置很多参数，这些参数共同控制着postgre_sli探针的行为，由上往下分析一下请求中的各个重要组成部分       
（1）使用curl命令发起PUT请求        
（2）请求的URL为http://localhost:9999/postgre_sli, 9999是Rest server处理启动探针请求监听的端口号，postgre_sli为探针的名称          
（3）cmd内容中的bin为postgre_sli探针的二进制可执行文件的绝对路径，check_cmd为探针启动的条件，这里check_cmd为空时代表探针无条件启动           
（4）cmd内容中的probe对应着探针的采集子项，postgre_sli探针probe的内容为空，代表对应的meta文件的指标数据全采集        
（5）snoopers内容中的配置探针监听对象有四个维度,proc_id、proc_name、pod_id和container_id, 分别是进程id，进程名称，pod id和容器id，其中任意
一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定       
（6）params内容中的参数，示例中的参数都是postgre_sli探针支持的参数      
    report_period是控制着采集的数据上报的周期，值为180的含义是每个180s上报一次采集到的数据           
    res_lower_thr是控制着资源的百分比下限         
    res_upper_thr是控制着资源的百分比上限      
    report_event是控制着探针是否上报异常事件，为1时代表上报异常事件       
    metrics_type控制着上报telemetry的metrics类型                
    env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据          
    dev_name控制着观测的网卡/磁盘的设备名，值为io和kafka的含义是观测设备名为io与kafka的设备            
（7）state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped                 


## openGauss访问吞吐量观测探针配置全集
看看openGauss访问吞吐量观测探针配置的全集         

```
curl -X PUT http://localhost:9999/opengauss_sli --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/opengauss_sli_probe",
        "check_cmd": "",
        "probe": [
        ]
    },
    "snoopers": {
        "ip": [
            "ip1",
            "ip2"
        ],
        "port": [
            "port1",
            "port2"
        ],
        "dbname": [
            "dbname1",
            "dbname2"
        ],
        "user": [
            "user1",
            "user2"
        ],
        "password": [
            "password1",
            "password2"
        ]
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20%,
        "res_upper_thr": 20%,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node"
    },
    "state":"running"
}'

```    

启动opengauss_sli探针的PUT请求中可以配置很多参数，这些参数共同控制着opengauss_sli探针的行为，由上往下分析一下请求中的各个重要组成部分           
（1）使用curl命令发起PUT请求                      
（2）请求的URL为http://localhost:9999/opengauss_sli, 9999是Rest server处理启动探针请求监听的端口号，opengauss_sli为探针的名称                  
（3）cmd内容中的bin为opengauss_sli探针的二进制可执行文件的绝对路径，check_cmd为探针启动的条件，这里check_cmd为空时代表探针无条件启动                      
（4）cmd内容中的probe对应着探针的采集子项，opengauss_sli探针probe的内容为空时代表opengauss探针对应的meta文件的指标数据全采集                  
（5）snoopers内容中的配置探针监听对象有四个维度,proc_id、proc_name、pod_id和container_id, 分别是进程id，进程名称，pod id和容器id，其中任意
一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定               
（6）params内容中的参数，示例中的参数都是opengauss_sli探针支持的参数            
    report_period是控制着采集的数据上报的周期，值为180的含义是每个180s上报一次采集到的数据            
    res_lower_thr是控制着资源的百分比下限            
    res_upper_thr是控制着资源的百分比上限                          
    report_event是控制着探针是否上报异常事件，为1时代表上报异常事件                        
    metrics_type控制着上报telemetry的metrics类型                        
    env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据                      
（7）state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped       


## DNS会话观测探针配置全集
看看DNS会话观测探针配置的全集            

```
curl -X PUT http://localhost:9999/dnsmasq --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/dnsmasq_probe",
        "check_cmd": "",
        "probe": [
        ]
    },
    "snoopers": {
        "ip": [
            "ip1",
            "ip2"
        ],
        "port": [
            "port1",
            "port2"
        ],
        "dbname": [
            "dbname1",
            "dbname2"
        ],
        "user": [
            "user1",
            "user2"
        ],
        "password": [
            "password1",
            "password2"
        ]
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20%,
        "res_upper_thr": 20%,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node",
        "elf_path": "/usr/lib/bin/log"
    },
    "state":"running"
}'

```    

启动dnsmasq探针的PUT请求中可以配置很多参数，这些参数共同控制着dnsmasq探针的行为，由上往下分析一下请求中的各个重要组成部分        
（1）使用curl命令发起PUT请求    
（2）请求的URL为http://localhost:9999/dnsmasq, 9999是Rest server处理启动探针请求监听的端口号，dnsmasq为探针的名称        
（3）cmd内容中的bin为dnsmasq探针的二进制可执行文件的绝对路径，check_cmd为探针启动的条件，这里check_cmd为空时代表探针无条件启动        
（4）cmd内容中的probe对应着探针的采集子项，dnsmasq探针probe的内容为空时代表dnsmasq探针对应的meta文件的指标数据全采集                            
（5）snoopers内容中的配置探针监听对象有四个维度,proc_id、proc_name、pod_id和container_id, 分别是进程id，进程名称，pod id和容器id，其中任意
一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定                 
（6）params内容中的参数，示例中的参数都是dnsmasq探针支持的参数                 
    report_period是控制着采集的数据上报的周期，值为180的含义是每个180s上报一次采集到的数据     
    res_lower_thr是控制着资源的百分比下限                
    res_upper_thr是控制着资源的百分比上限                      
    report_event是控制着探针是否上报异常事件，为1时代表上报异常事件                 
    metrics_type控制着上报telemetry的metrics类型               
    env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据                
    elf_path控制着要观测的可执行文件的路径,值/usr/lib/bin/log为要观测的可执行文件的路径           
（7）state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped             


## lvs会话观测探针配置全集
看看lvs会话观测探针配置的全集             

```
curl -X PUT http://localhost:9999/lvs --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/lvsprobe",
        "check_cmd": "",
        "probe": [
        ]
    },
    "snoopers": {
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20%,
        "res_upper_thr": 20%,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node"
    },
    "state":"running"
}'

```    

启动lvs探针的PUT请求中可以配置很多参数，这些参数共同控制着lvs探针的行为，由上往下分析一下请求中的各个重要组成部分            
（1）使用curl命令发起PUT请求             
（2）请求的URL为http://localhost:9999/lvs, 9999是Rest server处理启动探针请求监听的端口号，lvs为探针的名称              
（3）cmd内容中的bin为lvs探针的二进制可执行文件的绝对路径，check_cmd为探针启动的条件，这里check_cmd为空时代表探针无条件启动           
（4）cmd内容中的probe对应着探针的采集子项，lvs探针probe的内容为空时代表lvs探针对应的meta文件中的指标数据全采集                       
（5）snoopers内容中的配置探针监听对象为空                 
（6）params内容中的参数，示例中的参数都是lvs探针支持的参数              
    report_period是控制着采集的数据上报的周期，值为180的含义是每个180s上报一次采集到的数据             
    res_lower_thr是控制着资源的百分比下限                  
    res_upper_thr是控制着资源的百分比上限                 
    report_event是控制着探针是否上报异常事件，为1时代表上报异常事件                 
    metrics_type控制着上报telemetry的metrics类型                
    env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据                      
（7）state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped                        


## Nginx L4/L7层会话观测探针配置全集
看看Nginx L4/L7层会话观测探针配置的全集                 

```
curl -X PUT http://localhost:9999/nginx --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/nginxprobe",
        "check_cmd": "",
        "probe": [
        ]
    },
    "snoopers": {
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20%,
        "res_upper_thr": 20%,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node",
        "elf_path": "/usr/lib/bin/log"
    },
    "state":"running"
}'

```    

启动nginx探针的PUT请求中可以配置很多参数，这些参数共同控制着nginx探针的行为，由上往下分析一下请求中的各个重要组成部分                 
（1）使用curl命令发起PUT请求                 
（2）请求的URL为http://localhost:9999/nginx, 9999是Rest server处理启动探针请求监听的端口号，nginx为探针的名称               
（3）cmd内容中的bin为nginx探针的二进制可执行文件的绝对路径，check_cmd为探针启动的条件，这里check_cmd为空时代表探针无条件启动             
（4）cmd内容中的probe对应着探针的采集子项，nginx探针probe的内容为空时代表nginx探针对应的meta文件中的指标数据全采集                     
（5）snoopers内容中的配置探针监听对象为空               
（6）params内容中的参数，示例中的参数都是nginx探针支持的参数              
    report_period是控制着采集的数据上报的周期，值为180的含义是每个180s上报一次采集到的数据              
    res_lower_thr是控制着资源的百分比下限                
    res_upper_thr是控制着资源的百分比上限               
    report_event是控制着探针是否上报异常事件，为1时代表上报异常事件                 
    metrics_type控制着上报telemetry的metrics类型                       
    env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据                
    elf_path控制着要观测的可执行文件的路径             
（7）state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped                    


## Haproxy L4/L7层会话观测探针配置全集
看看Haproxy L4/L7层会话观测探针配置的全集           

```
curl -X PUT http://localhost:9999/haproxy --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/haproxyprobe",
        "check_cmd": "",
        "probe": [
        ]
    },
    "snoopers": {
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20%,
        "res_upper_thr": 20%,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node"
    },
    "state":"running"
}'

```    

启动haproxy探针的PUT请求中可以配置很多参数，这些参数共同控制着haproxy探针的行为，由上往下分析一下请求中的各个重要组成部分          
（1）使用curl命令发起PUT请求           
（2）请求的URL为http://localhost:9999/haproxy, 9999是Rest server处理启动探针请求监听的端口号，haproxy为探针的名称          
（3）cmd内容中的bin为haproxy探针的二进制可执行文件的绝对路径，check_cmd为探针启动的条件，这里check_cmd为空时代表探针无条件启动       
（4）cmd内容中的probe对应着探针的采集子项，haproxy探针probe的内容为空时代表haproxy探针对应的meta文件的指标数据全采集                   
（5）snoopers内容中的配置探针监听对象为空           
（6）params内容中的参数，示例中的参数都是haproxy探针支持的参数             
    report_period是控制着采集的数据上报的周期，值为180的含义是每个180s上报一次采集到的数据                
    res_lower_thr是控制着资源的百分比下限             
    res_upper_thr是控制着资源的百分比上限             
    report_event是控制着探针是否上报异常事件，为1时代表上报异常事件             
    metrics_type控制着上报telemetry的metrics类型       
    env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据                 
（7）state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped              


## Kafka 生产者/消费者topic观测探针配置全集
看看Kafka 生产者/消费者topic观测探针配置的全集             

```
curl -X PUT http://localhost:9999/kafka --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/kafkaprobe",
        "check_cmd": "",
        "probe": [
        ]
    },
    "snoopers": {
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20%,
        "res_upper_thr": 20%,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node"
    },
    "state":"running"
}'

```    

启动kafka探针的PUT请求中可以配置很多参数，这些参数共同控制着kafka探针的行为，由上往下分析一下请求中的各个重要组成部分              
（1）使用curl命令发起PUT请求           
（2）请求的URL为http://localhost:9999/haproxy, 9999是Rest server处理启动探针请求监听的端口号，kafka为探针的名称           
（3）cmd内容中的bin为kafka探针的二进制可执行文件的绝对路径，check_cmd为探针启动的条件，这里check_cmd为空时代表探针无条件启动             
（4）cmd内容中的probe对应着探针的采集子项，kafka探针probe的内容为空时代表kafka探针对应的meta文件的指标数据全采集                    
（5）snoopers内容中的配置探针监听对象为空         
（6）params内容中的参数，示例中的参数都是kafka探针支持的参数         
    report_period是控制着采集的数据上报的周期，值为180的含义是每个180s上报一次采集到的数据          
    res_lower_thr是控制着资源的百分比下限   
    res_upper_thr是控制着资源的百分比上限        
    report_event是控制着探针是否上报异常事件，为1时代表上报异常事件           
    metrics_type控制着上报telemetry的metrics类型     
    env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据       
（7）state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped              


## 系统基础信息观测探针配置全集
看看系统基础信息观测探针配置的全集             

```
curl -X PUT http://localhost:9999/baseinfo --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/baseinfoprobe",
        "check_cmd": "",
        "probe": [
            "cpu",
            "mem",
            "nic",
            "disk",
            "net",
            "fs",
            "proc",
            "host"
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]        
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20%,
        "res_upper_thr": 20%,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node",
        "dev_name": [
            "io",
            "kafka"
        ]
    },
    "state":"running"
}'

```    

启动baseinfo探针的PUT请求中可以配置很多参数，这些参数共同控制着baseinfo探针的行为，由上往下分析一下请求中的各个重要组成部分       
（1）使用curl命令发起PUT请求        
（2）请求的URL为http://localhost:9999/baseinfo, 9999是Rest server处理启动探针请求监听的端口号，baseinfo为探针的名称           
（3）cmd内容中的bin为baseinfo探针的二进制可执行文件的绝对路径，check_cmd为探针启动的条件，这里check_cmd为空时代表探针无条件启动             
（4）cmd内容中的probe对应着探针的采集子项，baseinfo探针probe的内容为空cpu，mem，nic，disk，net，fs，proc，host，代表着baseinfo探针会采集
cpu，mem，nic，disk，net，fs，proc，host这些类型的数据          
（5）snoopers内容中的配置探针监听对象有四个维度，proc_id、proc_name、pod_id和container_id，分别是进程id，进程名称，pod id和容器id，其中任意
一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定            
（6）params内容中的参数，示例中的参数都是baseinfo探针支持的参数            
    report_period是控制着采集的数据上报的周期，值为180的含义是每个180s上报一次采集到的数据              
    res_lower_thr是控制着资源的百分比下限           
    res_upper_thr是控制着资源的百分比上限                   
    report_event是控制着探针是否上报异常事件，为1时代表上报异常事件                 
    metrics_type控制着上报telemetry的metrics类型            
    env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据            
（7）state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped                


## 虚拟化观测探针（virt）配置全集
看看虚拟化观测探针（virt）配置的全集                  

```
curl -X PUT http://localhost:9999/virt --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/virtprobe",
        "check_cmd": "",
        "probe": [
        ]
    },
    "snoopers": {
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20%,
        "res_upper_thr": 20%,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node"
    },
    "state":"running"
}'

```    

启动virt探针的PUT请求中可以配置很多参数，这些参数共同控制着virt探针的行为，由上往下分析一下请求中的各个重要组成部分            
（1）使用curl命令发起PUT请求            
（2）请求的URL为http://localhost:9999/virt, 9999是Rest server处理启动探针请求监听的端口号，virt为探针的名称           
（3）cmd内容中的bin为virt探针的二进制可执行文件的绝对路径，check_cmd为探针启动的条件，这里check_cmd为空时代表探针无条件启动              
（4）cmd内容中的probe对应着探针的采集子项，virt探针的probe对应着探针的采集子项为空时代表virt对应的meta文件的指标数据全采集               
（5）snoopers内容中的配置探针监听对象为空                
（6）params内容中的参数，示例中的参数都是virt探针支持的参数                 
    report_period是控制着采集的数据上报的周期，值为180的含义是每个180s上报一次采集到的数据     
    res_lower_thr是控制着资源的百分比下限      
    res_upper_thr是控制着资源的百分比上限                
    report_event是控制着探针是否上报异常事件，为1时代表上报异常事件           
    metrics_type控制着上报telemetry的metrics类型             
    env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据         
（7）state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped         


## 线程级性能profiling探针（tprofiling）配置全集
看看线程级性能profiling探针配置的全集             

```
curl -X PUT http://localhost:9999/tprofiling --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/tprofilingprobe",
        "check_cmd": "",
        "probe": [
            "oncpu",
            "syscall_file",
            "syscall_net",
            "syscall_lock",
            "syscall_sched"
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20%,
        "res_upper_thr": 20%,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node"
    },
    "state":"running"
}'

```    

启动tprofiling探针的PUT请求中可以配置很多参数，这些参数共同控制着tprofiling探针的行为，由上往下分析一下请求中的各个重要组成部分                
（1）使用curl命令发起PUT请求             
（2）请求的URL为http://localhost:9999/tprofiling, 9999是Rest server处理启动探针请求监听的端口号，tprofiling为探针的名称            
（3）cmd内容中的bin为tprofiling探针的二进制可执行文件的绝对路径，check_cmd为探针启动的条件，这里check_cmd为空时代表探针无条件启动        
（4）cmd内容中的probe对应着探针的采集子项，tprofiling探针的probe对应着探针的采集子项为oncpu、syscall_file、syscall_net、syscall_lock、
syscall_sched,代表tprofiling探针会采集这些类型的数据            
（5）snoopers内容中的配置探针监听对象有四个维度,proc_id、proc_name、pod_id和container_id, 分别是进程id，进程名称，pod id和容器id，其中任意
一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定               
（6）params内容中的参数，示例中的参数都是virt探针支持的参数                
    report_period是控制着采集的数据上报的周期，值为180的含义是每个180s上报一次采集到的数据          
    res_lower_thr是控制着资源的百分比下限              
    res_upper_thr是控制着资源的百分比上限                
    report_event是控制着探针是否上报异常事件，为1时代表上报异常事件              
    metrics_type控制着上报telemetry的metrics类型             
    env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据         
（7）state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped           


## 容器信息探针（container）配置全集
看看容器信息探针（container）配置的全集              

```
curl -X PUT http://localhost:9999/container --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/containerprobe",
        "check_cmd": "",
        "probe": [
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params":{
        "report_period": 180,
        "res_lower_thr": 20%,
        "res_upper_thr": 20%,
        "report_event": 1,
        "metrics_type": [
            "raw",
            "telemetry"
        ],
        "env": "node"
    },
    "state":"running"
}'

```    

启动container探针的PUT请求中可以配置很多参数，这些参数共同控制着container探针的行为，由上往下分析一下请求中的各个重要组成部分           
（1）使用curl命令发起PUT请求           
（2）请求的URL为http://localhost:9999/container, 9999是Rest server处理启动探针请求监听的端口号，container为探针的名称             
（3）cmd内容中的bin为container探针的二进制可执行文件的绝对路径，check_cmd为探针启动的条件，这里check_cmd为空时代表探针无条件启动               
（4）cmd内容中的probe对应着探针的采集子项，container探针的probe对应着探针的采集子项为空               
（5）snoopers内容中的配置探针监听对象有四个维度,proc_id、proc_name、pod_id和container_id, 分别是进程id，进程名称，pod id和容器id，其中任意
一个都可以指定要监控的对象，监控对象指定之后，关于采集的监控对象相关的信息由cmd中的probe内容和params中的内容一起指定            
（6）params内容中的参数，示例中的参数都是container探针支持的参数            
    report_period是控制着采集的数据上报的周期，值为180的含义是每个180s上报一次采集到的数据               
    res_lower_thr是控制着资源的百分比下限      
    res_upper_thr是控制着资源的百分比上限             
    report_event是控制着探针是否上报异常事件，为1时代表上报异常事件           
    metrics_type控制着上报telemetry的metrics类型                  
    env控制着工作环境类型，为node的含义是gala-gopher工作在工作结点，负责采集工作结点的数据             
（7）state控制着探针的状态，启动探针时state必须配置为running，停止探针时state必须配置为stopped                 

注：以上的所有探针的bin属性，即代表探针的二进制可执行文件的绝对文件路径是可省略的，对使用探针不会有影响

下面介绍使用探针的步骤            

## 开启探针的步骤总结         
为了开启火焰图探针，需要先启动gala-gopher，之后发送请求给Rest server，以下面的启动探针请求为例，介绍一下开启探针时需要注意的几点                
（1）请求方法为PUT方法            
（2）端口号默认为9999，也可以在gala-gopher.conf配置文件中进行配置      
（3）flamegraph为探针的名字，bin为探针的二进制可执行文件的二选制文件的绝对文件路径       
（4）probe数组：probe数组中的内容控制了探针会采集哪些数据，火焰图探针的probe数组中的内容可以为"oncpu"、"offcpu"和"mem", 代表着火焰图探针可以采集"oncpu"、"offcpu"和"mem"类型的数据。如果probe数组为空则代表火焰图探针不会采集任何数据          
（5）snoopers数组：snoopers数组中的内容为探针所监控的对象，可以通过配置proc_ id(进程id)、proc_name (进程名称)、pod_id、container_id (容器id)指定探针监控的对象，snoopers为空时代表探针不会监控任何对象             
（6）state为探针的状态，由于需要开启探针，所以state必须为running才能开启探针           

开启火焰图探针的命令如下：            

```
curl -X PUT http://localhost:9999/flamegraph --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/stackprobe",
        "check_cmd": "",
        "probe": [
        ]
    },
    "snoopers": {
        "proc_id": [
        ],
        "proc_name": [
        ],
        "pod_id": [
        ],
        "container_id": [
        ]
    },
    "state":"running"
}'

```


## 配置探针监控范围  

探针的监控范围可以在开启探针时设置或者在开启探针后设置。探针监控范围由snoopers数组下的监控对象和probe数组下的需要采集的数据类型决定               

（1）配置snoopers数组下的监控对象（进程ID、进程名、容器ID、POD四个维度）          
以配置proc_id为例，可以尝试简单的配置监控某一个进程，假设你已经知晓该进程的进程id，如果该进程id为101和102，则配置火焰图探针监测该进程可以
将进程id填入snoopers数组下的proc_id              

配置探针监测指定进程示例如下：            

```
curl -X PUT http://localhost:9999/flamegraph --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/stackprobe",
        "check_cmd": "",
        "probe": [
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
        ],
        "pod_id": [
        ],
        "container_id": [
        ]
    }
}'
```

由于前面已经开启了flamegraph探针，配置flamegraph探针的监控范围可不带state状态，配置了proc_id之后可以不配置proc_name，flamegraph
探针可以根据proc_id识别到指定的进程              

（2）配置probe数组下的需要采集的数据类型               
flamegraph探针支持采集的数据类型有三种，分别是oncpu、offcpu和mem，可以选择你希望采集的数据类型，可以是oncpu、offcpu和mem的任意组合                

下面是火焰图同时开启oncpu, offcpu采集特性的API举例：               

```
curl -X PUT http://localhost:9999/flamegraph --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/stackprobe",
        "check_cmd": "",
        "probe": [
            "oncpu",
            "offcpu"
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    }
}'

```

以上，正确地开启并配置了flamegraph探针的监控范围                        


## 扩展         

下面，我们再多了解一些探针相关的信息               

gala-gopher支持采集多种特性，每种特性对应一个探针，你可以按照上面的步骤尝试使用指定的探针，目前所有探针支持采集的全量采集特性说明如下：                        

| 采集特性          | 采集特性说明                      | 采集子项范围                                                 | 监控对象                                 | 启动文件                               | 启动条件                  |
|---------------|-----------------------------| ------------------------------------------------------------ | ---------------------------------------- |------------------------------------| ------------------------- |
| flamegraph    | 在线性能火焰图观测能力                 | oncpu, offcpu, mem                                           | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/stackprobe        |                           |
| l7            | 应用7层协议观测能力                  | l7_bytes_metrics、l7_rpc_metrics、l7_rpc_trace               | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/l7probe           |                           |
| tcp           | TCP异常、状态观测能力                | tcp_abnormal, tcp_rtt, tcp_windows, tcp_rate, tcp_srtt, tcp_sockbuf, tcp_stats,tcp_delay | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/tcpprobe          |                           |
| socket        | Socket(TCP/UDP)异常观测能力       | tcp_socket, udp_socket                                       | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/endpoint          |                           |
| io            | Block层I/O观测能力               | io_trace, io_err, io_count, page_cache                       | NA                                       | $gala-gopher-dir/ioprobe           |                           |
| proc          | 进程系统调用、I/O、DNS、VFS等观测能力     | base_metrics, proc_syscall, proc_fs, proc_io, proc_dns,proc_pagecache | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/taskprobe         |                           |
| jvm           | JVM层GC, 线程, 内存, 缓存等观测能力     | NA                                                           | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/jvmprobe          |                           |
| ksli          | Redis性能SLI（访问时延）观测能力        | NA                                                           | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/ksliprobe         |                           |
| postgre_sli   | PG DB性能SLI（访问时延）观测能力        | NA                                                           | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/pgsliprobe        |                           |
| opengauss_sli | openGauss访问吞吐量观测能力          | NA                                                           | [ip, port, dbname, user,password]        | $gala-gopher-dir/pg_stat_probe.py  |                           |
| dnsmasq       | DNS会话观测能力                   | NA                                                           | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/rabbitmq_probe.sh |                           |
| lvs           | lvs会话观测能力                   | NA                                                           | NA                                       | $gala-gopher-dir/trace_lvs         | lsmod\|grep ip_vs\| wc -l |
| nginx         | Nginx L4/L7层会话观测能力          | NA                                                           | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/nginx_probe       |                           |
| haproxy       | Haproxy L4/7层会话观测能力         | NA                                                           | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/trace_haproxy     |                           |
| kafka         | kafka 生产者/消费者topic观测能力      | NA                                                           | dev, port                                | $gala-gopher-dir/kafkaprobe        |                           |
| baseinfo      | 系统基础信息                      | cpu, mem, nic, disk, net, fs, proc,host                      | proc_id, proc_name, pod_id, container_id | system_infos                       | NA                        |
| virt          | 虚拟化管理信息                     | NA                                                           | NA                                       | virtualized_infos                  | NA                        |
| tprofiling    | 线程级性能profiling观测能力          | oncpu, syscall_file, syscall_net, syscall_lock, syscall_sched | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/tprofiling        | NA                        |
| container     | 容器信息                        | NA                                                           | proc_id, proc_name, container_id         | $gala-gopher-dir/cadvisor_probe.py | NA                        |
| sermant       | Java应用7层协议观测能力，当前已支持dubbo协议 | l7_bytes_metrics、l7_rpc_metrics、               | proc_id, proc_name, pod_id, container_id | $gala-gopher-dir/sermant_probe.py  |                           |

每个探针支持的采集子项的详细说明如下：                  

| 采集特性          | 采集特性说明                      | 采集子项范围                                                 | 采集子项详细说明                                 |
|---------------|-----------------------------| ------------------------------------------------------------ | ---------------------------------------- |
| flamegraph    | 在线性能火焰图观测能力                 | oncpu, offcpu, mem                                           | oncpu：采集应用程序允许在cpu上时的状态，可以帮助识别出线程是如何消耗cpu资源的，以及主要耗时的函数调用<br/> offcpu：采集应用程序线程不在cpu上运行时的状态，帮助分析获取线程因执行什么操作（如等待I/O、锁）而进入offcpu<br/> mem：采集应用程序线程查询的时间范围内的内存申请的堆栈，获取内存使用情况 |
| l7            | 应用7层协议观测能力                  | l7_bytes_metrics、l7_rpc_metrics、l7_rpc_trace               | l7_bytes_metrics：采集应用程序接收及发送的数据字节数和接收和发送的数据包个数<br/> l7_rpc_metrics：采集应用程序线程接收的请求个数、发送的响应个数、请求的吞吐量、响应的吞吐量、平均时延、总时延、错误率等<br/> l7_rpc_trace：目前功能还不支持 |
| tcp           | TCP异常、状态观测能力                | tcp_abnormal, tcp_rtt, tcp_windows, tcp_rate, tcp_srtt, tcp_sockbuf, tcp_stats,tcp_delay | tcp_abnormal：tcp异常信息<br/> tcp_rtt：tcp连接数据传输的往返时间<br/> tcp_windows：tcp窗口相关信息<br/> tcp_rate：tcp传输速率<br/> tcp_srtt：tcp连接的srtt时间<br/> tcp_sockbuf：接收和发送数据的缓冲区的大小<br/> tcp_stats：tcp连接状态<br/> tcp_delay：tcp传输时延信息 |
| socket        | Socket(TCP/UDP)异常观测能力       | tcp_socket, udp_socket                                       | tcp_socket：tcp socket信息<br/> udp_socket：udp socket信息 |
| io            | Block层I/O观测能力               | io_trace, io_err, io_count, page_cache                       | io_trace：I/O请求数<br/> io_err：I/O错误信息<br/> io_count：I/O操作读和写的字节数<br/> page_cache：缓冲I/O信息 |
| proc          | 进程系统调用、I/O、DNS、VFS等观测能力     | proc_syscall, proc_fs, proc_io, proc_dns,proc_pagecache | proc_syscall：进程系统调用信息<br/> proc_fs：进程调用文件系统信息<br/> proc_io：进程I/O信息<br/> proc_dns：dns访问监控<br/> proc_pagecache：进程使用缓冲的信息 |
| jvm           | JVM层GC, 线程, 内存, 缓存等观测能力     | NA                                                           | NA |
| ksli          | Redis性能SLI（访问时延）观测能力        | NA                                                           | NA |
| postgre_sli   | PG DB性能SLI（访问时延）观测能力        | NA                                                           | NA |
| opengauss_sli | openGauss访问吞吐量观测能力          | NA                                                           | NA |
| dnsmasq       | DNS会话观测能力                   | NA                                                           | NA |
| lvs           | lvs会话观测能力                   | NA                                                           | NA |
| nginx         | Nginx L4/L7层会话观测能力          | NA                                                           | NA |
| haproxy       | Haproxy L4/7层会话观测能力         | NA                                                           | NA |
| kafka         | kafka 生产者/消费者topic观测能力      | NA                                                           | NA |
| baseinfo      | 系统基础信息                      | cpu, mem, nic, disk, net, fs, proc,host                      | cpu：cpu性能<br/> mem：内存性能<br/> nic：网卡性能<br/> disk：磁盘性能<br/> net：协议栈统计信息<br/> fs：文件系统信息<br/> proc：进程信息<br/> host：主机信息 |
| virt          | 虚拟化管理信息                     | NA                                                           | NA                                       |
| tprofiling    | 线程级性能profiling观测能力          | oncpu, syscall_file, syscall_net, syscall_lock, syscall_sched | oncpu：应用程序线程运行在cpu上时的状态，帮助识别出线程是如何消耗cpu资源，以及主要耗时的函数调用<br/> syscall_file：系统调用文件系统的信息<br/> syscall_net：系统调用的网络性能<br/> syscall_lock：系统调用死锁的次数<br/> syscall_sched：系统调用的次数 |
| container     | 容器信息                        | NA                                                           | NA |


## 配置探针的监听对象

```
curl -X PUT http://localhost:9999/flamegraph --data-urlencode json='
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/stackprobe",
        "check_cmd": "",
        "probe": [
            "oncpu",
            "offcpu"
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    }
}'

```

配置监听对象     
proc_id：proc_id代表进程id，进程id可以使用ps命令查询到        
proc_name：proc_name中的一个对象包含comm、cmdline和debugging_dir，假设这一个对象的进程id已知为101，则该进程的comm值为/proc/101/comm文件中的内容，cmdline值为/proc/101/cmdline文件中的内容，debugging_dir的含义是预留给探针设置debug目录，现在还没实际功能                 
pod_id：pod 是可以在 Kubernetes 中创建和管理的、最小的可部署的计算单元，可以使用了kubectl run创建pod并获取pod_name，然后使用kubectl get pods -n <namespace> <pod-name> -o jsonpath='{.metadata.uid}'获取pod_id            
container_id：可以使用docker容器，通过docker run运行一个容器，通过docker ps查看container_id                

Rest server监听开启探针请求的端口和探针请求的URL，即http://[gala-gopher所在节点ip] + [端口号] + function（采集特性）中使用的端口号是一个含义，
这个端口是可以配置的，下面如何进行配置      

配置文件的文件名为gala-gopher.conf，查看该文件，找到如下内容     

```
rest_api_server =
{
    port = 9999;
    ssl_auth = "off";
    private_key = "";
    cert_file = "";
    ca_file = "";
};
```

rest_api_server中的port即是端口号，可以对port的内容进行修改     
探针请求的URL中的 [端口号] 需要与port中的内容保持一致      


## 配置Rest server监听开启探针请求的端口号

Rest server监听开启探针请求的端口和探针请求的URL，即http://[gala-gopher所在节点ip] + [端口号] + function（采集特性）中使用的端口号是一个含义，
这个端口是可以配置的，下面如何进行配置     

配置文件的文件名为gala-gopher.conf，查看该文件，找到如下内容     

```
rest_api_server =
{
    port = 9999;
    ssl_auth = "off";
    private_key = "";
    cert_file = "";
    ca_file = "";
};
```

rest_api_server中的port即是端口号，可以对port的内容进行修改    
探针请求的URL中的 [端口号] 需要与port中的内容保持一致     


## 配置探针扩展标签

探针上报指标数据时会根据meta文件上报相应的标签信息。此外，用户也可以通过动态配置接口增加一些扩展的标签信息进行上报。当前支持的拓展标签有：        

- 固定标签         

  固定标签是指具有固定值的标签，用户可以在 `snoopers` 配置选项中添加 `custom_labels` 进行配置，该标签会在探针的指标数据上报时填充进去。             

  例如，通过下面的配置为 proc 探针添加一个 `task="task1"` 的标签。            

  ```
  curl -X PUT http://localhost:9999/proc --data-urlencode json='   
  {
      "snoopers": {
          "custom_labels": {
          	"task": "task1"
          }
      }
  }'

- Pod级标签         

  Pod级标签是指 k8s 附加到 Pod 对象上的键值对，一个 Pod 对象一般包含多个 Pod 标签。用户可以在 `snoopers` 配置选项中添加 `pod_labels` 配置项来指定需要上报哪些 Pod 标签。           
  
  例如，通过下面的配置为 proc 探针指定需要上报的 Pod 标签包括 "app" 和 "test"。如果配置的 Pod 标签不存在，则填充一个默认值 "not found" 。                
  
  ```
  curl -X PUT http://localhost:9999/proc --data-urlencode json='
  {
      "snoopers": {
          "pod_labels": ["app", "test"]
      }
  }'
  ```
  
  注：flamegraph探针不会根据meta文件上报标签信息，配置探针扩展标签这里不适用于flamegraph探针                        


## 配置探针参数

探针在启动时或运行期间可以设置一些参数，这些参数同样控制了探针的行为，如果希望指定探针的采样周期和上报周期，则可以设置火焰图的采样
周期sample_period和上报周期report_period，sample_period和report_period都是配置的探针参数                   

```
curl -X PUT http://localhost:9999/flamegraph --data-urlencode json='
{
    "params": {
        "report_period": 180,
        "sample_period": 180,
        "metrics_type": [
            "raw",
            "telemetry"
        ]
    }
}'
```

详细参数运行参数如下：                 

| 参数               | 含义                                                   | 缺省值&范围                                                  | 单位    | 支持的监控范围           | gala-gopher是否支持 |
| ------------------ | ------------------------------------------------------ | ------------------------------------------------------------ | ------- | ------------------------ | ------------------- |
| sample_period      | 采样周期                                               | 5000, [100~10000]                                             | ms      | io, tcp                  | Y                   |
| report_period      | 上报周期                                               | 60, [5~600]                                                 | s       | ALL                      | Y                   |
| latency_thr        | 时延上报门限                                           | 0, [10~100000]                                               | ms      | tcp, io, proc, ksli      | Y |
| offline_thr | 进程离线上报门限 | 0, [10~100000] | ms | proc | Y |
| drops_thr          | 丢包上送门限                                           | 0, [10~100000]                                               | package | tcp, nic                 | Y                   |
| res_lower_thr      | 资源百分比下限                                         | 0%, [0%~100%]                                                | percent | ALL                      | Y                   |
| res_upper_thr      | 资源百分比上限                                         | 0%, [0%~100%]                                                | percent | ALL                      | Y                   |
| report_event       | 上报异常事件                                           | 0, [0, 1]                                                    |         | ALL                      | Y                   |
| metrics_type       | 上报telemetry metrics                                  | raw, [raw, telemetry]                                        |         | ALL                      | N                   |
| env                | 工作环境类型                                           | node, [node, container, kubenet]                             |         | ALL                      | N                   |
| report_source_port | 是否上报源端口                                         | 0, [0, 1]                                                    |         | tcp                      | Y                   |
| l7_protocol        | L7层协议范围                                           | http, [http, pgsql, mysql, redis, kafka,  mongo, rocketmq, dns] |         | l7                       | Y                   |
| support_ssl        | 支持SSL加密协议观测                                    | 0, [0, 1]                                                    |         | l7                       | Y                   |
| multi_instance | 是否每个进程输出独立火焰图 | 0, [0, 1] |  | flamegraph | Y |
| native_stack | 是否显示本地语言堆栈(针对JAVA进程) | 0, [0, 1] | | flamegraph | Y |
| cluster_ip_backend | 执行Cluster IP backend转换 | 0, [0, 1] | | tcp，l7 | Y |
| pyroscope_server   | 设置火焰图UI服务端地址                                 | localhost:4040                                               |         | flamegraph               | Y                   |
| svg_period | 火焰图svg文件生成周期 | 180, [30, 600] | s | flamegraph | Y |
| perf_sample_period | oncpu火焰图采集堆栈信息的周期 | 10, [10, 1000] | ms | flamegraph | Y |
| svg_dir | 火焰图svg文件存储目录 | "/var/log/gala-gopher/stacktrace" | | flamegraph | Y |
| flame_dir | 火焰图原始堆栈信息存储目录 | "/var/log/gala-gopher/flamegraph" | | flamegraph | Y |
| dev_name | 观测的网卡/磁盘设备名 | "" |  | io, kafka, ksli, postgre_sli，baseinfo, tcp | Y |
| continuous_sampling | 是否持续采样 | 0, [0, 1] | | ksli | Y |
| elf_path | 要观测的可执行文件的路径 | "" | | nginx, haproxy, dnsmasq | Y |
| kafka_port | 要观测的kafka端口号 | 9092, [1, 65535] | | kafka | Y |
| cadvisor_port | 启动的cadvisor端口号 | 8080, [1, 65535] | | cadvisor | Y |

注：探针参数只能配置在支持的监控范围中的探针，例如，参数sample_period对应的支持的监控范围为io和tcp，则表明参数sample_period只能配置在
io探针和tcp探针，参数report_period对应的支持的监控范围为ALL，则表明参数report_period可以配置在gala-gopher支持的所有参数的参数中                   


## 启动、停止探针

"state"为running时代表开启探针，"state"为stopped时代表关闭探针。开启探针时请求参数中必须带有"state"：running，否则探针不能被开启，
停止探针时请求参数中必须带有"state"："stopped"，否则探针不能被停止                   
```
curl -X PUT http://localhost:9999/flamegraph --data-urlencode json='
{
    "state": "running" // optional: running,stopped
}'
```



## 约束与限制说明

```
1. 接口为无状态形式，每次上传的设置为该探针的最终运行结果，包括状态、参数、监控范围。
2. 监控对象可以任意组合，监控范围取合集。
3. 启动文件必须真实有效。
4. 采集特性可以按需开启全部/部分能力，关闭时只能整体关闭某个采集特性。
5. opengauss监控对象是DB实例（IP/Port/dbname/user/password）
6. 接口每次最多接收1M字节长度的数据
```



## 获取探针配置与运行状态

使用GET方法，获取名为flamegraph的探针的信息，请求命令为：                         

```
curl -X GET http://localhost:9999/flamegraph
```

GET请求的响应如下，"state"为探针的运行状态，running代表探针是运行中的状态，其余信息均为探针的配置信息                   

```
curl -X GET http://localhost:9999/flamegraph
{
    "cmd": {
        "bin": "/opt/gala-gopher/extend_probes/stackprobe",
        "check_cmd": ""
        "probe": [
            "oncpu",
            "offcpu"
        ]
    },
    "snoopers": {
        "proc_id": [
            101,
            102
        ],
        "proc_name": [
            {
                "comm": "app1",
                "cmdline": "",
                "debugging_dir": ""
            },
            {
                "comm": "app2",
                "cmdline": "",
                "debugging_dir": ""
            }
        ],
        "pod_id": [
            "pod1",
            "pod2"
        ],
        "container_id": [
            "container1",
            "container2"
        ]
    },
    "params": {
        "report_period": 180,
        "sample_period": 180,
        "metrics_type": [
            "raw",
            "telemetry"
        ]
    },
    "state": "running"
}
```
