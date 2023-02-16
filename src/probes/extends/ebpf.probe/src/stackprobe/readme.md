# stackprobe简介

## 探针描述

适用于云原生环境的系统资源占用火焰图。

## 特性

- 支持对C/C++、Go、Rust、JAVA语言应用的堆栈采集和转换。

- 调用栈支持容器、进程粒度：对于容器内进程，在调用栈底部分别以[Pod]和[Con]前缀标记工作负载Pod名称、容器Container名称。进程名以[<pid>]前缀标识，线程及函数（方法）无前缀。

- 支持本地生成svg格式火焰图或上传堆栈数据到中间件

## 配置说明

可在启动stackprobe探针前修改配置文件stackprobe.conf，也可使用默认配置。

下面说明主要配置项：

- 设置开启/关闭进程白名单

  通过whitelist_enable参数设置，参数值为`true`或`false`，表示是否仅采样白名单内进程。
  
  示例：

  `whitelist_enable = false;`

- 设置生成本地火焰图svg文件的周期

  通过period参数设置，单位为秒，默认值180，可选设置范围为[30, 600]的整数。
  
  示例：

  `period = 180;`

- 设置堆栈信息上传到pyroscope

  通过pyroscope_server参数设置，参数值需要包含addr和port，参数为空或格式错误则探针不会尝试上传堆栈信息。

  上传周期30s。
  
  示例：

  `pyroscope_server = "localhost:4040";`

- 设置生成火焰图类型

  通过flame_name下各火焰图类型参数设置，参数值为`true`或`false`，表示开启或关闭该类型火焰图监测。
  
  示例：

  `oncpu = true;`

## 实现方案

### oncpu火焰图：

通过eBPF + 系统perf事件10ms频率采样堆栈状态，生成CPU占用火焰图。

### memleak火焰图：

通过uprobe eBPF，跟踪glibc的内存相关函数，计算进程申请和释放的内存差值，生成内存泄漏火焰图。

### Java语言支持：

- jvm_agent.so：注册JVMTI回调函数

  当JVM加载一个Java方法或者动态编译一个本地方法时JVM会调用回调函数，回调函数会将java类名和方法名以及对应的内存地址写入到被观测java进程空间下（/proc/\<pid\>/root/tmp/java-sym-\<pid\>/java-symbols.bin）

- jvm_attach：用于实时加载jvm_agent.so到被观测进程的JVM上

  1. 设置自身的namespace（JVM加载agent时要求加载进程和被观测进程的namespace一致）

  2. 检查JVM attach listener是否启动（是否存在UNIX socket文件：/proc/\<pid\>/root/tmp/.java_pid\<pid\>）

  3. 未启动则创建/proc/\<pid\>/cwd/.attach_pid\<pid\>，并发送SIGQUIT信号给JVM

  4. 连接UNIX socket

  5. 读取响应为0表示attach成功

- java_support线程：监控java进程

  1. 发现新增java进程则将jvm_agent.so复制到该进程空间下/proc/\<pid\>/root/tmp（因为attach时容器内JVM需要可见此agent）

  2. 设置上述目录和jvm_agent.so的owner和被观测java进程一致

  3. 启动jvm_attach子进程，并传入被观测java进程相关参数

- stackprobe主进程：加载对应java进程的java-symbols.bin文件，供地址转换符号时查询。

## 注意事项

- 对于Java应用的观测，为获取最佳观测效果，请开启JVM选项XX:+PreserveFramePointer（JDK8以上）

## 约束条件

- 支持基于hotspot JVM的Java应用观测
