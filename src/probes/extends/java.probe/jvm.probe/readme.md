# jvmprobe简介

## 探针描述

用于监控运行的JVM进程，查看JVM内部状态。

## 实现方案

jvmprobe 基于`Java Agent`实现零侵入监控，当系统中有新的java进程时，动态地将`JvmProbeAgent.jar`即代理包`attach`到应用程序。这里attach动作利用`/opt/gala-gopher/extend_probe/jvm_attach`二进制实现。

JvmProbeAgent 利用Java的`JMX`机制来读取JVM运行时的一些监控数据，通过调用java.lang.management API监视和管理应用程序的内存使用、线程、GC情况以及运行时编译等方面的信息，并将监控信息转换成固定格式记录到`/tmp/java-data-<pid>/jvm-metric.txt`文件中。

jvmprobe架构图如下：

![1681891119555](D:\code\gala-gopher\doc\pic\jvmprobe实现架构图.png)

### JavaAgent实现思路

java.lang.management 提供了一组管理接口来管理和监视JVM进程，比如：ClassLoadingMXBean提供了一些类的装载信息、MemoryManagerMXBean提供了内存管理和内存池相关信息、GarbageCollectorMXBean提供了进程GC次数、GC总时间等信息。目前支持的指标信息参考jvm_probe.meta文件。通过中间文件 `/tmp/java-data-<pid>/jvm-metrics.txt` 将指标数据传递给探针主程序。

### 主程序实现思路

- 加载JavaAgent

  按照用户输入的采集周期启动代理类：

  ```C
  while (1) {
      ...
      sleep(period);
      jvm_attach <pid> <nspid> load instrument false "/tmp/JvmProbeAgent.jar=<pid>,java-data-<pid>"
      ...
  }
  ```

  > 注：JvmProbeAgent代理没有字节码增强，每次load操作即触发JVM进程启动代理类。

- 获取解析metrics 

  JvmProbeAgent 中将获取到的明文信息等信息存储到 `/tmp/java-data-<pid>/jvm-metrics.txt` 中，主进程解析文件并做下一步处理。 

## 外部依赖

- libinstrument.so



## 测试说明

- 支持的JDK版本：JDK 8、JDK 11

