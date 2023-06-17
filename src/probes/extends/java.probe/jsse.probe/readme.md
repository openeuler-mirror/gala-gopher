# JSSEProbe 探针开发简介

## 探针描述

JSSE为基于SSL和TLS协议的Java网络应用提供了Java API，JSSEProbe基于字节码插桩技术实现了对JSSE收发报文的观测。

> 注：该目录仅包含javaagent源码，对采集数据的处理在../ebpf.probe/src/l7probe中。



## 外部依赖

- libinstrument.so
- rt.jar



## 实现方案

### JSSEProbeAgent实现思路

通过javaagent动态的对已加载的类进行字节码增强，针对JSSE的指定的（接收、发送相关的）类嵌入字节码指令，在方法进入或退出时刻获取收发明文数据、时间戳等信息并存储到本地文件中。主进程主要是加载代理和定期轮训本地文件获取收发报文信息。

- JavaAgent是一个 jar 包，该 jar 包不能独立运行，需要依附到目标JVM进程中。JavaAgent 还有一种称呼叫 Java 探针，JVM一旦运行起来对于外界而言它就是一个黑盒，而 JavaAgent 可以像一支针一样插到JVM内部，获取进程运行信息。JSSEProbeAgent.jar 即是一个JavaAgent。

- insturment机制 主要提供 Java 代码增强，可以在已有的类上附加（修改）字节码从而实现增强的逻辑。其底层依赖JVMTI实现，jdk提供了 libinstrument.so，探针运行环境需要确认已提供该lib。

- 字节码修改工具 以字节码指令的格式实现代码逻辑，常用的字节码修改工具有：ASM、javasisst、Byte-Buddy 等，由于 ASM 直接操作字节码，性能上高于其他，因而 JSSEAgent 选用 ASM 框架实现。

- 字节码插桩原理如下图所示：

  ![JSSEProbe-BCI](../../../../../doc/pic/JSSEProbe-BCI.png)

### 主程序实现思路

主程序对应源码在 `../ebpf.probe/src/l7probe/java_mng.c` 中。

- 加载JavaAgent

  利用 jvm_attach （该工具实现源码对应 `../../../../../src/common/jvm_attach.c`），将 agent.jar 加载到目标JVM进程上。

  ```shell
  jvm_attach <pid> <nspid> load instrument false "/tmp/JSSEProbeAgent.jar=<pid>,java-data-<pid>"
  ```

- 获取解析metrics

  JSSEProbeAgent 中将获取到的明文信息等信息存储到 `/tmp/java-data-<pid>/jsse-metrics.txt` 中，主进程解析文件并做下一步处理。