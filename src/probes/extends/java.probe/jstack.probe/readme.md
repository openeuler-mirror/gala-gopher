# JstackProbe简介

## 探针描述

JstackProbe编译后生成一个Java agent（JstackProbeAgent.jar），可以加载到JVM上用于使能JFR功能并转换JFR统计结果为火焰图可用的堆栈格式。

stackprobe探针可以加载JstackProbeAgent.jar，并利用agent生成的堆栈文件stacks-xxx.txt后续生成火焰图。

## 实现方案

利用JFR API使能JFR功能（待完善）

## 使用示例：

方法一：stackprobe观测java程序时会自动加载JstackProbeAgent.jar到该进程上

方法二：使用agent加载工具手动加载JstackProbeAgent.jar到指定java进程${PID}，并指定观测内存事件(mem)

```shell
jvm_attach ${PID} ${PID} load instrument false "JstackProbeAgent.jar=${PID},/tmp/java-data-${PID},mem"
```
执行后会在/tmp/java-data-${PID}目录下生成两个文件：

/tmp/java-data-${PID}
├── recording-mem.jfr    <!--JFR文件，可用jfr print命令查看，也可使用JMC等工具可视化查看-->
└── stacks-mem.txt       <!--利用JFR文件生成的堆栈信息，可用于生成火焰图-->


## 约束及限制

- JDK需支持JFR， 因此JDK版本要求：JDK 8u262+，JDK 11

## JFR相关参考

- Get started with JDK Flight Recorder in OpenJDK 8u https://developers.redhat.com/blog/2020/08/25/get-started-with-jdk-flight-recorder-in-openjdk-8u#

- Flight Recorder API Programmer’s Guide https://docs.oracle.com/en/java/javase/14/jfapi/flight-recorder-api-programmers-guide.pdf

- Java Flight Recorder Runtime Guide https://docs.oracle.com/javacomponents/jmc-5-4/jfr-runtime-guide/toc.htm

- Backport JFR from JDK11 to JDK8 https://github.com/openjdk/jdk8u/commit/df7e09043392d5952d522a28702c6e5ec3e8492e