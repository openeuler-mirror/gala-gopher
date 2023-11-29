# gala-gopher

![](./doc/pic/logo.png)

### 什么是gala-gopher

gala-gopher是gala项目内负责数据采集的组件，其为gala项目提供Metrics、Event、Perf等数据，便于gala项目完成系统拓扑的绘制和故障根因的定位。   
gala-gopher是一款结合eBPF、java agent等非侵入可观测技术的观测平台，探针是gala-gopher用于观测和采集数据的主要工具，通过探针式架构gala-gopher可以轻松实现增加、减少探针。    

## 观测范围

### 系统性能

系统层资源可能会影响应用性能，使用gala-gopher将提供Node、Container、Device等维度的系统性能观测能力。包括：

- CPU性能：参见[CPU性能指标](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#cpu%E6%80%A7%E8%83%BD)，将提供CPU粒度的实时性能指标。
- 内存性能：参见[内存性能指标](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#%E5%86%85%E5%AD%98%E6%80%A7%E8%83%BD)，将系统内存、buffer、cache、dentry等多种资源实时指标。
- 网络性能：参见[网卡性能指标](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#%E7%BD%91%E5%8D%A1%E7%BB%9F%E8%AE%A1)，[协议栈性能](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#%E5%8D%8F%E8%AE%AE%E6%A0%88%E7%BB%9F%E8%AE%A1)统计，包括主机内TCP连接数量、接收报文数量、网卡收发字节数、丢包数等。
- I/O性能：参见[Block性能指标](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#block%E7%BB%9F%E8%AE%A1)，[磁盘指标](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#%E7%A3%81%E7%9B%98%E7%BB%9F%E8%AE%A1)，包括磁盘读写速率、使用率、吞吐量等指标，以及block层驱动、设备的时延、错误统计。
- 容器性能：参见[容器性能指标](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#%E5%AE%B9%E5%99%A8%E6%80%A7%E8%83%BD)，提供容器维度CPU、内存、I/O、网络多维度可观测数据。

### 网络监控

通过网络监控能力，可以轻松获取如下信息：

- 集群内微服务间TCP流量拓扑：提供进程粒度[TCP流量监控](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#tcp%E6%B5%81%E9%87%8F%E7%9B%91%E6%8E%A7)，结合[gala-spider](https://gitee.com/openeuler/gala-spider)可以轻松获取集群内微服务间TCP拓扑。
- DNS访问监控：参考[DNS访问监控](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#dns%E8%AE%BF%E9%97%AE%E7%9B%91%E6%8E%A7)，提供进程内DNS域名访问的平均、最大时延、错误率。
- TCP/IP监控：提供TCP连接粒度的[异常监控](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#tcp%E5%BC%82%E5%B8%B8%E7%9B%91%E6%8E%A7)，包括重传、丢包、TCP oom、收发RST等异常指标；提供[Socket异常监控](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#socket%E7%9B%91%E6%8E%A7)，包括listen队列溢出、syn队列溢出、建链失败次数等统计信息。

### 应用（微服务）访问性能监控

云原生场景会部署大量微服务，微服务之间访问性能的波动会直接影响整体业务效果，使用gala-gopher可以轻松了解每个微服务（或者POD）的[访问时延、吞吐量、错误率性能](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#%E5%BA%94%E7%94%A8%E5%BE%AE%E6%9C%8D%E5%8A%A1%E8%AE%BF%E9%97%AE%E6%80%A7%E8%83%BD)。

其支持微服务之间的访问协议包括：

| 协议       | 路线图                           | 备注 |
| ---------- | -------------------------------- | ---- |
| HTTP 1.X   | openEuler 22.03 SP3（23.12月份） |      |
| HTTP2.0    | openEuler 24.03 LTS（24.3月份）  |      |
| Redis      | openEuler 22.03 SP3（23.12月份） |      |
| Kafka      | openEuler 22.03 SP3（23.12月份） |      |
| MySQL      | openEuler 22.03 SP3（23.12月份） |      |
| PostgreSQL | openEuler 24.03 LTS（24.3月份）  |      |

支持加密场景：C/C++语言（OpenSSL 1.1.0/1.1.1）; GO语言（GoTLS）；Java语言（JSSE类库）

### 应用性能监控

应用性能经常受系统资源性能影响，gala-gopher可以提供应用视角精细化（进程粒度）的系统性能观测能力，涉及网络、I/O、内存、调度等多个方面。

- [TCP性能](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#tcp%E6%80%A7%E8%83%BD)：提供TCP窗口、RTT、SRTT、reordering、ato等性能指标；
- [应用性能](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#%E5%BA%94%E7%94%A8%E6%80%A7%E8%83%BD)：提供[基于流的性能监控](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#%E5%9F%BA%E4%BA%8E%E6%B5%81%E7%9A%84%E8%BF%9B%E7%A8%8B%E6%80%A7%E8%83%BD)、[进程性能监控](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#%E8%BF%9B%E7%A8%8B%E6%80%A7%E8%83%BD)，其提供基于TCP流的性能（时延、吞吐量）统计，体现应用性能。
- [I/O性能](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#io%E6%80%A7%E8%83%BD-1)：提供进程维度的 I/O操作字节数统计、FD资源占用统计、文件系统（vfs/ext4/overlay/tmpfs）层时延统计，大小I/O操作数量统计、BIO时延、错误统计（虚拟化QEMU进程有意义）等；
- [内存](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#%E5%86%85%E5%AD%98)：提供进程维度的pagefault、swap区、脏页、虚拟内存、物理内存等统计。
- [调度&系统调用](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#%E8%B0%83%E5%BA%A6%E7%B3%BB%E7%BB%9F%E8%B0%83%E7%94%A8)：提供进程维度系统调用时延、错误统计，进程用户态、系统态运行统计时间。
- [JVM监控](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#jvm%E7%9B%91%E6%8E%A7)：提供jvm线程、java类加载、jvm内存、jvm buffer、gc次数/花费时间等统计。

### 性能Profiling

性能火焰图是常用的性能问题诊断工具，常见的性能火焰图工具（perf、ansyc-profier）存在底噪大、精细化不够、多语言能力不够等问题。

gala-gopher提供持续、低底噪、多实例形式的性能Profiling能力，覆盖C/C++、Go、Java（最佳效果时，推荐加上-XX:+PreserveFramePointer启动参数）语言。

![Profiling示例](./doc/pic/profiling.png)

使用方法参考[这里](https://gitee.com/openeuler/gala-docs#qa)。

### kafka监控

kafka通常作为分布式应用场景中的消息中心，现有监控工具对kafka topic的观测、跟踪缺乏有效手段，gala-gopher针对此问题，提供自动化的kafka监控能力。提供能力如下：

- [Topic流监控](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#topic%E6%B5%81%E7%9B%91%E6%8E%A7)：提供topic 生产者、消费者的IP、Port信息，结合gala-spider，可以绘制出topic流视图。

- [Topic性能](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#topic%E6%80%A7%E8%83%BD%E7%9B%91%E6%8E%A7)：提供topic维度的吞吐量性能。

  约束：不支持加密场景。

### nginx/haproxy监控

nginx/haproxy通常作为云原生应用之间的负载均衡，网络流量经过负载均衡之后，现有监控工具无法有效观测云原生应用之间的真实流量路径。gala-gopher为此提供面向负载均衡的网络流量观测能力：

- [Nginx负载分担监控](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#nginx-%E8%B4%9F%E8%BD%BD%E5%88%86%E6%8B%85%E7%9B%91%E6%8E%A7)：提供nginx负载分担会话观测能力，基于负载分担会话，结合gala-spider可以绘制出云原生应用之间真实流量路径。
- [Haproxy负载分担监控](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#haproxy%E8%B4%9F%E8%BD%BD%E5%88%86%E6%8B%85%E7%9B%91%E6%8E%A7)：提供haproxy负载分担会话观测能力，基于负载分担会话，结合gala-spider可以绘制出云原生应用之间真实流量路径。
- [TCP性能监控](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#tcp%E6%80%A7%E8%83%BD%E7%9B%91%E6%8E%A7)：针对nginx、haproxy这类软件提供TCP性能监控能力，包括TCP窗口、RTT、SRTT、reordering、ato等性能指标。
- [TCP异常监控](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#tcp%E5%BC%82%E5%B8%B8%E7%9B%91%E6%8E%A7-1)：针对nginx、haproxy这类软件提供TCP异常监控能力，包括重传、丢包、TCP oom、收发RST等异常指标。
- [Socket监控](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#socket%E7%9B%91%E6%8E%A7-1)：针对nginx、haproxy这类软件提供Socket监控能力，包括listen队列溢出、syn队列溢出、建链失败次数等统计信息。

![负载分担流量监控](./doc/pic/demo.gif)

### Redis/PostgreSQL监控

Redis/PostgreSQL常用于为应用提供数据存储服务，现有性能监控工具（拨测、打点）存在失真、误差等问题，gala-gopher针对redis/PostgreSQL应用，提供非侵入的性能观测能力。除此以外，这类应用性能经常受网络、I/O影响，gala-gopher提供针对这些应用的网络、I/O监控能力。

- [Redis性能监控](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#redis%E6%80%A7%E8%83%BD%E7%9B%91%E6%8E%A7)：提供精细化的（具体到某个TCP）redis时延监控能力。（注意不支持加密场景）
- [PostgreSQL性能监控](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#postgresql%E6%80%A7%E8%83%BD%E7%9B%91%E6%8E%A7)：提供精细化的（具体到某个TCP）Postgre时延监控能力。
- [TCP性能监控](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#tcp%E6%80%A7%E8%83%BD%E7%9B%91%E6%8E%A7-1)：针对Redis、PostgreSQL这类软件提供TCP性能监控能力，包括TCP窗口、RTT、SRTT、reordering、ato等性能指标。
- [TCP异常监控](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#tcp%E5%BC%82%E5%B8%B8%E7%9B%91%E6%8E%A7-2)：针对Redis、PostgreSQL这类软件提供TCP异常监控能力，包括重传、丢包、TCP oom、收发RST等异常指标。
- [Socket监控](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#socket%E7%9B%91%E6%8E%A7-2)：针对Redis、PostgreSQL这类软件提供Socket监控能力，包括listen队列溢出、syn队列溢出、建链失败次数等统计信息。
- [I/O性能](https://gitee.com/openeuler/gala-docs/blob/master/gopher_tech.md#io%E6%80%A7%E8%83%BD-2)：针对Redis、PostgreSQL这类软件，提供进程维度的 I/O操作字节数统计、FD资源占用统计、文件系统（vfs/ext4/overlay/tmpfs）层时延统计，大小I/O操作数量统计等；

## eBPF如何更好的运行在java场景

### 场景1：持续性能Profiling

gala-gopher提供持续性能Profiling可以持续监控应用的OnCPU、OffCPU、Memory Alloc等性能。使用eBPF周期性或事件触发式的监控应用程序，持续收集应用堆栈信息。

通过java agent获取java函数符号表，eBPF获取堆栈信息，两者结合完成java场景的持续profiling。

![java场景性能Profiling](./doc/pic/java-agent-1.png)

### 场景2：微服务访问性能监控

gala-gopher提供的微服务访问性能监控可以非侵入、多语言的完成L7层流量性能监控能力。在java场景中，java应用会使用JSSE类库进行加密通信，eBPF在内核层获取到L7层流量是加密态，无法完成解析以及性能监控。通过java agent字节码注入技术，将JSSEProbeAgent.jar attach至目标jvm进程完成明文RPC消息的获取，通过临时文件读入l7Probe。

![java场景性能RPC密文观测](./doc/pic/java-agent-2.png)

## 如何解决跨版本兼容性问题

参考[这里](https://gitee.com/openeuler/gala-gopher/blob/dev/doc/compatible.md)。

## 安装指南

### RPM方式部署

- 获取rpm包

  gala-gopher目前已在openEuler 21.09（已停止维护）/openEuler 22.09（已停止维护）/openEuler 22.03-LTS-SP1发布，可以通过配置以上发布版本的正式repo源来获取rpm包；对于其他发布版本我们提供了以下方式来获取rpm包：

  - （1）方法一：OBS 链接，网页手动下载对应架构的rpm包

    ```basic
    openEuler-20.03-LTS-SP1 : https://117.78.1.88/package/show/home:zpublic:branches:openEuler:20.03:LTS:SP1/gala-gopher
    openEuler-22.03-LTS : https://117.78.1.88/package/show/home:zpublic:branches:openEuler:22.03:LTS/gala-gopher
    openEuler-22.03-LTS-SP1 : https://117.78.1.88/package/show/home:zpublic:branches:openEuler:22.03:LTS:SP1/gala-gopher
    ```

  - （2）方法二：使用命令编译构造rpm包
    构造rpm包时，主要的文件为gala-gopher.spec，需要根据所在的机器进行以下几点修改
    
    1：%define vmlinux_ver 5.10.0-126.0.0.66.oe2203.%{_arch}
    需要从src\probes\extends\ebpf.probe\src\include目录中，根据内核版本、CPU架构选择相应的版本号，该版本号与sh build.sh --debug后填写的版本号是一致的
    
    2：Version字段代表版本号，需要与gala-gopher目前的文件名称后的版本号是一致的
    
    ```手动给该项目指定版本号 2.0.0
        mv gala-gopher gala-gopher-2.0.0
        tar czf gala-gopher-2.0.0.tar.gz gala-gopher-2.0.0   tar包需要与目录名保持一致
    ```
    
    Version后的版本号需要与指定的版本号一致，修改Version后的版本号为2.0.0，即Version：2.0.0
    
    3：安装rpm-build
    
    ```bash
      yum install rpm-build
    ```
    
    4：新建目录/root/rpmbuild/SOURCES并将tar包放入目录/root/rpmbuild/SOURCES目录中
    
    ```bash
          mv gala-gopher-2.0.0.tar.gz  /root/rpmbuild/SOURCES
    ```
    
    5：构建rpm包
    
    ```bash
          rpmbuild -ba gala-gopher.spec
    ```
    
    执行目录后，查看编译的输出，看到生成的rpm包文件被存放在/root/rpmbuild/RPMS/x86_64/目录下，看一下示例的输出
    
    ```
          /root/rpmbuild/RPMS/x86_64/gala-gopher-debugsource-2.0.0-1.ky10.x86_64.rpm
          /root/rpmbuild/RPMS/x86_64/gala-gopher-2.0.0-1.ky10.x86_64.rpm
          /root/rpmbuild/RPMS/x86_64/gala-gopher-debuginfo-2.0.0-1.ky10.x86_64.rpm
    ```
  
- rpm安装

  （1）如果是通过OBS 链接从网页手动下载对应架构的rpm包，则rpm安装的方法
  
    ```bash
           yum install gala-gopher
    ```
  
    注：1. 上面指令中 gala-gopher 应填写完整包名，如gala-gopher-1.0.2-2.oe2203.x86_64.rpm。2. 当使用yum指令前，用户应自行配置yum源。

  （2）如果是通过rpmbuild命令编译构建的rpm包，则rpm安装的方法
  
    ```bash
           yum install /root/rpmbuild/RPMS/x86_64/gala-gopher-2.0.0-1.ky10.x86_64.rpm
    ```
- 启动服务

  通过 systemd 启动后台服务：

  ```bash
  systemctl start gala-gopher.service
  ```

### 容器方式部署

- 获取容器镜像

  用户可以选择直接[获取官方容器镜像](#docker1)或自行[构建容器镜像](#docker2)

  <a id="docker1"></a>

  - 获取官方容器镜像

    根据系统架构和版本从官方仓库拉取对应tag的gala-gopher官方容器镜像（以openEuler 22.03 LTS SP1为例），目前支持的镜像版本tag有：20.03-lts-sp1，22.03-lts，22.03-lts-sp1，kylin-v10-sp1(仅支持x86_64)，kylin-v10-sp3(仅支持x86_64)：

    ```
    # x86
    docker pull hub.oepkgs.net/a-ops/gala-gopher-x86_64:22.03-lts-sp1
    
    # aarch64
    docker pull hub.oepkgs.net/a-ops/gala-gopher-aarch64:22.03-lts-sp1
    ```
    
    注：如果拉取镜像的过程中出现"X509: certificate signed by unknown authority"错误，则需要将"hub.oepkgs.net"加入到/etc/docker/daemon.json中的"insecure-registries"项后重启docker服务再重试。
  
  <a id="docker2"></a>
  
  - 构建容器镜像
  
    获取gala-gopher的rpm包，获取方式详见[RPM方式部署](#RPM方式部署)。
  
    用于生成容器镜像的Dockerfile文件归档在[build目录](https://gitee.com/openeuler/gala-gopher/tree/dev/build)，生成方法详见[如何生成gala-gopher容器镜像](https://gitee.com/openeuler/gala-gopher/blob/dev/doc/how_to_build_docker_image.md)。
  
- 创建并运行容器

  - 启动容器

    执行如下命令（以创建openEuler 22.03 LTS SP1 x86版本、名字为gala-gopher的容器为例）：

    ```
    docker run -d --name gala-gopher --privileged --pid=host --network=host \
    -v /:/host -v /etc/localtime:/etc/localtime:ro -v /sys:/sys \
    -v /usr/lib/debug:/usr/lib/debug -v /var/lib/docker:/var/lib/docker \
    -e GOPHER_HOST_PATH=/host \
    hub.oepkgs.net/a-ops/gala-gopher-x86_64:22.03-lts-sp1
    ```

    其中，GOPHER_HOST_PATH环境变量用于指定容器外根目录"/"映射到gala-gopher容器内的目录，以便gala-gopher能够正常访问宿主机上的关键文件，必配且建议保持默认/host。

    另外可通过如下环境变量配置gala-gopher，若不指定，则使用配置文件默认配置：

    - GOPHER_LOG_LEVEL：gala-gopher日志输出级别
    - GOPHER_EVENT_CHANNEL：gala-gopher亚健康巡检异常事件输出方式
    - GOPHER_META_CHANNEL：gala-gopher观测对象元数据metadata输出方式
    - GOPHER_KAKFA_SERVER：gala-gopher上报亚健康巡检异常事件、观测对象元数据metadata的kafka服务端IP地址
    - GOPHER_METRIC_PORT：gala-gopher作为prometheus exporter输出指标数据的监听端口
    - GOPHER_REST_PORT：动态配置RESTful API端口号
    - GOPHER_METRIC_LOGS_TOTAL_SIZE：metrics指标数据日志文件总大小的上限，单位为MB
    - GOPHER_PROBES_INIT：控制gala-gopher启动后默认开启的探针以及其配置（采集子项、监控对象、参数），每个探针单独一行，每行内容为[采集特性名] [动态配置json]，特性名和json格式参照[REST API说明](https://gitee.com/openeuler/gala-gopher/blob/dev/config/gala-gopher支持动态配置接口设计_v0.3.md)，不配置则启动gala-gopher容器后不开启任何探针。

  - 通过docker ps查看容器是否运行成功：

    ```
    [root@localhost]# docker ps
    CONTAINER ID        IMAGE                                                   COMMAND                  CREATED             STATUS                     PORTS                    NAMES
    0fb3cad0df40        hub.oepkgs.net/a-ops/gala-gopher-x86_64:22.03-lts-sp1   "/entrypoint.sh /usr…"   6 days ago          3 days ago                             gala-gopher
    ```

- 获取数据

  容器启动后，通过默认的8888端口获取数据来验证gala-gopher是否运行成功，如果启动容器时未通过GOPHER_PROBES_INIT参数指定默认开启的探针，则需要通过[REST API](https://gitee.com/openeuler/gala-gopher/blob/dev/config/gala-gopher支持动态配置接口设计_v0.3.md)开启探针后再获取数据：

  ```
  [root@localhost]# curl http://localhost:8888
  ...
  gala_gopher_udp_que_rcv_drops{tgid="1234",s_addr="192.168.12.34",machine_id="xxxxx",hostname="eaxxxxxxxx02"} 0 1656383357000
  ...
  ```

  如上有指标数据输出则证明gala-gopher运行成功。

### K8S deployment方式部署

[k8s环境部署指导](https://gitee.com/openeuler/gala-gopher/blob/dev/k8s/README.md)

### 自动化脚本方式部署

用户可以选择rpm包或容器镜像方法部署gala-gopher

- 脚本下载

  首先需要下载[离线资源下载脚本](https://gitee.com/openeuler/gala-docs/blob/master/deploy/download_offline_res.sh)和[辅助脚本](https://gitee.com/openeuler/gala-docs/blob/master/deploy/comm.sh)（两种方法均需要），将两个脚本上传到机器上后执行命令（以下两种命令之一）完成相关离线资源下载，下载内容会存放在当前目录的子目录gala_deploy_gopher下。

- 运行脚本下载资源

  - 对应版本gala-gopher及依赖rpm包下载 

    ```xml
    sh download_offline_res.sh gopher [os_version]  [os_arch]
    ```

    os_version、os_arch 可同时配置（或同时使用默认值）：

    - os_version: 指定下载该操作系统版本 gala-gopher 软件包。未配置该项时，使用当前系统版本。支持版本列表：openEuler-22.03-LTS-SP1 openEuler-22.03-LTS openEuler-20.03-LTS-SP1 kylin

    - os_arch: 指定下载该架构 gala-gopher 软件包。未配置该项时，使用当前系统架构。支持架构列表：aarch64 x86_64

  - gala-gopher容器镜像下载     

    指定下载 gala-gopher docker 镜像 tar 和 gala-gopher 配置文件（docker 运行 gala-gopher， 将配置文件映射到宿主机上）。

    ```xml
    sh download_offline_res.sh gopher docker
    ```

    下载 tar 包 和 gala-gopher 配置文件存放在 gala_deploy_gopher 目录下，文件名格式为`gala-gopher-[os_arch]:[os_tag].tar`。下载内容如下：

    ```
      gala-gopher-aarch64:22.03-lts-sp1.tar
      gala-gopher.conf
      gala-gopher-app.conf
      stackprobe.conf
    ```

- 工具一键部署

  与上面介绍的两种下载内容对应，分别提供两种gala-gopher部署方法。部署前需将gala_deploy_gopher目录下的所有文件及[部署脚本](https://gitee.com/openeuler/gala-docs/blob/master/deploy/deploy.sh)和[辅助脚本](https://gitee.com/openeuler/gala-docs/blob/master/deploy/comm.sh)上传到目标生产节点机器上，执行如下命令安装、配置、启动gala-gopher服务，-S选项来指定离线安装包所在的目录。

  - rmp包方式部署

  ```xml
  sh deploy.sh gopher -K <kafka服务器地址> -p <pyroscope服务器地址> -S <离线安装包所在目录>
  ```

  - gala-gopher容器镜像方式部署

  ```xml
  sh deploy.sh gopher -K <kafka服务器地址> -p <pyroscope服务器地址> -S <离线安装包所在目录>  --docker
  ```

  选项详细说明：

  |      选项       |                           参数说明                           |    是否必配    |
  | :-------------: | :----------------------------------------------------------: | :------------: |
  |   -K\|--kafka   | 指定gala-gopher上报采集数据的目标kakfa服务器地址（一般来说是管理节点的IP），当不配置该选项时，kafka服务器地址使用localhost |       否       |
  | -p\|--pyroscope | 指定gala-gopher开启火焰图功能后火焰图上传到的pyroscope服务器地址（用于对接前端界面显示）（一般来说是管理节点的IP），当不配置该选项时，pyroscope服务器地址使用localhost |       否       |
  |  -S\|--srcdir   | 离线部署时使用该选项来指定gala-gopher以及其依赖包所在的目录  | 离线部署时必配 |
  |    --docker     |              指定以 docker 方式部署 gala-gopher              |       否       |

### 系统集成API及方式

[系统集成API及方式](https://gitee.com/openeuler/gala-gopher/blob/dev/doc/api_doc.md)

<a id="config"></a>

### 配置及参数

[配置文件及参数](https://gitee.com/openeuler/gala-gopher/blob/dev/doc/conf_introduction.md)

[REST API介绍](https://gitee.com/openeuler/gala-gopher/blob/dev/config/gala-gopher%E6%94%AF%E6%8C%81%E5%8A%A8%E6%80%81%E9%85%8D%E7%BD%AE%E6%8E%A5%E5%8F%A3%E8%AE%BE%E8%AE%A1_v0.3.md)

[规格与约束](https://gitee.com/openeuler/gala-gopher/blob/dev/doc/constraints_introduction.md)

## 软件架构

gala-gopher集成了常用的native探针以及知名中间件探针；gala-gopher有良好的扩展性，能方便的集成各种类型的探针程序，发挥社区的力量丰富探针框架的能力；gala-gopher中的几个主要部件：

- gala-gopher框架

  gala-gopher的基础框架，负责配置文件解析、native探针/extend探针的管理、探针数据收集管理、探针数据上报对接、集成测试等；

- native探针

  原生探针，主要是基于linux的proc文件系统收集的系统观测指标；

- extend探针

  支持shell/java/python/c等不同语言的第三方探针程序，仅需满足轻量的数据上报格式即可集成到gala-gopher框架中；方便满足各种应用场景下的观测诉求；目前已实现知名中间件程序的探针观测及指标上报，如：lvs、nginx、haproxy、dnsmasq、dnsbind、kafka、rabbitmq等；

- 部署配置文件

  gala-gopher启动配置文件，可自定义具体使能的探针、指定数据上报的对接服务信息（kafka/prometheus等）

## 如何贡献

### 基于源码构建

#### **仅编译二进制**

建议在最低openEuler-20.03-LTS-SP1的环境执行编译动作，这是因为gala-gopher中ebpf探针编译依赖clang和llvm，大多数的bpf功能需要clang 10或者更高版本才可以正常工作，而20.03-SP1以下的发布版本中clang版本较低(低于10)。

首先确保本地已有仓库源码，然后在gala-gopher下的[build目录](https://gitee.com/openeuler/gala-gopher/tree/dev/build)下执行安装工作。

- 安装依赖包

  该步骤会检查安装架构感知框架所有的依赖包，涉及三方探针编译、运行的依赖包会在编译构建中检查安装。

  ```
  # sh build.sh --check
  ```

- 构建

  ```
  # sh build.sh --clean
  # sh build.sh --release     # RELEASE模式
  # 或者
  # sh build.sh --debug       # DEBUG模式
  ```

  注：在编译过程中出现如下信息，表示bpf探针编译需要的vmlinux.h文件缺失；

  ![build_err](./doc/pic/build_err.png)

  vmlinux.h文件包含了系统运行Linux内核源码中使用的所有类型定义，可以利用bpftool工具生成；我们已经预生成了几个openEuler发布版本的vmlinux.h文件在`src\probes\extends\ebpf.probe\src\include`目录，请根据内核版本、CPU架构选择相应的文件，并手动软链接到vmlinux.h；例如：

  ```
  [root@master ~]# uname -r
  4.19.90-2012.5.0.0054.oe1.x86_64
  [root@master ~]# ln -s linux_4.19.90-2012.5.0.0053.oe1.x86_64.h vmlinux.h
  ```

  生成vmlinux.h文件后再次执行构建命令。

- 安装

  ```
  # sh install.sh
  ```

- 运行

  ```
  # gala-gopher
  ```

#### 构建rpm包

我们提供了OBS地址，用于用户编译最新的rpm包。当用户需要最新的rpm包时，可以按照如下步骤自行编译出最新版本的rpm包。

- OBS路径如下：

  ```
  openEuler-20.03-LTS-SP1 : https://117.78.1.88/package/show/home:zpublic:branches:openEuler:20.03:LTS:SP1/gala-gopher
  openEuler-22.03-LTS : https://117.78.1.88/package/show/home:zpublic:branches:openEuler:22.03:LTS/gala-gopher
  openEuler-22.03-LTS-SP1 : https://117.78.1.88/package/show/home:zpublic:branches:openEuler:22.03:LTS:SP1/gala-gopher
  ```

编译前需要选择对应版本的路径，并通过 `Branch package` 按钮拉出个人分支包，如下图所示：

![1667461889396](./doc/pic/obs%E7%BC%96%E8%AF%91-branch_package.png)

> 注：branch操作仅需在第一次编包的时候执行一次，后续可以直接在 **个人已有项目** 处找到，直接执行后续的打包、上传编译等步骤。

- 源码打包

  ```
  # 需要先将gala-gopher文件夹名重命名为gala-gopher-1.0.0
  # 然后打成tar包
  [root@master code]# tar zcvf gala-gopher-1.0.0.tar.gz gala-gopher-1.0.0/
  ```

- tar包上传并触发编译

  还是以编译能够在openEuler-20.03-LTS环境运行的rpm包为例，需要在**外网操作**。参考如下视频：

![obs编译-操作指南](./doc/pic/obs%E7%BC%96%E8%AF%91-%E6%93%8D%E4%BD%9C%E6%8C%87%E5%8D%97.gif)

右侧 `Build Results` 框会显示编译结果，`building`表示还在编译中，`failed`表示编译失败，`succeeded`表示编译成功，编译成功则可以点击获取最新的rpm包。

![1667461827079](./doc/pic/obs%E7%BC%96%E8%AF%91-%E8%8E%B7%E5%8F%96rpm%E5%8C%85.png)

- 安装

  ```
  [root@master ~]# yum localinstall gala-gopher-1.0.0-2.oe1.x86_64.rpm
  ```

- 运行

  ```
  # 前台运行
  [root@master ~]# gala-gopher
  # 通过systemd启动（推荐）
  [root@master ~]# systemctl start gala-gopher.service
  ```

### 探针开发

[探针开发指南](https://gitee.com/openeuler/gala-gopher/blob/dev/doc/how_to_add_probe.md)

## 路线图

### 巡检能力

| 特性                             | 发布时间 | 发布版本                             |
| -------------------------------- | -------- | ------------------------------------ |
| TCP异常巡检                      | 22.12    | openEuler 22.03 SP1                  |
| Socket异常巡检                   | 22.12    | openEuler 22.03 SP1                  |
| 系统调用异常巡检                 | 22.12    | openEuler 22.03 SP1                  |
| 进程I/O异常巡检                  | 22.12    | openEuler 22.03 SP1                  |
| Block I/O异常巡检                | 22.12    | openEuler 22.03 SP1                  |
| 资源泄漏异常巡检                 | 22.12    | openEuler 22.03 SP1                  |
| 硬件（磁盘/网卡/内存）故障巡检   | 23.09    | openEuler 22.03 SP1, openEuler 23.09 |
| JVM异常巡检                      | 23.09    | openEuler 22.03 SP1, openEuler 23.09 |
| 主机网络栈（包括虚拟化）丢包巡检 | 23.09    | openEuler 22.03 SP1, openEuler 23.09 |

### 可观测性

| 特性                                                         | 发布时间 | 发布版本                             |
| ------------------------------------------------------------ | -------- | ------------------------------------ |
| 进程级TCP观测能力                                            | 22.12    | openEuler 22.03 SP1                  |
| 进程级Socket观测能力                                         | 22.12    | openEuler 22.03 SP1                  |
| 分布式存储全栈I/O观测能力                                    | 22.12    | openEuler 22.03 SP1                  |
| 虚拟化存储I/O观测能力                                        | 22.12    | openEuler 22.03 SP1                  |
| Block I/O观测能力                                            | 22.12    | openEuler 22.03 SP1                  |
| 容器运行观测能力                                             | 22.12    | openEuler 22.03 SP1                  |
| Redis性能观测能力                                            | 22.12    | openEuler 22.03 SP1                  |
| PG性能观测能力                                               | 22.12    | openEuler 22.03 SP1                  |
| Nginx会话观测能力                                            | 22.12    | openEuler 22.03 SP1                  |
| Haproxy会话观测能力                                          | 22.12    | openEuler 22.03 SP1                  |
| Kafka会话观测能力                                            | 22.12    | openEuler 22.03 SP1                  |
| JVM性能观测能力                                              | 23.06    | openEuler 22.03 SP1, openEuler 23.09 |
| L7协议观测能力（HTTP1.X/MySQL/PGSQL/Redis/Kafka）            | 23.09    | openEuler 22.03 SP1, openEuler 23.09 |
| L7协议观测能力（HTTP1.X/MySQL/PGSQL/Redis/Kafka/MongoDB/DNS/RocketMQ） | 24.03    | openEuler 22.03 SP3，openEuler 24.03 |
| 通用应用性能观测能力                                         | 24.03    | openEuler 24.03                      |
| 全链路协议跟踪能力                                           | 24.09    | openEuler 24.09                      |

### 性能profiling

| 特性                                    | 发布时间 | 发布版本                             |
| --------------------------------------- | -------- | ------------------------------------ |
| 系统性能Profiling（OnCPU、Mem）         | 23.03    | openEuler 23.09                      |
| 系统性能Profiling（OnCPU、Mem、OffCPU） | 23.04    | openEuler 22.03 SP1, openEuler 23.09 |
| 线程级性能Profiling（java、C）          | 23.06    | openEuler 22.03 SP1, openEuler 23.09 |

### 版本兼容性

| 特性                        | 发布时间 | 发布版本                             |
| --------------------------- | -------- | ------------------------------------ |
| 支持内核Release版本跨度兼容 | 23.12    | openEuler 22.03 SP3, openEuler 24.03 |
| 支持内核大版本跨度兼容      | 24.09    | openEuler 24.09                      |
|                             |          |                                      |

### 可编程&扩展能力

| 特性                           | 发布时间 | 发布版本            |
| ------------------------------ | -------- | ------------------- |
| 非侵入集成第三方探针           | 22.12    | openEuler 22.03 SP1 |
| 非侵入集成第三方eBPF源码       | 24.03    | openEuler 23.09     |
| 大语言驱动自动生成eBPF观测探针 | 24.09    | openEuler 24.09     |



### 部署&集成能力

| 特性                             | 发布时间 | 发布版本                             |
| -------------------------------- | -------- | ------------------------------------ |
| 支持Prometheus exporter对接      | 22.12    | openEuler 22.03 SP1                  |
| 支持日志文件形式对接             | 22.12    | openEuler 22.03 SP1                  |
| 支持kafka client形式对接         | 22.12    | openEuler 22.03 SP1                  |
| 支持REST接口动态变更探针监控能力 | 23.06    | openEuler 22.03 SP1, openEuler 23.09 |
