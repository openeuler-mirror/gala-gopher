# ebpf.probe开发指南

ebpf.probe是一个bpf探针程序的开发框架，定义了一些开发规范，方便bpf程序的开发集成；

## ebpf.probe目录结构

目录结构：

```sh
├── build.sh				# BPF探针构建脚本
├── install.sh				# BPF探针安装脚本
├── src						# bpf程序源码目录
│   ├── include				# 公共头文件
│   │   ├── tcp.h			# TCP基础库头文件
│   │   ├── linux_4.18.0-147.5.1.6.h425.h		# 内核版本的头文件（仅包含probe使用相关）
│   │   ├── linux_4.19.90-2003.4.0.0036.oe1.h	# 内核版本的头文件（仅包含probe使用相关）
│   │   └── vmlinux.h -> linux_4.19.90-2003.4.0.0036.oe1.h	# 根据编译环境生成的vmlinux.h
│   └── lib					# 基础库
│       ├── tcp.c				# TCP基础库文件
│       ├── container.c			# 容器基础库文件
│       ├── xx.c				# xx基础库文件
│   ├── Makefile				# makefile
│   └── tcpprobe				# tcpprobe探针
│       ├── tcp_link.meta		# 探针数据采集meta文件
│       ├── tcpprobe.bpf.c		# 探针内核BPF程序
│       ├── tcpprobe.c			# 探针用户态BPF程序
│       └── tcpprobe.h			# 相关头文件
│   └── xxprobe					# xxprobe探针
│       ├── xx.meta				# 探针数据采集meta文件
│       ├── xxprobe.bpf.c		# 探针内核BPF程序
│       ├── xxprobe.c			# 探针用户态BPF程序
│       └── xxprobe.h			# 相关头文件
└── tools					# 工具目录
    └── gen_vmlinux_h.sh		# 自动生成vmlinux.h
```
## 如何编译

### 编译命令

```sh
# 环境准备（首次编译内核BPF探针时，需要构建内核头文件）
/etc/yum.repos.d/openEuler.repo
[source]
name=SOURCE
baseurl=https://repo.huaweicloud.com/openeuler/openEuler-20.03-LTS-SP2/source/
enabled=1
gpgcheck=0

[everything]
name=EveryThing
enabled=1
gpgcheck=0
baseurl=http://repo.huaweicloud.com/openeuler/openEuler-20.03-LTS-SP2/everything/x86_64/
**** 注意必须携带source源 ****

# 查看build方法
build.sh -h/--help : Show this message.
build.sh --check: Check the environment including arch/os/kernel/packages.
build.sh -g/--gen : Generate the linux header file.
build.sh -c/--clean: Clean the built binary.
build.sh -b/--build: Build all the probes.

# 生成编译环境的内核vmlinux.h头文件
build.sh -g

编程成功后可以在 gala-gopher/src/probes/extends/ebpf.probe/src/include/ 查看到具体生成的头文件
[root@master ebpf.probe]# ll src/include/
total 6404
-rw-r--r--. 1 root root     192 Oct 25 10:19 args.h
-rw-r--r--. 1 root root   16576 Oct 25 10:19 bpf.h
-rw-r--r--. 1 root root     648 Oct 25 10:19 container.h
-rw-r--r--. 1 root root    2928 Oct 25 10:19 ext_def.h
-rw-r--r--. 1 root root 1996914 Oct 25 10:19 linux_4.19.90-2012.4.0.0053.oe1.h
-rw-r--r--. 1 root root    2847 Oct 25 10:19 tcp.h
-rw-r--r--. 1 root root    1772 Oct 25 10:19 util.h
lrwxrwxrwx. 1 root root      27 Oct 25 10:19 vmlinux.h -> linux_4.19.90-2012.4.0.0053.oe1.h

**** linux_4.19.90-2012.4.0.0053.oe1.h 就是编译生成的头文件

# 编译bpf程序
[root@localhost ebpf.probe]# ./build.sh -b

# 安装bpf程序，安装到 /usr/bin/extends/ebpf.probe 目录下
[root@localhost ebpf.probe]# ./install.sh
/opt/A-Ops/gala-gopher/src/probes/extends/ebpf.probe/src/lib/util.c
.output .output/tcpprobe/ .output/killprobe/ .output/libbpf
tcpprobe/tcpprobe killprobe/killprobe  /usr/bin/extends/ebpf.probe
mkdir -p /usr/bin/extends/ebpf.probe
cp tcpprobe/tcpprobe killprobe/killprobe  /usr/bin/extends/ebpf.probe
[root@localhost ebpf.probe]#

# 清理编译过程
[root@localhost ebpf.probe]# ./build.sh -c
```

注：

1. bpf探针依赖libbpf开发库，./build.sh过程中会从git下载libbpf的稳定版本，编译环境要求能正常访问git；

2. bpf探针要求编译环境安装 elfutils-devel、clang、llvm等软件包，其中clang版本>=10.x.x，./build.sh中会检查安装；

## 如何新增probe程序

### 内核ebpf探针开发过程

1. 在src目录下创建一个独立目录， Makefile中增加新的探针；

   ```sh
   # 1 killprobe为新增的探针目录
   [root@localhost src]# ll
   total 20K
   drwxr-xr-x. 2 root root 4.0K Apr 24 02:09 include
   drwxr-xr-x. 2 root root 4.0K Apr 24 05:33 killprobe
   drwxr-xr-x. 2 root root 4.0K Apr 24 05:33 lib
   -rw-r--r--. 1 root root 2.7K Apr 24 03:57 Makefile
   drwxr-xr-x. 2 root root 4.0K Apr 24 05:33 tcpprobe
   [root@localhost src]#

   # 2 Makefile中增加killprobe探针, killprobe/killprobe /前为探针目录名，/后为探针名称（编译完成后，探针名称即为执行程序名）；
   [root@localhost src]# vim Makefile
   # add probe
   APPS := tcpprobe/tcpprobe \
           killprobe/killprobe \
           lvsprobe/trace_lvs \
           haproxyprobe/trace_haproxy \
           dnsmasqprobe/trace_dnsmasq \
           nginxprobe/nginx_probe \
           taskprobe/taskprobe \
   ```

2. 开发探针BPF代码，BPF源码文件名采用 *探针名*.bpf.c方式命名；

   ```sh
   [root@localhost killprobe]# ll
   total 1.6K
   -rw-r--r--. 1 root root 1.3K Apr 24 02:09 killprobe.bpf.c
   -rw-r--r--. 1 root root  294 Apr 24 02:09 killprobe.h
   [root@localhost killprobe]#
   ```

   1. - BPF程序开发SDK

      ```
      #ifdef BPF_PROG_USER
      #undef BPF_PROG_USER
      #endif
      #define BPF_PROG_KERN
      #include "bpf.h"        *SDK 头文件*

      // kprobe/kretprobe/raw_trace 三种观测方式对应的API
      #define KPROBE(func, type)  // func 内核探针，BPF程序ctx类型
      #define KRETPROBE(func, type)  // func 内核探针，BPF程序ctx类型
      #define KRAWTRACE(func, type)  // func 内核探针，BPF程序ctx类型
      举例：KPROBE(__x64_sys_kill, pt_regs) // 针对内核__x64_sys_kill完成kprobe方式观测
      // 观测点读取参数API
      PT_REGS_PARM1/2/3...6

      // 内核同一个观测点，同时完成kprobe/kretprobe的API
      #define KPROBE_RET(func, type)
      举例：KPROBE_RET(tcp_v4_inbound_md5_hash, pt_regs) // 针对内核tcp_v4_inbound_md5_hash同时kprobe/kretprobe。
      这种API一般用于观测点需要同时观测入参、返回值。

      // 同时观测kprobe/kretprobe对应的读参API
      #define PROBE_GET_PARMS(func, ctx, probe_val, caller_type)
      #define PROBE_PARM1(probe_val)
      ...
      ...
      #define PROBE_PARM5(probe_val)
      PT_REGS_RC(ctx) // 读返回值
      ```

      - BPF程序编译，编译过程完全自动化，build成功后，会产生相应的\*.skel.h、\*.bpf.o 文件。\*.skel.h文件内包括BPF程序的prog、map数据结构、程序加载、卸载等API。方便用户态程序对BPF程序进行操作。

      ```
      在src/.output/killprobe下；
      [root@localhost killprobe]# ll
      total 17.6K
      -rw-r--r--. 1 root root 3.6K Apr 24 05:41 killprobe.bpf.o
      -rw-r--r--. 1 root root  14K Apr 24 05:41 killprobe.skel.h
      ```

3. 开发用户态程序；

   探针用户态程序的目的是从BPF程序中获取观测数据。

   ```sh
   [root@localhost ebpf.probe]# ll src/killprobe/
   total 16K
   -rw-r--r-- 1 root root 1.3K Nov 27 09:23 killprobe.bpf.c
   -rw-r--r-- 1 root root 1.3K Nov 27 09:23 killprobe.c  # 用户态程序
   -rw-r--r-- 1 root root  274 Nov 27 09:23 killprobe.h
   -rw-r--r-- 1 root root  749 Nov 27 09:23 killprobe.meta
   ```

   - 用户态程序开发SDK

   ```
   #ifdef BPF_PROG_KERN
   #undef BPF_PROG_KERN
   #endif

   #ifdef BPF_PROG_USER
   #undef BPF_PROG_USER
   #endif

   #include "bpf.h"  // SDK头文件

   #include "XX.skel.h"  // xx探针

   #define LOAD(probe_name) // 加载XX探针的BPF程序
   #define UNLOAD(probe_name) // 卸载XX探针的BPF程序
   #define GET_MAP_OBJ(map_name) //根据MAP名称GET MAP对象
   #define GET_MAP_FD(map_name)  //根据MAP名称GET MAP ID
   #define GET_PROG_FD(prog_name) //根据程序名称（观测点）GET PROG ID
   ```

4. 探针框架集成探针采集数据方法

   对于需要探针框架集成输出观测指标的探针，要在探针目录下增加meta元模型，定义探针输出的观测指标模型，具体方法参考[如何开发探针](../../../../doc/how_to_add_probe.md)；

### 用户态ebpf探针开发过程

1. 在src目录下创建一个独立目录， Makefile中增加新的探针；

   ```sh
   # 1 nginxprobe为新增的探针目录
   [root@localhost ebpf.probe]# ll src/
   total 48K
   drwxr-xr-x 2 root root 4.0K Nov 27 09:23 dnsmasqprobe
   drwxr-xr-x 2 root root 4.0K Nov 27 09:23 endpointprobe
   drwxr-xr-x 2 root root 4.0K Nov 27 14:55 fileprobe
   drwxr-xr-x 2 root root 4.0K Nov 27 09:23 haproxyprobe
   drwxr-xr-x 2 root root 4.0K Nov 27 15:14 include
   drwxr-xr-x 2 root root 4.0K Nov 27 15:12 killprobe
   drwxr-xr-x 2 root root 4.0K Nov 27 09:23 lib
   drwxr-xr-x 2 root root 4.0K Nov 27 09:23 lvsprobe
   -rw-r--r-- 1 root root 3.0K Nov 27 09:23 Makefile
   drwxr-xr-x 2 root root 4.0K Nov 27 14:33 nginxprobe

   # 2 Makefile中增加nginxprobe探针, nginxprobe/nginx_probe /前为探针目录名，/后为探针名称（编译完成后，探针名称即为执行程序名）；
   [root@localhost src]# vim Makefile
   # add probe
   APPS := tcpprobe/tcpprobe \
           killprobe/killprobe \
           lvsprobe/trace_lvs \
           haproxyprobe/trace_haproxy \
           dnsmasqprobe/trace_dnsmasq \
           nginxprobe/nginx_probe \
           taskprobe/taskprobe \
   ```

2. 开发探针BPF代码，BPF源码文件名采用 *探针名*.bpf.c方式命名；

   ```sh
   [root@localhost ebpf.probe]# ll src/nginxprobe/
   total 32K
   -rw-r--r-- 1 root root 3.7K Nov 27 09:23 nginx_1.12.1.h
   -rw-r--r-- 1 root root 1.2K Nov 27 09:23 nginx_link.meta
   -rw-r--r-- 1 root root 4.8K Nov 27 09:23 nginx_probe.bpf.c
   -rw-r--r-- 1 root root 5.0K Nov 27 09:23 nginx_probe.c
   -rw-r--r-- 1 root root  864 Nov 27 09:23 nginx_probe.h
   -rw-r--r-- 1 root root 2.1K Nov 27 09:23 readme.md
   ```

   1. - BPF程序开发SDK

      ```
      #ifdef BPF_PROG_KERN
      #undef BPF_PROG_KERN
      #endif
      #define BPF_PROG_USER
      #include "bpf.h"        *SDK 头文件*

      // uprobe/uretprobe 两种观测方式对应的API
      #define UPROBE(func, type)  // 用户态程序需要观测的function，BPF程序ctx类型
      #define URETPROBE(func, type)  // 用户态程序需要观测的function，BPF程序ctx类型
      举例：UPROBE(ngx_close_connection, pt_regs) // 针对Nginx观测connection关闭行为
      // 观测点读取参数API
      PT_REGS_PARM1/2/3...6

      // 内核同一个观测点，同时完成uprobe/uretprobe的API
      #define UPROBE_RET(func, type, prog_id)
      这种API一般用于观测点需要同时观测入参、返回值。

      // 同时观测uprobe/uretprobe对应的读参API
      #define PROBE_GET_PARMS(func, ctx, probe_val, prog_id)
      #define PROBE_PARM1(probe_val)
      ...
      ...
      #define PROBE_PARM5(probe_val)
      PT_REGS_RC(ctx) // 读返回值
      ```

      - BPF程序编译，编译过程完全自动化，build成功后，会产生相应的\*.skel.h、\*.bpf.o 文件。\*.skel.h文件内包括BPF程序的prog、map数据结构、程序加载、卸载等API。方便用户态程序对BPF程序进行操作。

      ```
      在src/.output/nginxprobe；
      [root@master ebpf.probe]# ll src/.output/nginxprobe/
      total 132
      -rw-r--r--. 1 root root 18624 Oct 25 10:20 nginx_probe.bpf.o
      -rw-r--r--. 1 root root 59988 Oct 25 10:20 nginx_probe.skel.h
      ```

3. 开发用户态程序；

   探针用户态程序的目的是从BPF程序中获取观测数据。

   ```sh
   [root@localhost ebpf.probe]# ll src/nginxprobe/
   total 32K
   -rw-r--r-- 1 root root 3.7K Nov 27 09:23 nginx_1.12.1.h
   -rw-r--r-- 1 root root 1.2K Nov 27 09:23 nginx_link.meta
   -rw-r--r-- 1 root root 4.8K Nov 27 09:23 nginx_probe.bpf.c
   -rw-r--r-- 1 root root 5.0K Nov 27 09:23 nginx_probe.c // 用户程序
   -rw-r--r-- 1 root root  864 Nov 27 09:23 nginx_probe.h
   -rw-r--r-- 1 root root 2.1K Nov 27 09:23 readme.md
   ```

   - 用户态程序开发SDK

   ```
   #ifdef BPF_PROG_KERN
   #undef BPF_PROG_KERN
   #endif

   #ifdef BPF_PROG_USER
   #undef BPF_PROG_USER
   #endif

   #include "bpf.h"  // SDK头文件

   #include "XX.skel.h"  // xx探针

   #define LOAD(probe_name) // 加载XX探针的BPF程序
   #define UNLOAD(probe_name) // 卸载XX探针的BPF程序
   #define GET_MAP_OBJ(map_name) //根据MAP名称GET MAP对象
   #define GET_MAP_FD(map_name)  //根据MAP名称GET MAP ID
   #define GET_PROG_FD(prog_name) //根据程序名称（观测点）GET PROG ID


   #define UBPF_ATTACH(probe_name,proc_name,func_name,error)
   #define UBPF_RET_ATTACH(probe_name,proc_name,func_name,error)
   例如：
       UBPF_ATTACH(nginx_probe, nginx, ngx_stream_proxy_init_upstream,ret);
       UBPF_RET_ATTACH(nginx_probe, nginx, ngx_stream_proxy_init_upstream,ret);
       UBPF_ATTACH(nginx_probe, nginx, ngx_http_upstream_handler,ret2);
   ```

4. 探针框架集成探针采集数据方法

   对于需要探针框架集成输出观测指标的探针，要在探针目录下增加meta元模型，定义探针输出的观测指标模型，具体方法参考[如何开发探针](../../../../doc/how_to_add_probe.md)；