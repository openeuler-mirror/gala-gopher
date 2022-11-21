# 如何生成gala-gopher容器镜像

本文档介绍了gala-gopher容器镜像的生成方法，介绍示例基于openEuler20.0-LTS-SP1版本。请参考如下步骤进行配置、生成、运行等。

### 创建容器镜像

1. ##### 准备制作镜像的文件

   1、选择合适的Dockerfile文件，在[build目录](../build)下归档了openEuler部分版本的Dockerfile文件，由于gala-gopher强依赖内核版本，请根据自己宿主机内核信息选择合适的Dockerfile文件。

   2、将gala-gopher-xxx.rpm包、libbpf-0.3-xxx.rpm 和libbpf-devel-0.3-xxx.rpm包下载保存到该目录。注：下载rpm包的时候要注意获取正确内核版本、CPU架构的rpm包。

   ```shell
   [root@localhost ~]# cat /etc/openEuler-release
   openEuler release 20.03 (LTS-SP1)
   [root@localhost ~]# uname -r
   4.19.90-2012.5.0.0053.oe1.x86_64
   [root@localhost build]# ll
   -rw-r--r--. 1 root root 1.9K Jun 27 21:59 Dockerfile_2003_sp1_x86_64
   -rw-r--r--. 1 root root 227K Jun 28 09:02 gala-gopher-v1.1.0-52.x86_64.rpm
   -rw-r--r--. 1 root root 102K Jun 27 21:19 libbpf-0.3-1.h0.oe1.x86_64.rpm
   -rw-r--r--. 1 root root  62K Jun 27 21:19 libbpf-devel-0.3-1.h0.oe1.x86_64.rpm
   ```

2. ##### 配置Dockerfile文件

   ```shell
   # 确认构建容器镜像依赖的基础镜像(默认不需要修改)
   # base image
   FROM openeuler/openeuler:20.03-lts-sp1
   
   # 内网用户需要配置代理
   # aops_agent configuration is needed for intranet users
   # ENV http_proxy=http://z00xxxxxx:xxx@proxy.huawei.com:8080
   # ENV https_proxy=http://z00xxxxxx:xxx@proxy.huawei.com:8080
   
   # 确认本地安装包包名，如下三个rpm包名必须是真实的包名
   # install library dependencies
   RUN yum update -y \
       && yum install -y libbpf-0.3-1.h0.oe1.x86_64.rpm \
       && yum install -y libbpf-devel-0.3-1.h0.oe1.x86_64.rpm \
       && yum install -y gala-gopher-v1.1.0-52.x86_64.rpm
       
   # 确认暴露端口(默认为8888)
   # expose port
   EXPOSE 8888
   ```

3. ##### 下载openEuler镜像源

   ```shell
   [root@localhost build]# docker image pull openeuler/openeule:20.03-lts-sp1
   [root@localhost build]# docker images
   REPOSITORY            TAG                 IMAGE ID            CREATED             SIZE
   openeuler/openeuler   20.03-lts-sp1       60402ce20dab        2 months ago        512MB
   ```

4. ##### 创建镜像

   ```shell
   [root@localhost build]# docker build -f Dockerfile_2003_sp1_x86_64 -t gala-gopher:0.0.1 .
   ```

   成功生成容器镜像

   ```shell
   [root@localhost build]# docker images
   REPOSITORY            TAG                 IMAGE ID            CREATED             SIZE
   gala-gopher           0.0.1               211913592b58        22 minutes ago      614MB
   ```

### 保存容器镜像

生成容器镜像后可以将镜像保存为tar文件，其他宿主机可以通过load命令导入容器镜像：

```shell
[root@localhost build]# docker save -o gala-gopher_sp1_v0.0.1.tar 211913592b58
```

```shell
[root@localhost build]# docker load gala-gopher_sp1_v0.0.1.tar
```
