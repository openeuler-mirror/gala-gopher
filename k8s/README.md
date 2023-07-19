# k8s环境gala-gopher daemonset部署指导

## 环境准备

准备一套k8s集群环境，集群内操作系统的架构与版本建议保持一致，且只支持如下版本：openEuler 20.03 LTS SP1、openEuler 22.03 LTS、openEuler 22.03 LTS SP1、Kylin V10 x86。

## 定制daemonset yaml文件

将[daemonset模板文件](./daemonset.yaml.tmpl)下载到本地，重命名为gala-gopher_daemonset.yaml，按如下步骤对该文件进行修改。

### 修改namespace

按照实际情况修改gala-gopher_daemonset.yaml文件如下行中的{{NAMESPACE}}来定义gala-gopher所在的namespace，例如default。

```
namespace: {{NAMESPACE}}
```

### 修改容器镜像地址

按照集群内操作系统的架构与版本修改gala-gopher_daemonset.yaml文件如下行中的{{ARCH}}与{{TAG}}：

```
image: hub.oepkgs.net/a-ops/gala-gopher-{{ARCH}}:{{TAG}}
```

{{ARCH}}支持配置：aarch64 ，x86_64

{{TAG}}支持配置：20.03-lts-sp1，22.03-lts，22.03-lts-sp1，kylin-v10

### 修改容器环境变量

yaml文件中env条目下的环境变量用于控制gala-gopher运行时的各类配置，按如下说明进行修改：

| 变量名                  | 变量作用                                                     | 配置值说明                                                   |
| ----------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| GOPHER_HOST_PATH        | 容器外根目录"/"映射到gala-gopher容器内的目录，以便gala-gopher能够正常访问宿主机上的关键文件（例如内核debug文件、glibc动态库、httpd等二进制可执行文件）进行数据采集。 | 保持默认值，不建议修改                                       |
| GOPHER_EVENT_CHANNEL    | gala-gopher亚健康巡检异常事件输出方式                        | kafka：通过kafka上报（默认）<br/>logs：输出至本地日志        |
| GOPHER_META_CHANNEL     | gala-gopher观测对象元数据metadata输出方式                    | kafka：通过kafka上报（默认）<br/>logs：输出至本地日志        |
| GOPHER_KAKFA_SERVER     | gala-gopher上报亚健康巡检异常事件、观测对象元数据metadata的kafka服务端IP地址 | GOPHER_EVENT_CHANNEL和GOPHER_META_CHANNEL都设为logs时可设置为空，否则需要设置为有效的kafka服务端IP地址，例如1.2.3.4 |
| GOPHER_METRIC_PORT      | gala-gopher作为prometheus exporter输出指标数据的监听端口     | 配置有效且未被其他程序占用的端口号，默认为8888               |
| GOPHER_REST_PORT        | 动态配置RESTful API端口号                                    | 配置有效且未被其他程序占用的端口号，默认为9999               |
| GOPHER_REST_AUTH        | 控制动态配置RESTful接口是否开启https以及证书鉴权             | no：不开启（默认）<br/>yes：开启                             |
| GOPHER_REST_PRIVATE_KEY | 动态配置RESTful API开启https的私钥文件路径                   | GOPHER_REST_AUTH为yes时必配，路径为绝对路径                  |
| GOPHER_REST_CERT        | 动态配置RESTful API开启https的证书文件路径                   | GOPHER_REST_AUTH为yes时必配，路径为绝对路径                  |
| GOPHER_REST_CAFILE      | 动态配置RESTful API开启鉴权的CA证书文件路径                  | GOPHER_REST_AUTH为yes时必配，路径为绝对路径                  |
| GOPHER_PROBES_INIT      | 控制gala-gopher启动后默认开启的探针以及其配置（采集子项、监控对象、参数） | 每个探针单独一行，每行内容为[采集特性名] [动态配置json]，特性名和json格式参照[动态配置接口说明](../config/gala-gopher支持动态配置接口设计_v0.3.md)<br/>无需默认开启探针时配置为空 |

### 修改其他daemonset配置项（可选）

gala-gopher_daemonset.yaml文件默认会在当前集群的所有node（包括master）分支部署gala-gopher的pod，可通过按需修改文件中如下的如下内容来更改该行为：

    spec:
      nodeName:       # 控制在某个节点上创建pod     
      tolerations:    # 定义污点和容忍度规则
      - key: node-role.kubernetes.io/master
        effect: NoSchedule


## 开始部署

在k8s 集群master节点执行如下命令即可开始部署：

```
kubectl apply -f gala-gopher_daemonset.yaml
```

## 检查部署结果

部署过程中可以通过如下命令实时查看gala-gopher pod的状态

```
# 查看所有gala-gopher pods的状态
kubectl get pods -L gala-gopher

# 查看某个gala-gopher pod的部署详情
kubectl describe pod gala-gopher-xxxxx
```

当查询出的pod STATUS为Running，表示部署成功。



