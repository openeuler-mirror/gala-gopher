如何开发探针
============
## 1. native探针

### 1.1 探针参考

```
example.probe
```

### 1.2 探针技术规范
#### 1.2.1 定义探针的main函数
探针main函数要以`int main()`形式，不支持使用`int main(int argc, char *argv[])`作为main函数<br>
参考:
```c
int main()
{
    example_collect_data();
    return 0;
}
```
#### 1.2.2 定义探针的meta文件

```conf
version = "1.0.0"                # meta文件版本

measurements:                    # 探针数据表list，可以在一个探针中配置多张数据表
(
    {                            #--> 探针数据表
        table_name: "example",   #--> 数据表名称（唯一）
        entity_name: "example",  #--> 观测对象名称
                                 #--> 一个观测对象可以配置多张数据表，每张表的观测对象名称一致
        fields:                  #--> 数据字段
        (
            "cpu_usage",         #--> 数据字段名称，属于同一个观测对象的指标名必须唯一
            "memory_usage",
            "tcp_connection_num",
        )
    }
)
```

#### 1.2.3 输出探针指标
探针采集的数据要以通过`fprintf`打印的方式<br>
打印的第一个字符串是数据表名称<table_name><br>
而后的每个字符串和数据字段一一对应<br>
每个字段数据按照 `|` 分隔 <br>
如这里和example表中的数据对应：<br>
`cpu_usage:high`<br>
`memory_usage:low`<br>
`tcp_connection_num:15`<br>

```c
void example_collect_data()
{
    fprintf(stdout, "|%s|%s|%s|%s|\n",
        "example",
        "high",
        "low",
        "15"
    );
}
```

按照上面的方式开发好探针后，就可以被框架自动集成了：）

## 2. extends探针

gala-gopher支持灵活扩展三方探针，并不限制探针语言类型；扩展三方探针有几点需要配套；

### 2.1 满足探针输出格式

输出格式要求同1.2.3，即观测数据按格式要求输出到标准输出流；

注：为满足该条要求，探针程序可能需要做少量适配；

### 2.2 定义meta文件

要求同1.2.2；

### 2.3 定义探针目录

通常三方探针建议按语言分目录归档；对于同一种语言的探针，可归档到统一目录下；以python语言的探针为例，在extends目录下新建`python.probe`目录；

```shell
python.probe
├── install.sh					-- 按需定义build.sh/install.sh
└── redis.probe					-- 每个探针定义一个单独的目录
    ├── redis_probe.meta		 -- 探针meta文件
    └── redis_probe.py			 -- 探针程序
```

### 2.4 定义build.sh

如果探针涉及编译，需要定义build.sh（必须是该名称脚本，探针框架编译时会强匹配脚本名），如果不需要可以不定义（如shell探针）；

build.sh负责该类型探针的编译过程；

build.sh参数：

| 参数    | 含义                | 必选 | 使用场景                                                     |
| ------- | ------------------- | ---- | ------------------------------------------------------------ |
| package | 是否为rpm包编译模式 | N    | 若指定该参数，表示当前为rpm编译流程，三方探针程序可跳过依赖软件包的安装过程；若支持该参数，则依赖软件包需要在gala-gopher的spec中显示定义require依赖； |

### 2.5 定义install.sh

安装编译出的探针程序；

install.sh参数：

| 参数     | 含义         | 必选 | 使用场景                                                     |
| -------- | ------------ | ---- | ------------------------------------------------------------ |
| 安装路径 | 指定安装路径 | N    | gala-gopher集成编译时会指定，install.sh中需处理该参数，将程序安装到指定目录下，否则按install.sh默认安装路径安装； |

### 2.6 支持探针编译裁剪

参考[如何实现探针编译裁剪](how_to_tail_probe.md)

### 其他

对于eBPF探针，考虑到方便探针程序开发，集成了一个轻量的eBPF开发框架，详细了解请点击[进入](../src/probes/extends/ebpf.probe/README.md)。

