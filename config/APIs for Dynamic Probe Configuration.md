# APIs for Dynamic Probe Configuration

gala-gopher supports dynamic probe configuration in either of the following ways:

1.  Using the RESTful API. This method can be used only when the value of **rest_api_on** in the **global** section of the gala-gopher configuration file is **true**.

2.  Using the command line tool gopher-ctl. This method is supported by default.

For details about how to use the command line tool for dynamic probe configuration, see [Dynamically Configuring Probes Using the Command Line Tool](#dynamically-configuring-probes-using-the-command-line-tool). The following describes how to dynamically configure probes using the RESTful API.

After gala-gopher is started, it provides a RESTful API for configuration. The URL format is **http://\[*API listening IP address*\]:\[*API listening port*\]/\[*Collection feature*\]**. In the URL:

-   ***API listening IP address***: Set it in **bind_addr** in the **rest_server** section of the gala-gopher configuration file. By default, all-zero port listening is used. Therefore, you can use any IP address of the node where gala-gopher is located (**localhost** is used as an example in the following sections).

-   ***API listening port***: Set it in **port** in the **rest_server** part of the gala-gopher configuration file. The default value is **9999**.

-   ***Collection feature***: corresponds to a collection probe. For example, **tcp** corresponds to the TCP probe, and **flamegraph** corresponds to the stack probe.

RESTful APIs receive only PUT and GET requests initiated by you, which correspond to the following functions:

-   Queries probe configurations: GET request

-   Dynamically configures probe attributes, observation scope, parameters, and running status (without restarting gala-gopher): PUT request. The request body format is as follows:

<!-- -->

-   json='
        {
            "cmd": {
                "probe": []
            },
            "snoopers": {
                "proc_id": [],
                "proc_name": [{}],
                "pod_id": [],
                "container_id": [],
                "container_name": [],
                "custom_labels": {}
            },
            "params": {},
            "state": "running"
        }'

    1.  The **cmd** field is used to [configure basic probe attributes](#configuring-basic-probe-attributes), including probe collection subitems.

    2.  The **snoopers** field is used to [configure the observation scope](#configuring-the-probe-observation-scope) from five dimensions: process ID, process name, Pod ID, container ID, and container name. In addition, it supports [extended label matching](#configuring-extended-labels-for-probes).

    3.  The **params** field is used to [configure probe running parameters](#configuring-probe-running-parameters).

    4.  The **state** field is used to configure the probe running status, that is, to [start or stop the probe](#starting-or-stopping-a-probe).

## Probe Configuration APIs

### Configuring Basic Probe Attributes

The basic attributes of a probe include the probe file path and collection subitems. The following is an example API for setting the flame graph and enabling the oncpu and offcpu collection features:

    curl -X PUT http://localhost:9999/flamegraph -d json='
    {
        "cmd": {
            "probe": [
             "oncpu",
             "offcpu"
            ]
        }
    }'

-   **bin**: absolute path of the executable file of the probe. It is optional. If it is not specified, the default probe installation path is automatically selected.

-   **probe**: sub-functions (collection subitems) enabled during probe running.

The full set of collection features supported by all probes is described as follows:

| **Collection Feature** | **Description**                                              | **Collection Subitems**                                      | **Monitored Objects**                    | **Startup File**                                 | **Start Condition**       |
| ---------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ | ---------------------------------------- | ------------------------------------------------ | ------------------------- |
| flamegraph             | On-line performance flame graph observation capability       | oncpu, offcpu, mem                                           | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/stackprobe        |                           |
| l7                     | Application layer (layer 7) protocol observation capability  | l7_bytes_metrics, l7_rpc_metrics, l7_rpc_trace               | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/l7probe           |                           |
| tcp                    | TCP exception and status observation capability              | tcp_abnormal, tcp_rtt, tcp_windows, tcp_rate, tcp_srtt, tcp_sockbuf, tcp_stats,tcp_delay | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/tcpprobe          |                           |
| socket                 | Socket (TCP/UDP) exception observation capability            | tcp_socket, udp_socket                                       | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/endpoint          |                           |
| io                     | Block layer I/O observation capability                       | io_trace, io_err, io_count, page_cache                       | N/A                                      | /opt/gala-gopher/extend_probes/ioprobe           |                           |
| proc                   | Process system call, I/O, DNS, VFS, and ioctl observation capabilities | proc_syscall, proc_fs, proc_io, proc_dns, proc_pagecache, proc_net, proc_offcpu, proc_ioctl | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/taskprobe         |                           |
| jvm                    | JVM layer GC, thread, memory, and cache observation capabilities | N/A                                                          | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/jvmprobe          |                           |
| ksli                   | Redis performance SLI (access latency) observation capability | N/A                                                          | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/ksliprobe         |                           |
| postgre_sli            | PostgreSQL database performance SLI (access latency) observation capability | N/A                                                          | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/pgsliprobe        |                           |
| opengauss_sli          | openGauss access throughput observation capability           | N/A                                                          | \[ip, port, dbname, user,password\]      | /opt/gala-gopher/extend_probes/pg_stat_probe.py  |                           |
| dnsmasq                | DNS session observation capability                           | N/A                                                          | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/rabbitmq_probe.sh |                           |
| lvs                    | LVS session observation capability                           | N/A                                                          | N/A                                      | /opt/gala-gopher/extend_probes/trace_lvs         | lsmod\|grep ip_vs\| wc -l |
| nginx                  | Nginx layer 4/layer 7 session observation capability         | N/A                                                          | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/nginx_probe       |                           |
| haproxy                | HAProxy layer 4/layer 7 session observation capability       | N/A                                                          | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/trace_haproxy     |                           |
| kafka                  | Kafka producer/consumer topic observation capability         | N/A                                                          | N/A                                      | /opt/gala-gopher/extend_probes/kafkaprobe        |                           |
| baseinfo               | Basic system information                                     | cpu, mem, nic, disk, net, fs, proc, host, con                | proc_id, proc_name, pod_id, container_id | system_infos                                     | N/A                       |
| virt                   | Virtualization management information                        | N/A                                                          | N/A                                      | virtualized_infos                                | N/A                       |
| tprofiling             | Thread-level performance profiling observation capability    | oncpu, syscall_file, syscall_net, syscall_lock, syscall_sched | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/tprofiling        | N/A                       |
| Container              | Container information                                        | N/A                                                          | proc_id, proc_name, container_id         | /opt/gala-gopher/extend_probes/cadvisor_probe.py | N/A                       |
| sermant                | Java application layer 7 protocol observation capability. Currently, the dubbo protocol is supported. | l7_bytes_metrics, l7_rpc_metrics                             | proc_id, proc_name, pod_id, container_id | /opt/gala-gopher/extend_probes/sermant_probe.py  |                           |

The collection subitems supported by each probe are described as follows:

<table>
<colgroup>
<col style="width: 15%" />
<col style="width: 24%" />
<col style="width: 24%" />
<col style="width: 36%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Collection Feature</strong></th>
<th><strong>Description</strong></th>
<th><strong>Collection Subitems</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>flamegraph</td>
<td>On-line performance flame graph observation capability</td>
<td>oncpu, offcpu, mem</td>
<td><p><strong>oncpu</strong>: collects the status of application threads running on the CPU, helping identify how threads consume CPU resources and pinpoint time-consuming function calls.</p>
<p><strong>offcpu</strong>: collects the status of application threads that are not running on the CPU, helping analyze operations (such as waiting for I/O or locks) that cause threads to enter the <strong>offcpu</strong> state.</p>
<p><strong>mem</strong>: collects the memory allocation stack of application threads within the queried time period to determine memory usage.</p></td>
</tr>
<tr class="even">
<td>l7</td>
<td>Application layer (layer 7) protocol observation capability</td>
<td>l7_bytes_metrics, l7_rpc_metrics, l7_rpc_trace</td>
<td><p><strong>l7_bytes_metrics</strong>: collects the number of data bytes and data packets received and sent by application threads.</p>
<p><strong>l7_rpc_metrics</strong>: collects various metrics such as the number of requests received, number of responses sent, request throughput, response throughput, average latency, total latency, and error rate for application threads.</p>
<p><strong>l7_rpc_trace</strong>: not supported currently.</p></td>
</tr>
<tr class="odd">
<td>TCP</td>
<td>TCP exception and status observation capability</td>
<td>tcp_abnormal, tcp_rtt, tcp_windows, tcp_rate, tcp_srtt, tcp_sockbuf, tcp_stats,tcp_delay</td>
<td><p><strong>tcp_abnormal</strong>: TCP exception information</p>
<p><strong>tcp_rtt</strong>: TCP connection data transmission round-trip time</p>
<p><strong>tcp_windows</strong>: TCP window information</p>
<p><strong>tcp_rate</strong>: TCP transmission rate</p>
<p><strong>tcp_srtt</strong>: TCP connection Smoothed Round Trip Time (SRTT)</p>
<p><strong>tcp_sockbuf</strong>: size of the buffer for receiving and sending data</p>
<p><strong>tcp_stats</strong>: TCP connection status</p>
<p><strong>tcp_delay</strong>: TCP transmission delay</p></td>
</tr>
<tr class="even">
<td>socket</td>
<td>Socket (TCP/UDP) exception observation capability</td>
<td>tcp_socket, udp_socket</td>
<td><p><strong>tcp_socket</strong>: TCP socket information</p>
<p><strong>udp_socket</strong>: UDP socket information</p></td>
</tr>
<tr class="odd">
<td>io</td>
<td>Block layer I/O observation capability</td>
<td>io_trace, io_err, io_count, page_cache</td>
<td><p><strong>io_trace</strong>: number of I/O requests</p>
<p><strong>io_err</strong>: I/O error information</p>
<p><strong>io_count</strong>: number of read and write bytes of I/O operations</p>
<p><strong>page_cache</strong>: I/O cache information</p></td>
</tr>
<tr class="even">
<td>proc</td>
<td>Process system call, I/O, DNS, and VFS observation capabilities</td>
<td>proc_syscall, proc_fs, proc_io, proc_dns,proc_pagecache, proc_net, proc_offcpu, proc_ioctl</td>
<td><p><strong>proc_syscall</strong>: process system call information</p>
<p><strong>proc_fs</strong>: process file system information</p>
<p><strong>proc_io</strong>: process I/O information</p>
<p><strong>proc_dns</strong>: DNS access monitoring</p>
<p><strong>proc_pagecache</strong>: process memory page information</p>
<p><strong>proc_net</strong>: statistics on the duration for a process to send and receive network packets</p>
<p><strong>proc_offcpu</strong>: statistics on the process IO_wait and offcpu duration</p>
<p><strong>proc_ioctl</strong>: statistics on the process ioctl size and duration</p></td>
</tr>
<tr class="odd">
<td>jvm</td>
<td>JVM layer GC, thread, memory, and cache observation capabilities</td>
<td>N/A</td>
<td>N/A</td>
</tr>
<tr class="even">
<td>ksli</td>
<td>Redis performance SLI (access latency) observation capability</td>
<td>N/A</td>
<td>N/A</td>
</tr>
<tr class="odd">
<td>postgre_sli</td>
<td>PostgreSQL database performance SLI (access latency) observation capability</td>
<td>N/A</td>
<td>N/A</td>
</tr>
<tr class="even">
<td>opengauss_sli</td>
<td>openGauss access throughput observation capability</td>
<td>N/A</td>
<td>N/A</td>
</tr>
<tr class="odd">
<td>dnsmasq</td>
<td>DNS session observation capability</td>
<td>N/A</td>
<td>N/A</td>
</tr>
<tr class="even">
<td>LVS</td>
<td>LVS session observation capability</td>
<td>N/A</td>
<td>N/A</td>
</tr>
<tr class="odd">
<td>Nginx</td>
<td>Nginx layer 4/layer 7 session observation capability</td>
<td>N/A</td>
<td>N/A</td>
</tr>
<tr class="even">
<td>HAProxy</td>
<td>HAProxy layer 4/layer 7 session observation capability</td>
<td>N/A</td>
<td>N/A</td>
</tr>
<tr class="odd">
<td>Kafka</td>
<td>Kafka producer/consumer topic observation capability</td>
<td>N/A</td>
<td>N/A</td>
</tr>
<tr class="even">
<td>baseinfo</td>
<td>Basic system information</td>
<td>cpu, mem, nic, disk, net, fs, proc, host, con</td>
<td><p><strong>cpu</strong>: CPU performance</p>
<p><strong>mem</strong>: memory performance</p>
<p><strong>nic</strong>: NIC performance</p>
<p><strong>disk</strong>: disk performance</p>
<p><strong>net</strong>: protocol stack statistics</p>
<p><strong>fs</strong>: file system information</p>
<p><strong>proc</strong>: process information</p>
<p><strong>host</strong>: host information</p>
<p><strong>con</strong>: container information</p></td>
</tr>
<tr class="odd">
<td>virt</td>
<td>Virtualization management information</td>
<td>N/A</td>
<td>N/A</td>
</tr>
<tr class="even">
<td>tprofiling</td>
<td>Thread-level performance profiling observation capability</td>
<td>oncpu, syscall_file, syscall_net, syscall_lock, syscall_sched</td>
<td><p><strong>oncpu</strong>: status of application threads running on the CPU, helping identify how threads consume CPU resources and pinpoint time-consuming function calls.</p>
<p><strong>syscall_file</strong>: information about the file system called by the system</p>
<p><strong>syscall_net</strong>: performance of the network called by the system.</p>
<p><strong>syscall_lock</strong>: number of system call deadlocks</p>
<p><strong>syscall_sched</strong>: number of system calls</p></td>
</tr>
<tr class="odd">
<td>Container</td>
<td>Container information</td>
<td>N/A</td>
<td>N/A</td>
</tr>
</tbody>
</table>


### Configuring the Probe Observation Scope

Take the flame graph probe as an example. The command for configuring the observation scope is as follows:

    curl -X PUT http://localhost:9999/flamegraph -d json='
    {
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
            ],
            "pod_id": [
                "pod1",
                "pod2"
            ],
            "container_id": [
                "container1",
                "container2"
            ],
            "container_name": [
                "container_name1"
            ]
        }
    }'

-   **proc_id**: process ID. You can run the **ps -ef** command to query the process ID.

-   **proc_name**: An object in **proc_name** contains **comm**, **cmdline**, and **debugging_dir**. If the process ID of the object is **101**, the **comm** value of the process is the content of the **/proc/101/comm** file, and the **cmdline** value is the content of the **/proc/101/cmdline** file. **debugging_dir** indicates the debug directory reserved for the probe (related functions are not available currently).

-   **pod_id**: A pod is the minimum deployable compute unit that can be created and managed in Kubernetes. You can run **kubectl run** to create a pod and obtain the pod name, and then run **kubectl get pods -n \<namespace\> \<pod-name\> -o jsonpath='{.metadata.uid}'** to obtain the pod ID.

-   **container_id**: You can run the **docker run** command to run a Docker container and run the **docker ps** command to view the container ID.

-   **container_name**: You can run the **docker run** command to run a container and run the **docker ps** command to view the container name.

### Configuring Extended Labels for Probes

When reporting metric data, a probe reports the corresponding label information based on the meta file. In addition, you can add some extended label information through the dynamic configuration API for reporting. Currently, the following extended labels are supported:

-   Fixed labels

- A fixed label has a fixed value. You can add `custom_labels` to `snoopers` to configure the label. The label is populated when the probe reports metric data.

  For example, add a `task="task1"` label to the proc probe as follows:

      curl -X PUT http://localhost:9999/proc -d json='
      {
          "snoopers": {
              "custom_labels": {
               "task": "task1"
              }
          }
      }'



-   Pod labels

- A pod label is a key-value pair attached by Kubernetes to a pod object. A pod object generally contains multiple pod labels. You can add **pod_labels** to **snoopers** to specify the pod labels to be reported.

  For example, the following configuration specifies the pod labels to be reported for the proc probe, including **app** and **test**. If the configured pod label does not exist, the default value **not found** is used.

      curl -X PUT http://localhost:9999/proc -d json='
      {
          "snoopers": {
              "pod_labels": ["app", "test"]
          }
      }'

  Note: The flame graph probe does not report label information based on the meta file. Therefore, configuring extended labels for probes does not apply to the flame graph probe.

### Configuring Probe Running Parameters

Some parameters can be set during probe startup or runtime. These parameters control the probe's behavior. To specify the sampling and reporting periods of the probe, you can set **sample_period** and **report_period** for the TCP probe.

    curl -X PUT http://localhost:9999/tcp -d json='
    {
        "params": {
            "report_period": 60,
            "sample_period": 200,
        }
    }'

The detailed running parameters are as follows:

| **Parameter**       | **Description**                                              | **Default Value & Range**                                    | **Unit** | **Supported Collection Features**           | **Supported or Not** |
| ------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ | -------- | ------------------------------------------- | -------------------- |
| sample_period       | Sampling period                                              | 5000, \[100\~10000\]                                         | ms       | io, tcp                                     | Y                    |
| report_period       | Report period                                                | 60, \[5\~600\]                                               | s        | ALL                                         | Y                    |
| latency_thr         | Latency report threshold                                     | 0, \[10\~100000\]                                            | ms       | tcp, io, proc, ksli                         | Y                    |
| offline_thr         | Process offline report threshold                             | 0, \[10\~100000\]                                            | ms       | proc                                        | Y                    |
| drops_thr           | Packet loss report threshold                                 | 0, \[10\~100000\]                                            | package  | tcp, nic                                    | Y                    |
| res_lower_thr       | Lower resource threshold                                     | 0, \[0\~100\]                                                | percent  | ALL                                         | Y                    |
| res_upper_thr       | Upper resource threshold                                     | 0, \[0\~100\]                                                | percent  | ALL                                         | Y                    |
| report_event        | Exception event report                                       | 0, \[0, 1\]                                                  |          | ALL                                         | Y                    |
| metrics_type        | Telemetry metric report                                      | "raw", \["raw", "telemetry"\]                                |          | ALL                                         | N                    |
| env                 | Environment type                                             | "node", \["node", "container", "kubenet"\]                   |          | ALL                                         | N                    |
| l7_protocol         | Layer 7 protocol scope                                       | "",\["http", "pgsql", "redis","mysql", "kafka", "mongo", "dns"\] |          | l7                                          | Y                    |
| support_ssl         | SSL observation support                                      | 0, \[0, 1\]                                                  |          | l7                                          | Y                    |
| multi_instance      | Independent flame graph for each process                     | 0, \[0, 1\]                                                  |          | flamegraph                                  | Y                    |
| native_stack        | Local language stack display (for Java processes)            | 0, \[0, 1\]                                                  |          | flamegraph                                  | Y                    |
| cluster_ip_backend  | Cluster IP backend conversion                                | 0, \[0, 1\]                                                  |          | tcp, l7                                     | Y                    |
| pyroscope_server    | IP address of the flame graph UI server                      | "localhost:4040"                                             |          | flamegraph                                  | Y                    |
| svg_period          | Flame graph SVG file generation period                       | 180, \[30, 600\]                                             | s        | flamegraph                                  | Y                    |
| perf_sample_period  | Stack information collection period for **oncpu** flame graphs | 10, \[10, 1000\]                                             | ms       | flamegraph                                  | Y                    |
| output_dir          | Directory for storing output files                           |                               ""                             |         |                 flamegraph, tprofiling      |     Y      |
| flame_dir           | Directory for storing original stack information of flame graphs | "/var/log/gala-gopher/flamegraph"                            |          | flamegraph                                  | Y                    |
| dev_name            | Name of the NIC or disk device to be observed                | ""                                                           |          | io, kafka, ksli, postgre_sli, baseinfo, tcp | Y                    |
| continuous_sampling | Whether to perform continuous sampling                       | 0, \[0, 1\]                                                  |          | ksli                                        | Y                    |
| elf_path            | Path of the executable file to be observed                   | ""                                                           |          | baseinfo, nginx, haproxy, dnsmasq           | Y                    |
| kafka_port          | Kafka port number to be observed                             | 9092, \[1, 65535\]                                           |          | kafka                                       | Y                    |
| cadvisor_port       | cAdvisor port to be started                                  | 8083, \[1, 65535\]                                           |          | container                                   | Y                    |

Note: Probe parameters take effect only for probes within the supported monitoring scope. For example, if the **sample_period** parameter's supported monitoring scope is **io** and **tcp**, then it can only be configured in **io** and **tcp** probes. Conversely, if the **report_period** parameter's supported monitoring scope is **ALL**, it can be configured in all probes supported by gala-gopher.

### Starting or Stopping a Probe

If the value of **state** is **running**, the probe is started. If the value of **state** is **stopped**, the probe is stopped. To start a probe, the request parameter must contain **"state": "running"**. Otherwise, the probe cannot be started. To stop a probe, the request parameter must contain **"state": "stopped"**. Otherwise, the probe cannot be stopped.

    curl -X PUT http://localhost:9999/flamegraph -d json='
    {
        "state": "running"
    }'

### API Restrictions and Precautions

1.  The API is stateless. The settings uploaded each time are the final running results of the probe, including the status, parameters, and monitoring scope.

2.  The monitored objects can be combined randomly, and the monitoring scope is the combination.

3.  The startup file must be authentic and valid.

4.  You can enable some or all subitems of a collection feature as required. However, you can only disable all subitems of a collection feature at once.

5.  The monitored object of openGauss is the database instance (**ip**/**port**/**dbname**/**user**/**password**).

6.  The API can receive a maximum of 2048 bytes of data each time.

## Probe Configuration Query APIs

Use the GET method to obtain information about the flame graph probe. The request command is as follows:

    curl -X GET http://localhost:9999/flamegraph

The response to the GET request is as follows. **state** indicates the probe running status, **running** indicates that the probe is running, and other information is the probe configuration information.

    curl -X GET http://localhost:9999/flamegraph
    {
        "cmd": {
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

## Probe Configuration Examples

### Configuring the Flame Graph Probe

Full set of flame graph probe configurations:

    curl -X PUT http://localhost:9999/flamegraph -d json='
    {
        "cmd": {
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
            "multi_instance": 1,
            "native_stack": 1,
            "pyroscope_server": "localhost:4040",
            "svg_period": 180,
            "perf_sample_period": 10,
            "output_dir": "/var/log/gala-gopher/stacktrace",
            "flame_dir": "/var/log/gala-gopher/flamegraph"
        },
        "state":"running"
    }'

Many parameters can be configured in the PUT request for starting the flame graph probe. These parameters control the behavior of the flame graph probe. The following analyzes the important components in the request from top to bottom:

1.  Run the curl command to initiate a PUT request.

2.  The request URL is **http://localhost:9999/flamegraph**. **9999** is the listening port number used by the REST server to process the probe startup request. **flamegraph** is the probe name.

3.  The probe in the command corresponds to the collection subitem of the probe. The content of the flame graph probe is **oncpu**, **offcpu**, and **mem**, indicating that the flame graph probe can collect data of the oncpu, offcpu, and mem types.

4.  The object monitored by the probe in **snoopers** has four dimensions: **proc_id**, **proc_name**, **pod_id**, and **container_id**, which indicate the process ID, process name, pod ID, and container ID, respectively. Any dimension can be used to specify the object to be monitored. After the monitored object is specified, the information about the monitored object to be collected is specified by the probe content in **cmd** and the content in **params**.

5.  Parameters in **params** and the parameters in the example are all supported by the flame graph probe.

> **multi_instance** controls whether each process outputs the flame graph independently. If the value is **1**, each process independently outputs the flame graph.
>
> **native_stack** specifies whether to display the local language stack (for Java processes). The value **1** indicates that the local language stack of the Java process is displayed.
>
> **pyroscope_server** specifies the address of the flame graph UI server. The value **localhost:4040** indicates that the address of the flame graph UI server is **localhost:4040**.
>
> **svg_period** controls the interval for generating the SVG file of the flame graph. The value **180** indicates that the SVG file of the flame graph is generated every 180 seconds.
>
> **perf_sample_period** controls the interval for collecting stack information of the oncpu flame graph. The value **10** indicates that the oncpu flame graph stack information is collected every 10 ms.
>
> **output_dir** controls the storage directory of the SVG file of the flame graph. The value **/var/log/gala-gopher/stacktrace** indicates the SVG file of the flame graph is stored in the **/var/log/gala-gopher/stacktrace** directory.
>
> **flame_dir** controls the directory for storing the original stack information of the flame graph. The value **/var/log/gala-gopher/flamegraph** indicates the original stack information of the flame graph is stored in the **/var/log/gala-gopher/flamegraph** directory.
>
> Note: Do not configure parameters that are not supported by the flame graph probe. Ensure that the parameters that are not supported by the flame graph probe are ignored. Otherwise, the probe collection result may be affected.

6.  The **state** parameter specifies the probe status. To start a probe, set the **state** parameter to **running**. To stop a probe, set the **state** parameter to **stopped**.

### Configuring the Application Layer 7 Protocol Probe

    curl -X PUT http://localhost:9999/l7 -d json=' 
    { 
        "cmd": { 
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
            "report_period": 60, 
            "l7_protocol": [ 
                "http", 
                "pgsql" 
            ], 
            "support_ssl": 1, 
        }, 
        "state":"running" 
    }' 

Many parameters can be configured in the PUT request for starting the layer 7 probe. These parameters control the behavior of the layer 7 probe. The following analyzes the important components in the request from top to bottom.

1.  Run the curl command to initiate a PUT request.

2.  The request URL is **http://localhost:9999/l7**. **9999** is the listening port number used by the REST server to process the request for starting the probe. **l7** is the probe name.

3.  **probe** in **cmd** corresponds to the collection subitem of the probe. The content of the layer 7 probe includes **l7_bytes_metrics**, **l7_rpc_metrics**, and **l7_rpc_trace**, indicating that the flame graph probe can collect data of the **l7_bytes_metrics**, **l7_rpc_metrics**, and **l7_rpc_trace types**. For details about the meaning of each data type, see the detailed description of collection subitems in this document.

4.  The object monitored by the probe in **snoopers** has four dimensions: **proc_id**, **proc_name**, **pod_id**, and **container_id**, which indicate the process ID, process name, pod ID, and container ID, respectively. Any dimension can be used to specify the object to be monitored. After the object to be monitored is specified, the object information to be collected is specified by the probe content in **cmd** and the content in **params**.

5.  Parameters in **params** and the parameters in the example are all supported by the layer 7 probe.

> **report_period** controls the period for reporting collected data. The value **60** indicates that the collected data is reported every 60 seconds.
>
> **l7_protocol** specifies the protocol used by the layer 7 probe to collect data. In the example, the layer 7 probe collects data through HTTP and PostgreSQL.
>
> **support_ssl** specifies whether the SSL encryption protocol is supported. The value **1** indicates that the SSL encryption protocol is supported.
>
> **clusterip_backend** controls the cluster IP backend conversion. The value **1** indicates that the cluster IP backend is converted.

6.  The **state** parameter specifies the probe status. To start a probe, set the **state** parameter to **running**. To stop a probe, set the **state** parameter to **stopped**.

### Configuring the TCP Exception and Status Observation Probe

Full set of configurations for the TCP exceptions and status observation probe:

    curl -X PUT http://localhost:9999/tcp -d json='
    {
        "cmd": {
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
            "proc_id": [],
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
            "sample_period": 200,
            "report_period": 60,
            "latency_thr": 60,
            "drops_thr": 10,
            "res_lower_thr": 20,
            "res_upper_thr": 40,
            "report_event": 1,
            "cluster_ip_backend": 1,
        },
        "state":"running"
    }'

Many parameters can be configured in the PUT request for starting the TCP probe. These parameters control the behavior of the TCP probe. The following analyzes the important components in the request from top to bottom.

1.  Run the curl command to initiate a PUT request.

2.  The request URL is **http://localhost:9999/tcp**. **9999** is the listening port number used by the REST server to process the request for starting the probe. **tcp** is the probe name.

3.  **probe** in **cmd** corresponds to the collection subitem of the probe. The content of the TCP probe includes **tcp_abnormal**, **tcp_rtt**, **tcp_windows**, **tcp_rate**, **tcp_srtt**, **tcp_sockbuf**, **tcp_stats**, and **tcp_delay**, indicating that the TCP probe can collect data of the **tcp_abnormal**, **tcp_rtt**, **tcp_windows**, **tcp_rate**, **tcp_srtt**, **tcp_sockbuf**, **tcp_stats**, and **tcp_delay** types.

> For details about the meaning of each data type, see the detailed description of collection subitems in this document.

4.  The object monitored by the probe in **snoopers** has four dimensions: **proc_id**, **proc_name**, **pod_id**, and **container_id**, which indicate the process ID, process name, pod ID, and container ID, respectively. Any dimension can be used to specify the object to be monitored. After the object to be monitored is specified, the object information to be collected is specified by the probe content in **cmd** and the content in **params**.

5.  Parameters in **params** and the parameters in the example are all supported by the TCP probe.

> **sample_period** controls the data collection period of the probe. The value **200** indicates that data is collected every 200 ms.
>
> **report_period** controls the data reporting period. The value **60** indicates that the collected data is reported every 60 seconds.
>
> **latency_thr** controls the latency reporting threshold. The value **60** indicates that the data is reported only when the delay exceeds 60 ms.
>
> **drops_thr** controls the packet loss reporting threshold. The value **10** indicates that packets are discarded only when the number of lost packets is greater than 10.
>
> **res_lower_thr** controls the lower limit of the resource percentage.
>
> **res_upper_thr** controls the upper limit of the resource percentage.
>
> **report_event** controls whether the probe reports abnormal events. The value **1** indicates an abnormal event is reported.
>
> **metrics_type** controls the type of metrics reported to Telemetry.
>
> **env** controls the working environment type. The value **node** indicates that gala-gopher works on the working node.
>
> **report_source_port** specifies whether to report the source port. The value **1** indicates that the source port is reported.
>
> **cluster_ip_backend** specifies whether to perform cluster IP backend conversion. The value **1** indicates that the cluster IP backend is converted.
>
> **dev_name** controls the device name of the NIC or disk to be observed. The values **io** and **kafka** indicate that the device names of the devices to be observed are **io** and **kafka**.

6.  The **state** parameter specifies the probe status. To start a probe, set the **state** parameter to **running**. To stop a probe, set the **state** parameter to **stopped**.

## Dynamically Configuring Probes Using the Command Line Tool

gala-gopher supports dynamic probe configuration using the command line tool gopher-ctl.

The syntax of gopher-ctl is as follows:

    gopher-ctl probe get <probe_name>
    gopher-ctl probe set <probe_name> <probe_config>

Operation description:

-   `get`: gets the dynamic configuration information of a probe.

-   `set`: sets the dynamic configuration information of a probe.

Parameter description:

-   `<probe_name>`: specifies the probe name. For details about the value range, see [Probe Configuration APIs](#Xb4363d9f2ae6532043fd7e8f05b859869c54913).

-   `<probe_config>`: specifies probe configuration information in JSON format. The content is the same as that of the RESTful API. For details, see [Probe Configuration APIs](#Xb4363d9f2ae6532043fd7e8f05b859869c54913).