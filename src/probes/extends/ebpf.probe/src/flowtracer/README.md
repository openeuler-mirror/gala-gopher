To mount cgroup2 in OpenEuler:
 1. Create a mount point: `sudo mkdir /mnt/cgroup2`.
 2. Mount cgroup2 to the mount point: `mount -t cgroup2 none /mnt/cgroup2/`.

### To enable FlowTracer

FlowTracer can be controlled via gopher-ctl:
 1. Enable FlowTracer: `gopher-ctl probe set flowtracer  '{"state":"running"}'`.
 2. Enable FlowTracer data mapping in tcp probe: `gopher-ctl probe set tcp '{"cmd": {"probe": ["tcp_stats"]},"snoopers":{"proc_name":[{"comm":"^python.*","cmdline":""}]},"params":{"report_period": 5,"cluster_ip_backend": 2},"state":"running"}'`. Note that this command enables only 1 of TCP probes for processes that name start with python.

### To disable FlowTracer

FlowTracer can be controlled via gopher-ctl:
 1. Stop FlowTracer: `gopher-ctl probe set flowtracer  '{"state":"stopped"}'`.
 2. Disable FlowTracer data mapping in tcp probe: `gopher-ctl probe set tcp '{"cmd": {"probe": ["tcp_stats"]},"snoopers":{"proc_name":[{"comm":"^python.*","cmdline":""}]},"params":{"report_period": 5,"cluster_ip_backend": 0},"state":"running"}'`.

### Example

There are 2 pods running on different nodes in Kubernetes cluster. Pod A is a client that sends HTTP request to a server running in Pod B. 
The example shows metric attributes that are collected by Gala-Gopher (common attributes are removed for brevity).

#### Metrics without FlowTracer

Client-side - the client connects to a virtual service IP:
```
gala_gopher_tcp_link_tx_bytes{role="client",client_ip="10.0.0.131",server_ip="10.247.204.240",server_port="8000",pod="app/a-664d757c7b-q6ds2"} 110 1704451439000
```
Server-side - the server receives packets from a translated address (host gateway):
```
gala_gopher_tcp_link_rx_bytes{role="server",client_ip="192.168.3.14",server_ip="10.0.0.5",server_port="8000",pod="app/b-6758f884b4-7mgbm"} 110 1704451440000
```

#### Metrics with FlowTracer

Client-side - the virtual service IP is resolved to the address of the server:
```
gala_gopher_tcp_link_tx_bytes{role="client",client_ip="10.0.0.131",server_ip="10.0.0.5",server_port="8000",pod="app/a-664d757c7b-q6ds2"} 110 1704451981000
```
Server-side - the real client address is visible too:
```
gala_gopher_tcp_link_rx_bytes{role="server",client_ip="10.0.0.131",server_ip="10.0.0.5",server_port="8000",pod="app/b-6758f884b4-7mgbm"} 110 1704451982000
```