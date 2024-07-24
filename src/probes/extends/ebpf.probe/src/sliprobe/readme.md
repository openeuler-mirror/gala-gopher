# SLI探针开发说明

## 功能描述
基于 ebpf 采集并周期性上报容器粒度的 SLI 指标。支持的功能有：
- 采集周期内CPU调度事件的时延总计和统计直方图，关注的事件包括：调度等待，主动睡眠，锁/IO引起的阻塞，调度延迟，长系统调用等

- 采集周期内Memory分配事件的时延总计和统计直方图，关注的事件包括：内存回收，换页，内存规整等

- 采集周期内BIO层IO操作的时延总计和统计直方图

## 代码逻辑
#### 总体思路

1. 用户态接收待观测的容器列表，将容器的cpuacct子系统目录inode记录在ebpf map中，共享给内核态。

2. 通过ebpf kprobe/tracepoint跟踪相关内核事件，判断当前进程是否属于待观测范围，记录事件类型，时间戳等信息。每隔一定周期将同一cgroup内进程的SLI指标进行聚合上报。
3. 用户态接收并打印内核态上报的SLI指标信息。

#### SLI指标计算方式

##### CPU SLI

1. **cpu_wait**

​	在sched_stat_wait观测点，获取第二个参数delay的值

2. **cpu_sleep**

​	在sched_stat_sleep观测点，获取第二个参数delay的值

3. **cpu_iowait**

​	在sched_stat_blocked观测点，判断当前进程in_iowait，则获取第二个参数delay的值

4. **cpu_block**

​	在sched_stat_blocked观测点，判断当前进程非in_iowait，则获取第二个参数delay的值

5. **cpu_rundelay**

​	在sched_switch观测点，通过第三个参数next获取将被调度进程的run_delay值：next->sched_info.run_delay，记录在task_sched_map中。计算同一进程两次被调度时run_delay的差值

6. **cpu_longsys**

​	在sched_switch观测点，通过第三个参数next获取将被调度进程的task结构体，从task结构体中获取上下文切换次数（nvcsw+nivcsw）和用户态执行时间utime。如果同一进程两次被调度时的上下文切换次数和用户态执行时间都不变，则说明在该进程在执行一个较长的系统调用，累积该进程处在内核态的时间

##### MEM SLI

1. **mem_reclaim**

​	计算mem_cgroup_handle_over_high函数返回时间戳和进入时间戳的差值

​	计算mm_vmscan_memcg_reclaim_end观测点和mm_vmscan_memcg_reclaim_begin观测点时间戳的差值

2. **mem_swapin**

​	计算do_swap_page函数返回时间戳和进入时间戳的差值

3. **mem_compact**

​	计算try_to_compact_pages函数返回时间戳和进入时间戳的差值

##### IO SLI

1. **bio_latency**

​	计算进入bio_endio函数和触发block_bio_queue观测点的时间戳差值

​	计算进入bio_endio函数和退出generic_make_request_checks函数的时间戳差值