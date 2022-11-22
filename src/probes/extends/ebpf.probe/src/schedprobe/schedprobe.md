# 功能介绍：

scheprobe存在2个功能：

#功能1：用于观测进程较长时间处于系统态，以及相应的进程信息、调用栈信息。

#功能2：进程系统调用时被其他高优先级任务抢占，导致系统调用时长超过阈值，上报相应的时延、调用栈信息。

# 使用方法：

./schedprobe -P [1/2/3]  // 开启#功能1，#功能2，#功能1&#功能2

./schedprobe -T [] // 设定调度时延门限。

./schedprobe -F [] // 设定观测的进程名，不设置则观测所有进程；也可以设置成task，则观测范围取决于白名单范围。

# 原理介绍：

## #功能1

1. account_process_tick观测点抓取resched.pid并记录进resched_pid_map，并记录resched时间戳。
2. （option）sched_switch观测点抓取resched.pid被调度出去的事件，如果调度时延（now - resched时间戳）超出门限，上报异常事件，删除resched.pid，流程结束。
3. （option）resched.pid未被调度，再次进入account_process_tick观测点，如果调度时延（now - resched时间戳）超出门限，上报异常事件。

执行过程可能组合：1->[3*] -> 2



## #功能2

1. syscall 记录进程发起系统调用时间。
2. sched_switch 记录进程被切换出去的时间。（option）
3. sysexit 记录进程退出系统调用时间。
4. 上报整个过程的时间点。
