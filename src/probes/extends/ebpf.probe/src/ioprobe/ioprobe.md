# 功能介绍：

IOProbe用于观测Block IO全栈能力，支持NVME、SCSI、VirtBlock三种类型。

# 使用方法：

./ioprobe // 缺省参数

./ioprobe -t [] // 设定上报周期。

./ioprobe -s [] // 设定采样周期。

./ioprobe -d [] // 设定目标设备名。

# 原理介绍：

针对Block处理过程四个阶段进行打点：IO启动、向设备驱动发起请求、向设备发起请求、设备应答、IO结束。

观测点介绍：

SCSI
block_getrq -> block_rq_issue -> scsi_dispatch_cmd_start -> scsi_dispatch_cmd_done -> block_rq_complete
START              ISSUE_DRIVER           ISSUE_DEVICE                      ISSUE_DEVICE_OK                                  END

virtblk
block_getrq -> virtio_queue_rq ->  block_rq_issue -> blk_mq_complete_request -> block_rq_complete
START           ISSUE_DRIVER              ISSUE_DEVICE         ISSUE_DEVICE_OK                                 END

nvme
block_getrq -> nvme_setup_cmd -> block_rq_issue -> blk_mq_complete_request -> block_rq_complete
START           ISSUE_DRIVER                 ISSUE_DEVICE        ISSUE_DEVICE_OK                                     END

注意：

1. IO trace过程基于request对象跟踪，基于block对象统计分段时延。
2. 因为基于request对象跟踪，block_getrq(TP)观测点不易获取request，忽略该观测点，改用‘request->start_time_ns’代替
3. virtblk场景中，virtio_queue_rq 由于没有存在的合适观测点，放弃观测。即该场景 ISSUE_DRIVER、ISSUE_DEVICE使用相同时间戳。
4. 分段统计分别为：I/O整体时间（END - START），驱动处理时间（ISSUE_DEVICE - START）、设备处理时间（ISSUE_DEVICE_OK -  ISSUE_DEVICE）

