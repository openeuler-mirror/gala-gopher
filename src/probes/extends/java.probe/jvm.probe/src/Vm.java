import com.sun.tools.attach.*;
import javax.management.MBeanServerConnection;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;
import java.io.IOException;
import java.lang.management.*;
import java.util.List;
import java.util.concurrent.TimeUnit;


public class Vm {
    public VirtualMachineDescriptor virtualMachineDescriptor;
    public MBeanServerConnection mBeanServerConnection;
    public JMXConnector connector;
    public final String canonicalPath;
    public StringBuilder res;

    final String localConnectorAddress = "com.sun.management.jmxremote.localConnectorAddress";

    public Vm(VirtualMachineDescriptor virtualMachineDescriptor,String canonicalPath) throws AgentLoadException, IOException, AttachNotSupportedException, AgentInitializationException {
        this.virtualMachineDescriptor = virtualMachineDescriptor;
        this.canonicalPath = canonicalPath;
        getTargetVmConnection(virtualMachineDescriptor.id());
        res = new StringBuilder();
    }

    private void getTargetVmConnection(String vmId) throws IOException, AttachNotSupportedException, AgentLoadException, AgentInitializationException {

        VirtualMachine virtualMachine = VirtualMachine.attach(vmId);
        virtualMachine.loadAgent(canonicalPath);

        String connectorAddress = (String) virtualMachine.getAgentProperties().get(localConnectorAddress);
        virtualMachine.detach();
        this.connector = JMXConnectorFactory.connect(new JMXServiceURL(connectorAddress));
        this.mBeanServerConnection = connector.getMBeanServerConnection();
    }

    public void getData() throws IOException, InterruptedException {
        try {
            getInfo(this.mBeanServerConnection);
        } catch (IOException e) {
            System.out.println(e.getMessage());
        } finally {
            try {
                connector.close();
            } catch (IOException e) {
                System.out.println(e.getMessage());
            }
        }
    }

    private void getInfo(MBeanServerConnection connection) throws IOException, InterruptedException {
        RuntimeMXBean runtimeMXBean = ManagementFactory.newPlatformMXBeanProxy(
                connection, ManagementFactory.RUNTIME_MXBEAN_NAME, RuntimeMXBean.class);
        com.sun.management.OperatingSystemMXBean operatingSystemMXBean = ManagementFactory.newPlatformMXBeanProxy(connection,
                ManagementFactory.OPERATING_SYSTEM_MXBEAN_NAME, com.sun.management.OperatingSystemMXBean.class);
        List<GarbageCollectorMXBean> garbageCollectorMXBeans = ManagementFactory.getPlatformMXBeans(
                connection,GarbageCollectorMXBean.class);
        ThreadMXBean threadMXBean = ManagementFactory.newPlatformMXBeanProxy(
                connection, ManagementFactory.THREAD_MXBEAN_NAME, ThreadMXBean.class);
        MemoryMXBean memoryMXBean = ManagementFactory.newPlatformMXBeanProxy(
                connection, ManagementFactory.MEMORY_MXBEAN_NAME, MemoryMXBean.class);
        List<BufferPoolMXBean> pools = ManagementFactory.getPlatformMXBeans(
                connection,BufferPoolMXBean.class);
        // tid % mainclass
        String jvmPid = virtualMachineDescriptor.id();
        String[] split = virtualMachineDescriptor.displayName().split(" ");
        String pkgNameMainClass = split[0];
        res.append(String.format("|jvm|%s|%s|", jvmPid, pkgNameMainClass));
        
        // vesion % type
        String jvmVersion = runtimeMXBean.getSpecVersion();
        String jvmType = runtimeMXBean.getVmName();
        res.append(String.format("%s|%s|", jvmVersion, jvmType));
        
        // gc
        double gcDetail = getGarbageCollectionUsage(runtimeMXBean, operatingSystemMXBean, garbageCollectorMXBeans);
        long gc_counts = getTotalGarbageCollectionCount(garbageCollectorMXBeans);
        long gc_time_ms = getTotalGarbageCollectionTime(garbageCollectorMXBeans);       
        res.append(String.format("%.2f|%d|%d|", gcDetail, gc_counts, gc_time_ms));
        // process & thread
        Long processStartTimeSeconds = runtimeMXBean.getStartTime();
        Long processCpuSecondsTotal = runtimeMXBean.getUptime();

        int threadsCurrent = threadMXBean.getThreadCount();
        int threadsPeak = threadMXBean.getPeakThreadCount();
        int threadsDeadlocked = 0;
        if(threadMXBean.findDeadlockedThreads() != null) {
            threadsDeadlocked = threadMXBean.findDeadlockedThreads().length;
        }

        res.append(String.format("%d|%d|%d|%d|%d|", processStartTimeSeconds, processCpuSecondsTotal, threadsCurrent, threadsPeak, threadsDeadlocked));
        
        // heap
        double heap_occupied = 100.0 * Double.valueOf(memoryMXBean.getHeapMemoryUsage().getCommitted()) / memoryMXBean.getHeapMemoryUsage().getMax();
        long heap_used = memoryMXBean.getHeapMemoryUsage().getUsed();
        res.append(String.format("%d|%.2f|", heap_used, heap_occupied));
        
        // noheap
        long noheap_used = memoryMXBean.getNonHeapMemoryUsage().getUsed();
        double noheap_occupied = memoryMXBean.getNonHeapMemoryUsage().getMax();
        if(noheap_occupied > 0) {
            noheap_occupied = 100.0 * Double.valueOf(memoryMXBean.getNonHeapMemoryUsage().getCommitted()) / noheap_occupied;
            res.append(String.format("%d|%.2f|", noheap_used, noheap_occupied));
        }
        else {
            res.append(String.format("%d|%.0f|", noheap_used,noheap_occupied));
        }
        // bufferpool
        long bf_capacity = getTotalBufferPoolsCapacity(pools);
        long bf_used = getTotalBufferPoolsUsed(pools);
        res.append(String.format("%d|%d|\n", bf_capacity, bf_used));		
        System.out.printf(res.toString());
    }

    private long getTotalGarbageCollectionCount(List<GarbageCollectorMXBean> garbageCollectorMXBeans) {
        long gc_count=0;
        for(GarbageCollectorMXBean gc :garbageCollectorMXBeans) {
            gc_count +=gc.getCollectionCount();
        }
        return gc_count;
    }

    private long getTotalGarbageCollectionTime(List<GarbageCollectorMXBean> gcmList) {
        long total_ms=0;
        for(GarbageCollectorMXBean gc :gcmList) {
            total_ms += gc.getCollectionTime();
        }
        return total_ms;
    }

    private double getGarbageCollectionUsage(RuntimeMXBean runtime, com.sun.management.OperatingSystemMXBean os, List<GarbageCollectorMXBean> gcmList) {
        // 上一个cpu运行记录时间点
        long prevUpTime = runtime.getUptime();
        // 当时cpu运行时间
        long upTime;
        // 上一次cpu运行总时间
        long prevProcessCpuTime =  os.getProcessCpuTime();
        // 当前cpu运行总时间
        long processCpuTime;
        // 上一次gc运行总时间
        long prevProcessGcTime = getTotalGarbageCollectionTime(gcmList);
        // 当前gc运行总时间
        long processGcTime;
        // 可用内核数量
        int processorCount =os.getAvailableProcessors();
        try {
            TimeUnit.SECONDS.sleep(1);
        } catch (InterruptedException e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }
        processCpuTime = os.getProcessCpuTime();
        processGcTime = getTotalGarbageCollectionTime(gcmList);
        upTime = runtime.getUptime();
        long upTimeDiff = upTime - prevUpTime;
        //processGcTimeDiff 取到得是纳秒数  1ms = 1000000ns
        //计算gccpu使用率
        long processGcTimeDiff = processGcTime - prevProcessGcTime;
        double gcDetail =  (processGcTimeDiff * 100.0 /1000000/ processorCount / upTimeDiff);
        return gcDetail;
    }

    private long getTotalBufferPoolsCapacity(List<BufferPoolMXBean> bufferpools) {
        long total_bytes = 0;
        for (BufferPoolMXBean bpool : bufferpools) {
            total_bytes += bpool.getTotalCapacity();
        }
        return total_bytes;
    }

    private long getTotalBufferPoolsUsed(List<BufferPoolMXBean> bufferpools) {
        long total_bytes = 0;
        for (BufferPoolMXBean bpool : bufferpools) {
            total_bytes += bpool.getMemoryUsed();
        }
        return total_bytes;
    }

}
    
