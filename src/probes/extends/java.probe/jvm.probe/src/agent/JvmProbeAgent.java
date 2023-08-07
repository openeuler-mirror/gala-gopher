package agent;

import java.util.List;
import java.io.IOException;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.lang.management.ManagementFactory;
import com.sun.management.OperatingSystemMXBean;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadMXBean;
import java.lang.management.ClassLoadingMXBean;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.lang.management.MemoryPoolMXBean;
import java.lang.management.BufferPoolMXBean;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;


/**
 * If you decide to update this agent during the jvm process running mode,
 * the modification wouldn't work since the jvm has attached original jar package.
 * (Reason: https://gitee.com/openeuler/gala-gopher/issues/I7KUN6?from=project-issue#note_19870876_link)
 * 
 * Note: If you update jar, please also update Manifest-Version;
 */
public class JvmProbeAgent {

    private static final int MSEC_PER_SEC = 1000;
    private static final int NSEC_PER_SEC = 1000000000;
    private static final String METRIC_FILE_NAME = "jvm-metrics.txt";
    private static String pid;
    private static String mainClassName = null;
    private static String metricTmpPath;
    private static String metricTmpFile;

    private static void createTmpFile() throws IOException {
        File tmpDirectory = new File(metricTmpPath);
        if (!tmpDirectory.exists()) {
            tmpDirectory.mkdir();
        }

        File tmpFile = new File(tmpDirectory, METRIC_FILE_NAME);
        if (!tmpFile.exists()) {
            tmpFile.createNewFile();
        }

        metricTmpFile = String.format("%s/%s", metricTmpPath, METRIC_FILE_NAME);
    }

    private static void writeMetricRecords(String record) {
        try {
            FileWriter fw = new FileWriter(metricTmpFile, true);
            BufferedWriter bw = new BufferedWriter(fw);
            bw.write(record);
            bw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void getMainClass() {
        if (mainClassName != null) {
            return;
        }

        RuntimeMXBean runtimeBean = ManagementFactory.getRuntimeMXBean();
        String wholeCmdLine = runtimeBean.getSystemProperties().get("sun.java.command");
        if (wholeCmdLine == null) {
            mainClassName = "Unknown";
            return;
        }
        mainClassName = wholeCmdLine;

        int firstSpace = wholeCmdLine.indexOf(' ');
        if (firstSpace > 0) {
            mainClassName = wholeCmdLine.substring(0, firstSpace);
            return;
        }
    }

    private static void getJmxInfo() throws IOException {
        RuntimeMXBean runtimeBean = ManagementFactory.getRuntimeMXBean();
        OperatingSystemMXBean osBean = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
        ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();
        ClassLoadingMXBean clBean = ManagementFactory.getClassLoadingMXBean();
        MemoryMXBean memoryBean = ManagementFactory.getMemoryMXBean();
        MemoryUsage heapUsage = memoryBean.getHeapMemoryUsage();
        MemoryUsage nonHeapUsage = memoryBean.getNonHeapMemoryUsage();
        List<MemoryPoolMXBean> memPoolBeans = ManagementFactory.getMemoryPoolMXBeans();
        List<BufferPoolMXBean> bufPoolBeans = ManagementFactory.getPlatformMXBeans(BufferPoolMXBean.class);
        List<GarbageCollectorMXBean> garbageCollectors = ManagementFactory.getGarbageCollectorMXBeans();

        infoCollector(runtimeBean);
        processCollector(runtimeBean, osBean);
        classCollector(clBean);
        threadCollector(threadBean);
        memoryAreaCollector(heapUsage, "heap");
        memoryAreaCollector(nonHeapUsage, "nonheap");
        memoryPoolCollector(memPoolBeans);
        bufferPoolCollector(bufPoolBeans);
        gcCollector(garbageCollectors);
    }

    private static void infoCollector(RuntimeMXBean runtimeBean) {
        String jvmName = runtimeBean.getVmName();
        String jvmVersion = runtimeBean.getVmVersion();   // or getSpecVersion();
        String jvmVender = runtimeBean.getVmVendor();

        writeMetricRecords(String.format("|jvm_info|%s|%s|%s|%s|%s|%d|\n", pid, mainClassName, jvmName, jvmVender, jvmVersion, 1));
    }

    private static void processCollector(RuntimeMXBean runtimeBean, OperatingSystemMXBean osBean) {
        long processStartTime = runtimeBean.getStartTime(); // ms
        try {
            Long processCpuTime = callLongGetter(osBean.getClass().getMethod("getProcessCpuTime"), osBean); // ns
            writeMetricRecords(String.format("|jvm_proc|%s|%s|%f|%f|\n",
                pid, mainClassName, ((double)processStartTime / MSEC_PER_SEC), ((double)processCpuTime / NSEC_PER_SEC)));
        } catch (Exception e) {
            //System.out.println("error");
        }
    }

    private static Long callLongGetter(Method method, Object obj) throws InvocationTargetException {
        try {
            return (Long) method.invoke(obj);
        } catch (IllegalAccessException e) {
            // Expected, the declaring class or interface might not be public.
        }

        for (Class<?> clazz : method.getDeclaringClass().getInterfaces()) {
            try {
                Method interfaceMethod = clazz.getMethod(method.getName(), method.getParameterTypes());
                Long result = callLongGetter(interfaceMethod, obj);
                if (result != null) {
                    return result;
                }
            } catch (NoSuchMethodException e) {
                // Expected, class might implement multiple, unrelated interfaces.
            }
        }
        return null;
    }

    // thread
    private static void threadCollector(ThreadMXBean threadBean) {
        int currentThreadCnt = threadBean.getThreadCount();
        int daemonThreadCnt = threadBean.getDaemonThreadCount();
        int peakThreadCnt = threadBean.getPeakThreadCount();
        long startThreadCnt = threadBean.getTotalStartedThreadCount();
        long cycleThreadDeadlocked = 0;
        long[] deadlocks = threadBean.findDeadlockedThreads();
        if (deadlocks != null && deadlocks.length > 0) {
            cycleThreadDeadlocked = deadlocks.length;
        }
        writeMetricRecords(String.format("|jvm_thread|%s|%s|%d|%d|%d|%d|%d|\n",
            pid, mainClassName, currentThreadCnt, daemonThreadCnt, peakThreadCnt, startThreadCnt, cycleThreadDeadlocked));
    }

    private static void classCollector(ClassLoadingMXBean clBean) {
        int currentClassCnt = clBean.getLoadedClassCount();
        long totalClassCnt = clBean.getTotalLoadedClassCount();
        writeMetricRecords(String.format("|jvm_class|%s|%s|%d|%d|\n", pid, mainClassName, currentClassCnt, totalClassCnt));
    }

    // memory
    private static void memoryAreaCollector(MemoryUsage memUsage, String area) {
        long memUsed = memUsage.getUsed();
        long memCommitted = memUsage.getCommitted();
        long memMax = memUsage.getMax();
        long memInit = memUsage.getInit();
        writeMetricRecords(String.format("|jvm_mem|%s|%s|%s|%d|%d|%d|%d|\n",
            pid, mainClassName, area, memUsed, memCommitted, memMax, memInit));
    }

    // memory_pool
    private static void memoryPoolCollector(List<MemoryPoolMXBean> poolBeans) {
        for (final MemoryPoolMXBean pool : poolBeans) {
            MemoryUsage poolUsage = pool.getUsage();
            if (poolUsage != null) {
                writeMetricRecords(String.format("|jvm_mem_pool|%s|%s|%s|%d|%d|%d|",
                    pid, mainClassName, pool.getName(), poolUsage.getUsed(), poolUsage.getCommitted(), poolUsage.getMax()));
            }
            MemoryUsage colPoolUsage = pool.getCollectionUsage();
            if (colPoolUsage != null) {
                writeMetricRecords(String.format("%d|%d|%d|",
                    colPoolUsage.getUsed(), colPoolUsage.getCommitted(), colPoolUsage.getMax()));
            } else {
                writeMetricRecords(String.format("-1|-1|-1|"));
            }
            writeMetricRecords(String.format("\n"));
        }
    }

    // buffer_pool
    private static void bufferPoolCollector(List<BufferPoolMXBean> bufferPools) {
        for (BufferPoolMXBean pool : bufferPools) {
            writeMetricRecords(String.format("|jvm_buf_pool|%s|%s|%s|%d|%d|%d|\n",
                pid, mainClassName, pool.getName(), pool.getMemoryUsed(), pool.getCount(), pool.getTotalCapacity()));
        }
    }

    // gc
    private static void gcCollector(List<GarbageCollectorMXBean> garbageCollectors) {
        for (GarbageCollectorMXBean gc : garbageCollectors) {
            writeMetricRecords(String.format("|jvm_gc|%s|%s|%s|%d|%f|\n",
                pid, mainClassName, gc.getName(), gc.getCollectionCount(), ((double)gc.getCollectionTime() / MSEC_PER_SEC)));
        }
    }


    public static void agentmain(String agentArgs) {
        String[] argStr = agentArgs.split("[,]");
        pid = argStr[0];
        metricTmpPath = argStr[1];
        try {
            createTmpFile();
            getMainClass();
            getJmxInfo();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }
}
