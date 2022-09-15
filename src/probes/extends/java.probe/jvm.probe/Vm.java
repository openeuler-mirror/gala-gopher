import com.sun.tools.attach.*;
import javax.management.MBeanServerConnection;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadMXBean;


public class Vm {

    private VirtualMachineDescriptor virtualMachineDescriptor;
    private MBeanServerConnection mBeanServerConnection;
    private JMXConnector connector;
    private String canonicalPath;

    final String jmxRemote = "com.sun.management.jmxremote";
    final String localConnectorAddress = "com.sun.management.jmxremote" + ".localConnectorAddress";

    public Vm(VirtualMachineDescriptor virtualMachineDescriptor,String canonicalPath) throws AgentLoadException, IOException, AttachNotSupportedException, AgentInitializationException {
        this.virtualMachineDescriptor = virtualMachineDescriptor;
        this.canonicalPath = canonicalPath;
        this.mBeanServerConnection = getTargetVmConnection(virtualMachineDescriptor.id());
    }

    public MBeanServerConnection getTargetVmConnection(String vmId) throws IOException, AttachNotSupportedException, AgentLoadException, AgentInitializationException {
        // attach
        VirtualMachine virtualMachine = VirtualMachine.attach(vmId);
        virtualMachine.loadAgent(canonicalPath, jmxRemote);
        String connectorAddress = (String) virtualMachine.getAgentProperties().get(localConnectorAddress);
        virtualMachine.detach();

        connector = JMXConnectorFactory.connect(new JMXServiceURL(connectorAddress));
        MBeanServerConnection mBeanServerConnection = connector.getMBeanServerConnection();
        return mBeanServerConnection;
    }

    public void getData() throws IOException {
        getInfo(this.mBeanServerConnection);
        connector.close();
    }

    public void getInfo(MBeanServerConnection connection) throws IOException {
        String jvmPid = virtualMachineDescriptor.id();
        String[] split = virtualMachineDescriptor.displayName().split(" ");
        String pkgNameMainClass = split[0];
        RuntimeMXBean runtimeMXBean = ManagementFactory.newPlatformMXBeanProxy(
                connection, ManagementFactory.RUNTIME_MXBEAN_NAME, RuntimeMXBean.class);
        String jvmVersion = runtimeMXBean.getSpecVersion();
        String jvmType = runtimeMXBean.getVmName();
        Long processStartTimeSeconds = runtimeMXBean.getStartTime();
        Long processCpuSecondsTotal = runtimeMXBean.getUptime();

        ThreadMXBean threadMXBean = ManagementFactory.newPlatformMXBeanProxy(
                connection, ManagementFactory.THREAD_MXBEAN_NAME, ThreadMXBean.class);
        int threadsCurrent = threadMXBean.getThreadCount();
        int threadsPeak = threadMXBean.getPeakThreadCount();
        int threadsDeadlocked = 0;
        if (threadMXBean.findDeadlockedThreads() != null) {
            threadsDeadlocked = threadMXBean.findDeadlockedThreads().length;
        }
        System.out.printf("|jvm|%s|%s|%s|%s|%d|%d|%d|%d|%d|\n", jvmPid,pkgNameMainClass, jvmVersion, jvmType
                , processStartTimeSeconds, processCpuSecondsTotal, threadsCurrent,threadsPeak, threadsDeadlocked);
    }
}
