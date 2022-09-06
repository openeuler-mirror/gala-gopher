import com.sun.tools.attach.*;
import javax.management.MBeanServerConnection;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;

import java.io.File;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadMXBean;


public class Vm {
    private VirtualMachineDescriptor virtualMachineDescriptor;
    private MBeanServerConnection mBeanServerConnection;
	
	final String existAgentPath2 = File.separator + "lib" + File.separator + "management-agent.jar";
        final String existAgentPath1 = File.separator + "jre" + existAgentPath2;
	final String jmxRemote = "com.sun.management.jmxremote";
	final String localConnectorAddress = "com.sun.management.jmxremote" + ".localConnectorAddress";
	
	public Vm(VirtualMachineDescriptor virtualMachineDescriptor) throws AgentLoadException, IOException, AttachNotSupportedException, AgentInitializationException {
        this.virtualMachineDescriptor = virtualMachineDescriptor;
        this.mBeanServerConnection = getTargetVmConnection(virtualMachineDescriptor.id());
    }

    public MBeanServerConnection getTargetVmConnection(String vmId) throws IOException, AttachNotSupportedException, AgentLoadException, AgentInitializationException {
        // attach
	   VirtualMachine virtualMachine = VirtualMachine.attach(vmId);
        
	   String javaHome = virtualMachine.getSystemProperties().getProperty("java.home");
	   String agentPath = javaHome + existAgentPath1;

	   File file = new File(agentPath);
        if (!file.exists()) {
            agentPath = javaHome + existAgentPath2;
            file = new File(agentPath);
            if (!file.exists())
                throw new IOException("[JVM Probe] management-agent.jar not found");
        }

        virtualMachine.loadAgent(file.getCanonicalPath(), jmxRemote);

        String connectorAddress = (String) virtualMachine.getAgentProperties().get(localConnectorAddress);
		virtualMachine.detach();
		return JMXConnectorFactory.connect(new JMXServiceURL(connectorAddress)).getMBeanServerConnection();
    }

    public void getData() throws IOException {
        getInfo(this.mBeanServerConnection);
    }

    private void getInfo(MBeanServerConnection connection) throws IOException {
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
        if(threadMXBean.findDeadlockedThreads()!=null){
            threadsDeadlocked = threadMXBean.findDeadlockedThreads().length;
        }
        System.out.printf("|jvm|%s|%s|%s|%s|%d|%d|%d|%d|%d|\n",jvmPid,pkgNameMainClass,jvmVersion,jvmType
                ,processStartTimeSeconds,processCpuSecondsTotal,threadsCurrent,threadsPeak,threadsDeadlocked);
    }
}
