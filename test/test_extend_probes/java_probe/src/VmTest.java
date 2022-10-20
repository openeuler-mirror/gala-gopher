import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.VirtualMachineDescriptor;
import org.junit.Before;
import org.junit.Test;
import java.io.*;
import java.lang.management.BufferPoolMXBean;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.util.List;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertEquals;

public class VmTest {

    private VirtualMachineDescriptor virtualMachineDescriptor;
    private Vm vm;
    private RuntimeMXBean runtimeMXBean;
    private List<GarbageCollectorMXBean> garbageCollectorMXBeans;
    private com.sun.management.OperatingSystemMXBean operatingSystemMXBean;
    private List<BufferPoolMXBean> pools;

    @Before
    public void setUp() throws Exception {
        //SetUp
        List<VirtualMachineDescriptor> virtualMachineDescriptors = VirtualMachine.list();
        virtualMachineDescriptor = virtualMachineDescriptors.get(0);
        try {
             JvmProbe.agentPath = JvmProbe.getTemporaryRes(JvmProbe.agent);
        } catch (IOException e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }
        vm = new Vm(virtualMachineDescriptor,JvmProbe.agentPath);
        runtimeMXBean = ManagementFactory.newPlatformMXBeanProxy(
                vm.mBeanServerConnection, ManagementFactory.RUNTIME_MXBEAN_NAME, RuntimeMXBean.class);
        garbageCollectorMXBeans = ManagementFactory.getPlatformMXBeans( vm.mBeanServerConnection,GarbageCollectorMXBean.class);
        operatingSystemMXBean = ManagementFactory.newPlatformMXBeanProxy(vm.mBeanServerConnection,
                ManagementFactory.OPERATING_SYSTEM_MXBEAN_NAME, com.sun.management.OperatingSystemMXBean.class);
        pools = ManagementFactory.getPlatformMXBeans(vm.mBeanServerConnection,BufferPoolMXBean.class);
    }

    @Test
    public void testGetData() {
        // Setup
        String id = "connector";
        final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outContent));
        // Run the test
        vm.getData();
        // Verify the results
        assertThat(outContent.toString(), containsString("jvm"));
        System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out)));
        try {
            id = vm.connector.getConnectionId();
        }
        catch (IOException e){
            id = "close";
        }
        assertEquals("close",id);
        System.out.println("testGetData passed");
    }
}
