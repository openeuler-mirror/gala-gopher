import org.junit.Test;
import java.io.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class JvmProbeTest {

    @Test
    public void testArgsParse() {
        // Setup
        String strings = "-t 10";
       	// Run the test
        JvmProbe.ArgsParse(strings.split(" "));
        // Verify the results
        assertEquals(10, JvmProbe.time);
        System.out.println("testArgsParse passed");
    }

    @Test
    public void testProbe() {
        // Setup
        final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outContent));
        try {
            JvmProbe.agentPath = JvmProbe.getTemporaryRes(JvmProbe.agent);
        } catch (IOException e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }
    	// Run the test
        JvmProbe.probe();
        JvmProbe.executorService.shutdown();
        // Verify the results
        assertNotNull(JvmProbe.virtualMachineDescriptors);
        System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out)));
        System.out.println("testProbe passed");
    }

    @Test
    public void testGetTemporaryRes() {
        //SetUp
        String result = null;
        // Run the test
        try {
            result = JvmProbe.getTemporaryRes(JvmProbe.agent);
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
        // Verify the results
        assertNotNull(result);
        System.out.println("testGetTemporaryRes passed");
    }
}
