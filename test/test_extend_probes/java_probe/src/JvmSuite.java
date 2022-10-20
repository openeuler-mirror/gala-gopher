import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.junit.runner.RunWith;
import org.junit.runner.notification.Failure;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({VmTest.class,JvmProbeTest.class})
public class JvmSuite {
	public static void main(String[] args) {

        Result result = JUnitCore.runClasses(JvmSuite.class);
        for (Failure failure : result.getFailures()) {
            System.out.println(failure.toString());
        }
        if (result.wasSuccessful()) {
            System.out.println(" All tests finished successfully ");
        }
    }
}
