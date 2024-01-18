import java.io.File;
import jdk.jfr.Recording;
import java.nio.file.Path;
import java.time.Duration;

public class JstackProbeAgent {
    private static boolean OncpuEnable = false;
    private static boolean OffcpuEnable = false;
    private static boolean MemEnable = false;
    private static boolean IoEnable = false;
    private static int SamplePeriodMs = 10; // ms
    private static String DataDir;
    private static Path JfrPath;
    private static final String CPU_EVENT_JAVA_SAMPLE = "jdk.ExecutionSample";
    private static final String CPU_EVENT_NATIVE_SAMPLE = "jdk.NativeMethodSample";
    private static final String OFFCPU_EVENT_JAVA_MON_WAIT = "jdk.JavaMonitorWait";
    private static final String OFFCPU_EVENT_THREAD_PARK = "jdk.ThreadPark";
    private static final String MEM_EVENT_IN_TLAB = "jdk.ObjectAllocationInNewTLAB";
    private static final String MEM_EVENT_OUT_TLAB = "jdk.ObjectAllocationOutsideTLAB";

    private static int initFiles() throws Exception {
        File dataDir = new File(DataDir);
        if (!dataDir.exists()) {
            dataDir.mkdir();
        }

        String JfrFileStr = String.format("%s/recording.jfr", DataDir);
        File jfrFile = new File(JfrFileStr);
        if (!jfrFile.exists()) {
            jfrFile.createNewFile();
        }

        JfrPath = jfrFile.toPath();
        if (JfrPath == null) {
            System.out.println("[JstackProbe] get Jfr Path failed.");
            return -1;
        }
        return 0;
    }

    private static void startRecording() {
        Recording recording = new Recording();
        try {
            // event ref: jdk\src\share\classes\jdk\jfr\conf\default.jfc or jdk.test.lib.jfr.EventNames
            if (OncpuEnable) {
                recording.enable(CPU_EVENT_JAVA_SAMPLE).withPeriod(Duration.ofMillis(SamplePeriodMs));
                recording.enable(CPU_EVENT_NATIVE_SAMPLE).withPeriod(Duration.ofMillis(SamplePeriodMs));
            }
            if (OffcpuEnable) {
                recording.enable(OFFCPU_EVENT_JAVA_MON_WAIT).withPeriod(Duration.ofMillis(SamplePeriodMs));
                recording.enable(OFFCPU_EVENT_THREAD_PARK).withPeriod(Duration.ofMillis(SamplePeriodMs));
            }
            if (MemEnable) {
                recording.enable(MEM_EVENT_IN_TLAB);
                recording.enable(MEM_EVENT_OUT_TLAB);
            }

            recording.setDestination(JfrPath);
            recording.setDuration(Duration.ofSeconds(20));
            recording.scheduleStart(Duration.ofSeconds(2));

            recording.start();
        } catch (Exception e) {
            e.printStackTrace();
            recording.stop();
        }
    }

    private static int setArgs(String Args) {
        if (Args == null) {
            System.out.println("[JstackProbe] Agent agentmain input agentArgs is null.");
            return -1;
        }

        String[] args = Args.split("[,]");
        if (args.length < 4) {
            System.out.println("[JstackProbeAgent] please add args: Pid, DataPath, EventType, SamplePeriod.");
            return -1;
        }
        try {
            DataDir = args[1];
            if (args[2].contains("oncpu")) {
                OncpuEnable = true;
            }
            if (args[2].contains("offcpu")) {
                OffcpuEnable = true;
            }
            if (args[2].contains("mem")) {
                MemEnable = true;
            }
            if (args[2].contains("io")) {
                IoEnable = true;
            }
            SamplePeriodMs = Integer.parseInt(args[3]);
        } catch (IllegalArgumentException e) {
            System.out.println("[JstackProbeAgent] parse args failed.");
            return -1;
        }
        return 0;
    }

    public static void agentmain(String agentArgs) {
        if (setArgs(agentArgs) != 0) {
            return;
        }

        try {
            if (initFiles() != 0) {
                return;
            }
            startRecording(); // +150~300% cpu 0.4s=>5~0% cpu 0.2s
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
