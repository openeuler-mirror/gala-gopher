import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.File;
import jdk.jfr.consumer.*;
import jdk.jfr.Recording;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

public class JstackProbeAgent {
    private static Recording recording = null;
    private static File jfrFile = null;
    private static Path jfrPath = null;

    private static final String CPU_EVENT_JAVA_SAMPLE = "jdk.ExecutionSample";
    private static final String CPU_EVENT_NATIVE_SAMPLE = "jdk.NativeMethodSample";
    private static final String OFFCPU_EVENT_JAVA_MON_WAIT = "jdk.JavaMonitorWait";
    private static final String OFFCPU_EVENT_THREAD_PARK = "jdk.ThreadPark";
    private static final String MEM_EVENT_IN_TLAB = "jdk.ObjectAllocationInNewTLAB";
    private static final String MEM_EVENT_OUT_TLAB = "jdk.ObjectAllocationOutsideTLAB";

    private static BufferedWriter oncpuStackWriter;
    private static BufferedWriter offcpuStackWriter;
    private static BufferedWriter memStackWriter;
    private static ArgsParse args;

    private static void clearFile(File f) throws IOException {
        if (f == null) {
            return;
        }

        FileWriter fw = new FileWriter(f);
        fw.write("");
        fw.flush();
        fw.close();
    }

    private static BufferedWriter getBuffWriter(String fileName) throws IOException {
        if (fileName != null) {
            File stacksFile = new File(fileName);
            if (!stacksFile.exists()) {
                stacksFile.createNewFile();
            } else {
                clearFile(stacksFile);
            }

            FileWriter fw = new FileWriter(stacksFile);
            return new BufferedWriter(fw);
        }
        return null;
    }

    private static void initFiles() throws IOException {
        File dataDir = new File(args.getArgDataDir());
        if (!dataDir.exists()) {
            dataDir.mkdir();
        }

        jfrFile = new File(args.getArgJfrFile());

        oncpuStackWriter = getBuffWriter(args.getArgOncpuStacksFile());
        offcpuStackWriter = getBuffWriter(args.getArgOffcpuStacksFile());
        memStackWriter = getBuffWriter(args.getArgMemStacksFile());
    }

    private static void closeStackWriters() throws IOException {
        if (oncpuStackWriter != null) {
            oncpuStackWriter.flush();
            oncpuStackWriter.close();
        }
        if (offcpuStackWriter != null) {
            offcpuStackWriter.flush();
            offcpuStackWriter.close();
        }
        if (memStackWriter != null) {
            memStackWriter.flush();
            memStackWriter.close();
        }
    }

    private static void walkFrames(RecordedStackTrace rst, RecordedEvent event) throws IOException {
        String eventType = event.getEventType().getName();
        BufferedWriter bw;

        if (eventType.equals(CPU_EVENT_JAVA_SAMPLE) || eventType.equals(CPU_EVENT_NATIVE_SAMPLE)) {
            bw = oncpuStackWriter;
        } else if (eventType.equals(OFFCPU_EVENT_JAVA_MON_WAIT) || eventType.equals(OFFCPU_EVENT_THREAD_PARK)) {
            bw = offcpuStackWriter;
        } else {
            bw = memStackWriter;
        }

        if (bw == null) {
            return;
        }

        boolean first = true;
        List<RecordedFrame> frames = rst.getFrames();
        for (int i = frames.size() - 1; i >= 0; i--) {
            if (!first) {
                bw.write("; ");
            }
            RecordedFrame rf = frames.get(i);
            bw.write(rf.getMethod().getType().getName() + "." );
            bw.write(rf.getMethod().getName());
            first = false;
        }

        if (!first) {
            if (bw == memStackWriter) {
                bw.write(" " + event.getLong("allocationSize") + "\n");
            } else {
                bw.write(" 1\n");
            }
        }
    }

    private static int readJfrFile() throws Exception {
        if (!jfrFile.exists()) {
            jfrFile.createNewFile();
            jfrPath = jfrFile.toPath();
            return -1;
        }

        jfrPath = jfrFile.toPath();
        if (jfrPath == null) {
            closeStackWriters();
            return -1;
        }

        if (jfrFile.length() == 0) {
            Thread.sleep(1000);
            if (jfrFile.length() == 0) {
                closeStackWriters();
                return -1;
            }
        }

        return 0;
    }

    private static void walkEvents() throws Exception {
        int ret = readJfrFile();
        if (ret != 0) {
            return;
        }

        String eventThread;
        RecordingFile recordingFile = new RecordingFile(jfrPath);
        while (recordingFile.hasMoreEvents()) {
            RecordedEvent event = recordingFile.readEvent();
            if (event == null) {
                continue;
            }

            RecordedThread thread = event.getThread();
            if (thread == null) {
                 if (event.hasField("sampledThread")) {
                     RecordedThread sampledThread = event.getValue("sampledThread");
                     eventThread = sampledThread.getOSName();
                 } else {
                     continue;
                 }
            } else {
                eventThread = thread.getOSName();
            }

            if (eventThread.equals("Attach Listener") || eventThread.equals("JFR Periodic Tasks") || eventThread.equals("JFR Recording Scheduler")) {
                continue;
            }

            RecordedStackTrace rst = event.getStackTrace();
            if (rst == null) {
                continue;
            }

            walkFrames(rst, event);

        }
        closeStackWriters();

        clearFile(jfrFile);
    }

    private static void startRecording() {
        try {
            recording = new Recording();
            int samplePeriodMs = args.getSamplePeriodMs();

            // event ref: jdk\src\share\classes\jdk\jfr\conf\default.jfc or jdk.test.lib.jfr.EventNames
            if (oncpuStackWriter != null) {
                recording.enable(CPU_EVENT_JAVA_SAMPLE).withPeriod(Duration.ofMillis(samplePeriodMs));
                recording.enable(CPU_EVENT_NATIVE_SAMPLE).withPeriod(Duration.ofMillis(samplePeriodMs));
            }
            if (offcpuStackWriter != null) {
                recording.enable(OFFCPU_EVENT_JAVA_MON_WAIT).withPeriod(Duration.ofMillis(samplePeriodMs));
                recording.enable(OFFCPU_EVENT_THREAD_PARK).withPeriod(Duration.ofMillis(samplePeriodMs));
            }
            if (memStackWriter != null) {
                recording.enable(MEM_EVENT_IN_TLAB);
                recording.enable(MEM_EVENT_OUT_TLAB);
            }
            recording.setDestination(jfrPath);
            recording.setDuration(Duration.ofSeconds(30));

            recording.start();
        } catch (Exception e) {
            e.printStackTrace();
            recording.stop();
        }
    }

    public static void agentmain(String agentArgs) {
        if (agentArgs == null) {
            System.out.println("[JstackProbe] Agent agentmain input agentArgs is null.");
            return;
        }
        args = new ArgsParse();
        args.setArgs(agentArgs);

        try {
            initFiles();
            walkEvents();
            startRecording();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
