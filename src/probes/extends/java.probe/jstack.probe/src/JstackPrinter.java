import jdk.jfr.consumer.*;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class JstackPrinter {
    private static String DataDir;
    private static String OncpuStacksFile = null;
    private static String OffcpuStacksFile = null;
    private static String MemStacksFile = null;
    private static String IoStacksFile = null;
    private static Path JfrPath = null;
    private static final String CPU_EVENT_JAVA_SAMPLE = "jdk.ExecutionSample";
    private static final String CPU_EVENT_NATIVE_SAMPLE = "jdk.NativeMethodSample";
    private static final String OFFCPU_EVENT_JAVA_MON_WAIT = "jdk.JavaMonitorWait";
    private static final String OFFCPU_EVENT_THREAD_PARK = "jdk.ThreadPark";
    private static final String MEM_EVENT_IN_TLAB = "jdk.ObjectAllocationInNewTLAB";
    private static final String MEM_EVENT_OUT_TLAB = "jdk.ObjectAllocationOutsideTLAB";

    private static BufferedWriter oncpuStackWriter = null;
    private static BufferedWriter offcpuStackWriter = null;
    private static BufferedWriter memStackWriter = null;

    private static HashMap<RecordedStackTrace, Long> oncpuMap = new HashMap<>();
    private static HashMap<RecordedStackTrace, Long> offcpuMap = new HashMap<>();
    private static HashMap<RecordedStackTrace, Long> memMap = new HashMap<>();

    private static BufferedWriter getBuffWriter(String fileName) throws Exception {
        if (fileName != null) {
            File stacksFile = new File(fileName);
            if (!stacksFile.exists()) {
                stacksFile.createNewFile();
            }

            return new BufferedWriter(new FileWriter(stacksFile));
        }
        return null;
    }

    private static int initFiles() throws Exception {
        File dataDir = new File(DataDir);
        if (!dataDir.exists()) {
            dataDir.mkdir();
            System.out.println("[JstackProbe] dataDir is null.");
            return -1;
        }

        String JfrFileStr = String.format("%s/recording.jfr", DataDir);
        File jfrFile = new File(JfrFileStr);
        if (!jfrFile.exists()) {
            System.out.println("[JstackProbe] jfrFile is null.");
            return -1;
        }

        JfrPath = jfrFile.toPath();
        if (JfrPath == null) {
            System.out.println("[JstackProbe] JfrPath is null.");
            return -1;
        }

        if (jfrFile.length() == 0) {
            Thread.sleep(1000);
            if (jfrFile.length() == 0) {
                System.out.println("[JstackProbe] Jfr File is empty.");
                return -1;
            }
        }

        oncpuStackWriter = getBuffWriter(OncpuStacksFile);
        offcpuStackWriter = getBuffWriter(OffcpuStacksFile);
        memStackWriter = getBuffWriter(MemStacksFile);

        return 0;
    }

    private static String frameToString(RecordedFrame f) {
        RecordedMethod m = f.getMethod();
        String methodName = m.getName();
        String className = m.getType().getName();
        return className + "." + methodName;
    }

    private static String walkFrames(BufferedWriter bw, RecordedStackTrace rst, Long value) throws IOException {
        boolean first = true;
        List<RecordedFrame> frames = rst.getFrames();
        String stackStr = "";
        for (int i = frames.size() - 1; i >= 0; i--) {
            if (!first) {
                stackStr += "; ";
            }
            RecordedFrame rf = frames.get(i);
            stackStr += frameToString(rf);
            first = false;
        }

        if (!first) {
            if (bw == memStackWriter) {
                bw.write(stackStr + " " + value + "\n");
            } else {
                bw.write(stackStr + " " + value + "\n");
            }
        }
        return stackStr;
    }

    private static void addRecordedStackTraceMap(HashMap<RecordedStackTrace, Long> rstHashMap,
                                                 RecordedStackTrace rst, RecordedEvent event){
        Long value, originValue;
        if (rstHashMap == memMap) {
            value = event.getLong("allocationSize");
        } else {
            value = 1L;
        }

        if (rstHashMap.containsKey(rst)) {
            originValue = rstHashMap.get(rst);
            rstHashMap.put(rst, originValue + value);
        } else {
            rstHashMap.put(rst, 1L);
        }
    }

    private static void printHashMapStacks(BufferedWriter bw, HashMap<RecordedStackTrace, Long> hashMap) throws Exception {
        for (Map.Entry<RecordedStackTrace, Long> entry : hashMap.entrySet()) {
            RecordedStackTrace rst = entry.getKey();
            Long value = entry.getValue();
            walkFrames(bw, rst, value);
        }
    }

    private static void printStacks() throws Exception {
        if (oncpuStackWriter != null) {
            printHashMapStacks(oncpuStackWriter, oncpuMap);
            oncpuStackWriter.flush();
            oncpuStackWriter.close();
        }
        if (offcpuStackWriter != null) {
            printHashMapStacks(offcpuStackWriter, offcpuMap);
            offcpuStackWriter.flush();
            offcpuStackWriter.close();
        }
        if (memStackWriter != null) {
            printHashMapStacks(memStackWriter, memMap);
            memStackWriter.flush();
            memStackWriter.close();
        }
    }

    private static int checkThread(RecordedEvent event) {
        String eventThread;
        RecordedThread thread = event.getThread();
        if (thread == null) {
            if (event.hasField("sampledThread")) {
                RecordedThread sampledThread = event.getValue("sampledThread");
                eventThread = sampledThread.getOSName();
            } else {
                return -1;
            }
        } else {
            eventThread = thread.getOSName();
        }

        if (eventThread.equals("Attach Listener") || eventThread.equals("JFR Periodic Tasks") || eventThread.equals("JFR Recording Scheduler")) {
            return -1;
        }
        return 0;
    }

    private static void walkEvents() throws Exception {
        RecordingFile recordingFile = new RecordingFile(JfrPath);
        while (recordingFile.hasMoreEvents()) {
            RecordedEvent event = recordingFile.readEvent();
            if (event == null) {
                continue;
            }

            RecordedStackTrace rst = event.getStackTrace();
            if (rst == null) {
                continue;
            }

            if (checkThread(event) != 0) {
                continue;
            }

            String eventType = event.getEventType().getName();
            if (eventType.equals(CPU_EVENT_JAVA_SAMPLE) || eventType.equals(CPU_EVENT_NATIVE_SAMPLE)) {
                addRecordedStackTraceMap(oncpuMap, rst, event);
            } else if (eventType.equals(OFFCPU_EVENT_JAVA_MON_WAIT) || eventType.equals(OFFCPU_EVENT_THREAD_PARK)) {
                addRecordedStackTraceMap(offcpuMap, rst, event);
            } else if (eventType.equals(MEM_EVENT_IN_TLAB) || eventType.equals(MEM_EVENT_OUT_TLAB)) {
                addRecordedStackTraceMap(memMap, rst, event);
            } else {
                continue;
            }
        }
    }

    private static int setArgs(String[] args) {
        if (args.length < 2) {
            System.out.println("[JstackProbeAgent] please add args: DataPath, EventType.");
            return -1;
        }
        try {
            DataDir = args[0];
            if (args[1].contains("oncpu")) {
                OncpuStacksFile = String.format("%s/stacks-oncpu.txt", DataDir);
            }
            if (args[1].contains("offcpu")) {
                OffcpuStacksFile = String.format("%s/stacks-offcpu.txt", DataDir);
            }
            if (args[1].contains("mem")) {
                MemStacksFile = String.format("%s/stacks-mem.txt", DataDir);
            }
            if (args[1].contains("io")) {
                IoStacksFile = String.format("%s/stacks-io.txt", DataDir);
            }

        } catch (IllegalArgumentException e) {
            System.out.println("[JstackProbeAgent] parse args failed.");
            return -1;
        }
        return 0;
    }

    public static void main(String[] args)  {
        if (setArgs(args) != 0) {
            return;
        }

        try {
            if (initFiles() != 0) {
                return;
            }
            walkEvents();
            printStacks();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
