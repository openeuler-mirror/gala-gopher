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
    private static final String MEM_EVENT_IN_TLAB = "jdk.ObjectAllocationInNewTLAB";
    private static final String MEM_EVENT_OUT_TLAB = "jdk.ObjectAllocationOutsideTLAB";
    private static BufferedWriter stackWriter;
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

    private static void initFiles() throws IOException {
        File dataDir = new File(args.getArgDataDir());
        if (!dataDir.exists()) {
            dataDir.mkdir();
        }

        jfrFile = new File(args.getArgJfrFile());
        if (!jfrFile.exists()) {
            jfrFile.createNewFile();
        }
        jfrPath = jfrFile.toPath();

        File stacksFile = new File(args.getArgStacksFile());
        if (!stacksFile.exists()) {
            stacksFile.createNewFile();
        } else {
            clearFile(stacksFile);
        }

        FileWriter fw = new FileWriter(stacksFile);
        stackWriter = new BufferedWriter(fw);
    }

    private static void walkEvents() throws IOException {
        if (jfrPath == null || jfrFile.length() == 0) {
            stackWriter.close();
            return;
        }

        RecordingFile recordingFile = new RecordingFile(jfrPath);
        while (recordingFile.hasMoreEvents()) {
            RecordedEvent event = recordingFile.readEvent();
            if (event == null) {
                continue;
            }

            RecordedThread thread = event.getThread();
            if (thread == null) {
                continue;
            }

            String eventThread = thread.getOSName();
            if (eventThread.equals("Attach Listener") || eventThread.equals("JFR Periodic Tasks") || eventThread.equals("JFR Recording Scheduler")) {
                continue;
            }

            RecordedStackTrace rst = event.getStackTrace();
            if (rst == null) {
                continue;
            }

            boolean first = true;
            List<RecordedFrame> frames = rst.getFrames();
            for (int i = frames.size() - 1; i >= 0; i--) {
                if (!first) {
                    stackWriter.write("; ");
                }
                RecordedFrame rf = frames.get(i);
                stackWriter.write(rf.getMethod().getType().getName() + "." );
                stackWriter.write(rf.getMethod().getName());
                first = false;
            }

            if (!first) {
                stackWriter.write(" " + event.getLong("allocationSize") + "\n");
            }
        }
        stackWriter.flush();
        stackWriter.close();

        clearFile(jfrFile);
    }

    private static void startRecording() {
        try {
            recording = new Recording();

            // ref: jdk\src\share\classes\jdk\jfr\conf\default.jfc or jdk.test.lib.jfr.EventNames
            recording.enable(MEM_EVENT_IN_TLAB);
            recording.enable(MEM_EVENT_OUT_TLAB);
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
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }
}
