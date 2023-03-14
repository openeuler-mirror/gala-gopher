import java.io.IOException;
import java.io.File;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;
import java.lang.Process;
import java.lang.ProcessBuilder;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

public class JvmProbe {

    private static String PROC_COMM_CMD = "/usr/bin/cat /proc/%d/comm 2> /dev/null";
    private static String PROC_STATUS_CMD =
        "/usr/bin/cat /proc/%s/status 2> /dev/null | grep -w NStgid | awk -F ' ' '{print $NF}'";
    private static String BPFTOOL_DUMP_PROCMAP_CMD =
        "bpftool map dump pinned /sys/fs/bpf/probe/proc_map 2> /dev/null | grep key | awk -F ' ' '{print $5$4$3$2}'";
    // jvm_attach <pid> <nspid> load instrument false "/tmp/JvmProbeAgent.jar=<pid>,<nspid>"
    private static String ATTACH_CMD = "%s %s %s load instrument false \"%s=%s,%s\"";
    private final static String ATTACH_BIN_PATH = "/opt/gala-gopher/extend_probes/jvm_attach";
    private final static String HOST_JAR_DIR = "/opt/gala-gopher/extend_probes";
    private final static String NS_TMP_DIR = "/tmp";
    private final static String AGENT_JAR_NAME = "JvmProbeAgent.jar";
    private static final String METRIC_FILE_NAME = "jvm-metrics.txt";
    private static int period = 5;

    private static class ProcessInfo {
        String pid;
        String nspid;
    }

    private static void argsParse(String[] args) {
        int  argsLen = args.length;
        HashMap<String,String> argsMap = new HashMap<>();
        for (int i = 0; i < argsLen / 2; i++) {
            argsMap.put(args[i], args[i + 1]);
        }
        //set
        if (argsMap.containsKey("-t")) {
            period = Integer.parseInt(argsMap.get("-t"));
        }
    }

    private static Boolean detactProcIsJava(int procId) throws IOException {
        List<String> commandList = new ArrayList<>();
        commandList.add("sh");
        commandList.add("-c");
        commandList.add(String.format(PROC_COMM_CMD, procId));

        ProcessBuilder pb = new ProcessBuilder(commandList);
        Process process = pb.start();

        BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line = null;
        while ((line = br.readLine()) != null) {
            if (line.equals("java")) {
                return true;
            }
        }
        return false;
    }

    private static List<Integer> checkProcessToAttach() throws IOException, InterruptedException {
        List<Integer> pidList = new ArrayList<>();
        List<String> commandList = new ArrayList<>();
        commandList.add("sh");
        commandList.add("-c");
        commandList.add(BPFTOOL_DUMP_PROCMAP_CMD);

        ProcessBuilder pb = new ProcessBuilder(commandList);
        Process process = pb.start();
        int ret = process.waitFor();
        if (ret != 0) {
            System.out.println("Process exited with code: " + ret + " cmd: " + commandList);
            return pidList; // empty list
        }
        BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line = null;
        while ((line = br.readLine()) != null) {
            int decimal = Integer.decode(String.format("0x%s", line));
            if (detactProcIsJava(decimal)) {
                pidList.add(decimal);
            }
        }

        return pidList;
    }

    private static ProcessInfo setEffectiveId(String pid) throws IOException {
        ProcessInfo attachInfo = new ProcessInfo();
        List<String> commandList = new ArrayList<>();
        commandList.add("sh");
        commandList.add("-c");
        commandList.add(String.format(PROC_STATUS_CMD, pid));

        ProcessBuilder pb = new ProcessBuilder(commandList);
        Process process = pb.start();

        BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line = null;
        while ((line = br.readLine()) != null) {
            attachInfo.nspid = line;
        }

        attachInfo.pid = pid;
        return attachInfo;
    }

    private static void setJarFileToTmp(String Pid) throws IOException {
        File nsAgentPath = new File(String.format("/proc/%s/root%s/%s", Pid, NS_TMP_DIR, AGENT_JAR_NAME));
        File hostAgentJarPath = new File(String.format("%s/%s", HOST_JAR_DIR, AGENT_JAR_NAME));

        Files.copy(hostAgentJarPath.toPath(), nsAgentPath.toPath(), StandardCopyOption.REPLACE_EXISTING);
    }

    private static Boolean getNsJarPath(ProcessInfo attachInfo) {
        if (attachInfo.nspid.equals(attachInfo.pid)) {
            return true;
        }
        return false;
    }

    private static void delTmpFile(File file) {
        if (file.delete() != true) {
            System.out.println("delete file failed.\n");
        }
    }

    private static int doAttach(ProcessInfo attachInfo) throws IOException, InterruptedException {
        int ret = -1;
        List<String> commandList = new ArrayList<>();
        if (attachInfo.pid == null || attachInfo.nspid == null) {
            System.out.println("attach failed becase null pid or nspid");
            return -1;
        }
        String nsJarPath;
        if (getNsJarPath(attachInfo)) {
            nsJarPath = String.format("/proc/%s/root%s/%s", attachInfo.pid, NS_TMP_DIR, AGENT_JAR_NAME);
        } else {
            nsJarPath = String.format("%s/%s", NS_TMP_DIR, AGENT_JAR_NAME);
        }
        
        commandList.add("sh");
        commandList.add("-c");
        commandList.add(String.format(ATTACH_CMD,
            ATTACH_BIN_PATH, attachInfo.pid, attachInfo.nspid, nsJarPath, attachInfo.pid, attachInfo.nspid));

        ProcessBuilder pb = new ProcessBuilder(commandList);
        Process process = pb.start();
        ret = process.waitFor();
        if (ret != 0) {
            System.out.println("Program attach exited with code: " + ret + " command: " + commandList);
        }

        return ret;
    }

    private static int readMetricFile(ProcessInfo attachInfo) throws IOException {
        File jvmMetricFile = new File(String.format("/proc/%s/root/tmp/%s", attachInfo.pid, METRIC_FILE_NAME));
        if (!jvmMetricFile.exists()) {
            System.out.printf("Proc[%s] has no jvm metric file in /tmp path.\n", attachInfo.pid);
            return 0;
        }

        InputStreamReader streamReader = new InputStreamReader(new FileInputStream(jvmMetricFile));
        BufferedReader br = new BufferedReader(streamReader);
        String line = null;
        while ((line = br.readLine()) != null) {
            System.out.println(line);
        }

        // del metric file after read
        if (jvmMetricFile.delete() != true) {
            System.out.println("delete jvm metric file failed.\n");
            return -1;
        }

        return 0;
    }

    private static void probe() throws IOException, InterruptedException {
        List<Integer> jvmProcList = checkProcessToAttach();
        System.out.println(jvmProcList);

        for (int i = 0; i < jvmProcList.size(); i++) {
            ProcessInfo attachInfo = setEffectiveId(jvmProcList.get(i).toString());
            try {
                setJarFileToTmp(attachInfo.pid);
            } catch (IOException e) {
                System.out.println("copy host_jar to ns_tmp failed, err: %s" + e.getMessage());
                continue;
            }
            doAttach(attachInfo);
            readMetricFile(attachInfo);
        }
    }

    public static void main(String[] args) {
        argsParse(args);
        while (true) {
            try {
                probe();
            } catch (IOException e) {
                System.out.println(e.getMessage());
            } catch (InterruptedException e) {
                System.out.println(e.getMessage());
            }
            // sleep
            try {
                TimeUnit.SECONDS.sleep(period);
            } catch (InterruptedException e) {
                System.out.println(e.getMessage());
            }
        }
    }

}
