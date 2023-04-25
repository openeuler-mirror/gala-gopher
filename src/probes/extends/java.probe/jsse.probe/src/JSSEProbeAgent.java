import java.lang.instrument.Instrumentation;
import java.io.IOException;
import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

public class JSSEProbeAgent {

    private static void createTmpFile(ArgsParse parse) throws IOException {
        File tmpDirectory = new File(ArgsParse.getArgMetricDataPath());
        if (!tmpDirectory.exists()) {
            tmpDirectory.mkdir();
        }
        File metricTmpFile = new File(ArgsParse.getArgMetricTmpFile());
        if (!metricTmpFile.exists()) {
            metricTmpFile.createNewFile();
        }
    }

    // 该方法仅在premain使用，获取当前进程PID
    private static String getPid() throws IOException {
        byte[] bo = new byte[256];
        InputStream is = new FileInputStream("/proc/self/stat");
        is.read(bo);
        for (int i = 0; i < bo.length; i++) {
            if ((bo[i] < '0') || (bo[i] > '9')) {
                return new String(bo, 0, i);
            }
        }
        return "-1";
    }

    public static void premain(String agentArgs, Instrumentation inst) {
        try {
            String selfPid = getPid();
            if (selfPid == "-1") {
                System.out.println("[JSSEProbeAgent] get self pid null.");
            }
            ArgsParse parse = new ArgsParse();
            parse.setArgs(String.format("%s,java-data-%s", selfPid, selfPid));

            createTmpFile(parse);
        } catch (IOException e) {
            System.out.println("[JSSEProbeAgent] get self pid failed.");
        }

        inst.addTransformer(new ProfilingTransformer());
    }

    public static void premain(String agentArgs) {
        System.out.println("Agent premain 1param:" + agentArgs);
    }

    public static void agentmain(String agentArgs, Instrumentation instrumentation) {
        if (agentArgs == null) {
            System.out.println("[JSSEProbeAgent] Agent agentmain input agentArgs is null, please input $PID.");
            return;
        }

        ArgsParse parse = new ArgsParse();
        parse.setArgs(agentArgs);

        instrumentation.addTransformer(new ProfilingTransformer(), true);
        // agentmain运行时，由于堆里已经存在Class文件。所以添加Transformer后
        // 还要再调用一个 retransformClasses(clazz) 方法来更新Class文件
        for (Class clazz:instrumentation.getAllLoadedClasses()) {
            if (clazz.getName().equals("sun.security.ssl.SSLSocketImpl$AppOutputStream") ||
                clazz.getName().equals("sun.security.ssl.SSLSocketImpl$AppInputStream")) {
                try {
                    createTmpFile(parse);
                    instrumentation.retransformClasses(clazz);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public static void agentmain(String agentArgs) {
        System.out.println("Agent agentmain 1param :" + agentArgs);
    }
}
