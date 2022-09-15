import com.sun.tools.attach.*;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class JvmProbe {

    public static List<VirtualMachineDescriptor> virtualMachineDescriptors;
    public static ExecutorService executorService;
    public static int time =5 ;
    public static String canonicalPath;

    public static void main(String[] args) {
        // set args
        ArgsParse(args);
        //get canonicalPath
        GetFileCanonicalPath();
        //run probe
        while (true) {
            try {
                probe();
                TimeUnit.SECONDS.sleep(time);
            } catch (InterruptedException e) {
                System.out.println(e.getMessage());
                System.exit(1);
            }
        }
    }

    public static void GetFileCanonicalPath() {

        String existAgentPath2 = File.separator + "lib" + File.separator + "management-agent.jar";
        String existAgentPath1 = File.separator + "jre" + existAgentPath2;
        String javaHome = System.getProperties().getProperty("java.home");
        String agentPath = javaHome + existAgentPath1;

        File file = new File(agentPath);
        if (!file.exists()) {
            agentPath = javaHome + existAgentPath2;
            file = new File(agentPath);
            if (!file.exists()) {
                try {
                    throw new IOException("[JVM Probe] management-agent.jar not found");
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                    System.exit(1);
                }
            }
        }
        try {
            canonicalPath = file.getCanonicalPath();
        } catch (IOException e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }
    }

    public static void ArgsParse(String[] args) {
        int  argsLen = args.length;
        HashMap<String,String> argsMap = new HashMap<>();
        for (int i = 0; i < argsLen / 2; i++) {
            argsMap.put(args[i], args[i + 1]);
        }
        //set
        if (argsMap.containsKey("-t")) {
            time = Integer.parseInt(argsMap.get("-t"));
        }
    }

    public static void probe() {
        virtualMachineDescriptors = VirtualMachine.list();
        if (executorService == null) {
            executorService = Executors.newFixedThreadPool(5);
        }
        for (VirtualMachineDescriptor virtualMachineDescriptor : virtualMachineDescriptors) {
            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        Vm vm = new Vm(virtualMachineDescriptor,canonicalPath);
                        vm.getData();
                    } catch (AgentLoadException | IOException | AttachNotSupportedException | AgentInitializationException e) {
                        System.out.println(e.getMessage());
                    }
                }
            });
        }
    }

}
