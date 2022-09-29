import com.sun.tools.attach.*;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class JvmProbe {

    public static List<VirtualMachineDescriptor> virtualMachineDescriptors;
    public static ExecutorService executorService;
    public static int time = 5;
    public static String agentPath;

    final static String agent = "management-agent.jar";

    public static void main(String[] args) {
        ArgsParse(args);
        try {
            agentPath = getTemporaryRes(agent);
        } catch (IOException e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }

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
            executorService.submit(() -> {
                try {
                    Vm vm = new Vm(virtualMachineDescriptor, agentPath);
                    vm.getData();
                } catch (IOException | AgentLoadException | AttachNotSupportedException | AgentInitializationException | InterruptedException e) {
                    System.out.println(e.getMessage());
                }
            });
        }
    }

    public static String getTemporaryRes(String resource) throws IOException {
        //read embedded resource from this JAR
        InputStream inputStream = JvmProbe.class.getResourceAsStream(resource);
        if(inputStream == null){
            throw new IOException("Resource not found in the JAR");
        }

        // create a temporary file
        File temporaryFile = File.createTempFile("resource", null);
        temporaryFile.deleteOnExit();

        // Copy the resource data into the temporary file
        Files.copy(inputStream, temporaryFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        return temporaryFile.getAbsolutePath();
    }
}
