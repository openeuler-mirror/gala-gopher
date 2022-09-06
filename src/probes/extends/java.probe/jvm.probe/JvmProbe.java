import com.sun.tools.attach.*;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

class JvmProbe {


    public static void main(String[] args) throws InterruptedException {
        while (true){
            JvmProbe jvmProbe = new JvmProbe();
            jvmProbe.probe();
            int time = 5;
            if (!args[0].isEmpty()){
                time = Integer.parseInt(args[1]);
            }
            TimeUnit.SECONDS.sleep(time);
        }
    }

    public void probe() {
        List<VirtualMachineDescriptor> virtualMachineDescriptors = VirtualMachine.list();
        ExecutorService executorService = Executors.newFixedThreadPool(5);

        for (VirtualMachineDescriptor virtualMachineDescriptor : virtualMachineDescriptors) {
            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        Vm vm = new Vm(virtualMachineDescriptor);
                        vm.getData();
                    } catch (AgentLoadException | IOException | AttachNotSupportedException | AgentInitializationException e) {
                        e.getMessage();
                    }
                }
            });
        }
    }

}
