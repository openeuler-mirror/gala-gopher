public class ArgsParse {
    private String Pid;
    private String DataDir;
    private String EventType;
    private String StacksFile;
    private String JfrFile;

    public int setArgs(String Args) {
        String[] args = Args.split("[,]");
        if (args.length < 3) {
            System.out.println("[JstackProbeAgent] please add args: Pid, DataPath, EventType.");
            return -1;
        }
        try {
            this.Pid = args[0];
            this.DataDir = args[1];     // /tmp/java-data-<pid>
            this.EventType = args[2];   // onpcu,offcpu,mem,io
            this.StacksFile = String.format("%s/stacks-%s.txt", args[1], args[2]);
            this.JfrFile = String.format("%s/recording-%s.jfr", args[1], args[2]); // recording-mem.jfr
        } catch (IllegalArgumentException e) {
            System.out.println("[JstackProbeAgent] parse args failed.");
            return -1;
        }
        return 0;
    }

    public String getArgPid() {
        return this.Pid;
    }

    public String getArgDataDir() {
        return this.DataDir;
    }

    public String getArgStacksFile() {
        return this.StacksFile;
    }

    public String getArgJfrFile() {
        return this.JfrFile;
    }

    public String getArgEventType() {
        return this.EventType;
    }
}
