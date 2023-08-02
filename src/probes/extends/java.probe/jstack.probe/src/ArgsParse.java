public class ArgsParse {
    private String Pid;
    private String DataDir;
    private String OncpuStacksFile = null;
    private String OffcpuStacksFile = null;
    private String MemStacksFile = null;
    private String IoStacksFile = null;
    private int SamplePeriodMs = 10; // ms
    private String JfrFile;

    public int setArgs(String Args) {
        String[] args = Args.split("[,]");
        if (args.length < 4) {
            System.out.println("[JstackProbeAgent] please add args: Pid, DataPath, EventType, SamplePeriod.");
            return -1;
        }
        try {
            this.Pid = args[0];
            this.DataDir = args[1];     // /tmp/java-data-<pid>
            if (args[2].contains("oncpu")) {
                this.OncpuStacksFile = String.format("%s/stacks-oncpu.txt", args[1]);
            }
            if (args[2].contains("offcpu")) {
                this.OffcpuStacksFile = String.format("%s/stacks-offcpu.txt", args[1]);
            }
            if (args[2].contains("mem")) {
                this.MemStacksFile = String.format("%s/stacks-mem.txt", args[1]);
            }
            if (args[2].contains("io")) {
                this.IoStacksFile = String.format("%s/stacks-io.txt", args[1]);
            }

            this.SamplePeriodMs = Integer.parseInt(args[3]);
            this.JfrFile = String.format("%s/recording.jfr", args[1]); // recording.jfr
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

    public String getArgOncpuStacksFile() { return this.OncpuStacksFile; }

    public String getArgOffcpuStacksFile() { return this.OffcpuStacksFile; }

    public String getArgMemStacksFile() { return this.MemStacksFile; }

    public String getArgIoStacksFile() { return this.IoStacksFile; }

    public String getArgJfrFile() {
        return this.JfrFile;
    }

    public int getSamplePeriodMs() {
        return this.SamplePeriodMs;
    }
}
