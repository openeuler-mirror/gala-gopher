
public class ArgsParse {

    private static String METRIC_TMPFILE_NAME = "jsse-metrics.txt";
    private static String MetricDataPath;
    private static String MetricTmpFile;
    private static String Pid;

    public int setArgs(String Args) {
        String[] args = Args.split("[,]");
        if (args.length < 2) {
            System.out.println("[JSSEProbeAgent] please add args: Pid,MetricDataPath.");
            return -1;
        }
        try {
            this.Pid = args[0];
            this.MetricDataPath = args[1];
            this.MetricTmpFile = String.format("%s/%s", args[1], METRIC_TMPFILE_NAME);
        } catch (IllegalArgumentException e) {
            System.out.println("[JSSEProbeAgent] parse args failed.");
            return -1;
        }
        return 0;
    }

    public static String getArgPid() {
        return Pid;
    }

    public static String getArgMetricDataPath() {
        return MetricDataPath;
    }

    public static String getArgMetricTmpFile() {
        return MetricTmpFile;
    }

}
