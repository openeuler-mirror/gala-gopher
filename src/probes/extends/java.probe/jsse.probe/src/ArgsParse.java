
public class ArgsParse {

    private static String METRIC_TMPFILE_NAME = "jsse-metrics.txt";
    private static String MetricDataPath;
    private static String MetricTmpFile;
    private static String Pid;
    private static String Action;

    public int setArgs(String Args) {
        String[] args = Args.split("[,]");
        if (args.length < 3) {
            System.out.println("[JSSEProbeAgent] please add args: Pid,MetricDataPath,Action.");
            return -1;
        }
        try {
            this.Pid = args[0];
            this.MetricDataPath = args[1];
            this.MetricTmpFile = String.format("%s/%s", args[1], METRIC_TMPFILE_NAME);
            this.Action = args[2];
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

    public static String getArgMetricAction() {
        return Action;
    }

}
