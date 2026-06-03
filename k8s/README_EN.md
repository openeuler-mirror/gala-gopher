# Deployment Guide for gala-gopher DaemonSet in the Kubernetes Environment

## Environment Preparation

Prepare a Kubernetes cluster environment. It is recommended that the OS architecture and version be consistent in the cluster. Only the following versions are supported: openEuler 20.03 LTS SP1, openEuler 22.03 LTS, openEuler 22.03 LTS SP1, and Kylin V10 x86.

## Customizing the DaemonSet YAML File

Download the [DaemonSet template file](./daemonset.yaml.tmpl) to the local host, rename it **gala-gopher_daemonset.yaml**, and perform the following steps to modify the file:

### Modifying the Namespace

Modify {{NAMESPACE}} in the following line of the **gala-gopher_daemonset.yaml** file to define the namespace where gala-gopher is located, for example, **default**.

```shell
namespace: default
```

### Modifying the Container Image Address

Modify {{ARCH}} and {{TAG}} in the following line of the **gala-gopher_daemonset.yaml** file based on the architecture and version of the OS in the cluster.

```shell
image: hub.oepkgs.net/a-ops/gala-gopher-{{ARCH}}:{{TAG}}
```

{{ARCH}} can be set to **aarch64** or **x86_64**.

{{TAG}} can be set to **20.03-lts-sp1**, **22.03-lts**, **22.03-lts-sp1** and **kylin-v10**.

### Modifying Container Environment Variables

The environment variables under the **env** entry in the YAML file are used to control various configurations during gala-gopher running. Modify the environment variables as follows.

| Variable Name                       | Variable Function                                                    | Configured Value                                                  |
| ----------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| GOPHER_HOST_PATH              | The root directory "/" outside the container is mapped to a directory in the gala-gopher container so that gala-gopher can access key files (binary executable files such as kernel debug files, glibc dynamic libraries, and httpd) on the host machine for data collection.| The default value is recommended.                                      |
| GOPHER_LOG_LEVEL              | Specifying the output level of gala-gopher logs                                 | The value can be **debug**, **info**, **warn**, or **error**.                         |
| GOPHER_EVENT_CHANNEL          | Output mode of gala-gopher subhealth inspection exception events                       | **kafka**: reported through Kafka (default)<br>**logs**: output to local logs       |
| GOPHER_META_CHANNEL           | Output mode of gala-gopher observed object metadata                   | **kafka**: reported through Kafka (default)<br>**logs**: output to local logs       |
| GOPHER_KAKFA_SERVER           | IP address of the Kafka server to which gala-gopher reports subhealth inspection exception events and observed object metadata| This variable can be left empty when both ***GOPHER_EVENT_CHANNEL*** and ***GOPHER_META_CHANNEL*** are set to **logs**. Otherwise, set this variable to a valid Kafka server IP address, for example, 1.2.3.4.|
| GOPHER_METRIC_PORT            | Listening port of gala-gopher that functions as the Prometheus exporter to output metric data    | Set this variable to a valid port number that is not occupied by other programs. The default value is **8888**.              |
| GOPHER_REST_PORT              | Dynamically configuring the port number of the RESTful API                                   | Set this variable to a valid port number that is not occupied by other programs. The default value is **9999**.              |
| GOPHER_REST_AUTH              | Specifying dynamic configuration of whether to enable HTTPS and certificate authentication for the RESTful API            | **no**: disabled (default)<br>**yes**: enabled                            |
| GOPHER_REST_PRIVATE_KEY       | Dynamically configuring the path of the private key file for enabling HTTPS for the RESTful API                  | This variable is mandatory when ***GOPHER_REST_AUTH*** is set to **yes**. The path must be an absolute path.                 |
| GOPHER_REST_CERT              | Dynamically configuring the path of the certificate file for enabling HTTPS for the RESTful API                  | This variable is mandatory when ***GOPHER_REST_AUTH*** is set to **yes**. The path must be an absolute path.                 |
| GOPHER_REST_CAFILE            | Dynamically configuring the path of the CA certificate file for enabling authentication for the RESTful API                 | This variable is mandatory when ***GOPHER_REST_AUTH*** is set to **yes**. The path must be an absolute path.                 |
| GOPHER_METRIC_LOGS_TOTAL_SIZE | Maximum total size of metrics data log files, in MB               | The value must be a positive integer. The default value is **100**.                                       |
| GOPHER_PROBES_INIT            | Specifying the probes that are enabled by default after gala-gopher is started and their configurations (collection sub-items, monitored objects, and parameters).| Each probe occupies a separate line. The content of each line is [Collection feature name] [Dynamic configuration JSON]. For details about the feature name and JSON format, see [APIs for Dynamic Configuration](../config/APIs for Dynamic Probe Configuration.md).<br>If the probe does not need to be enabled by default, leave this variable empty.|

### (Optional) Modifying Other DaemonSet Configuration Items

By default, the **gala-gopher_daemonset.yaml** file deploys gala-gopher pods on all nodes (including master nodes) of the cluster. You can modify the following content in the file as required:

    spec:
      nodeName:       # Specifies nodes on which the pods are created.    
      tolerations:    # Defines taints and tolerance rules.
      - key: node-role.kubernetes.io/master
        effect: NoSchedule

## Starting Deployment

Run the following command on the master node of the Kubernetes cluster:

```shell
kubectl apply -f gala-gopher_daemonset.yaml
```

## Checking the Deployment Result

During the deployment, you can run the following command to check the status of gala-gopher pods in real time:

```shell
# Check the status of all gala-gopher pods.
kubectl get pods -L gala-gopher

# Check the deployment details of a gala-gopher pod.
kubectl describe pod gala-gopher-xxxxx
```

If the pod status is **Running**, the deployment is successful.

## Note

(1) During Kubernetes deployment, the JSON file may conflict with the command line. In this case, delete the description about insecure-registries from the **/etc/sysconfig/docker-storage** file.

(2) During Kubernetes deployment, kubectl may fail to connect to the Kubernetes server, as indicated by the prompt message "The connection to the server 9.82.169.17:6443 was refused - did you specify the right host or port?".
    Run the following commands to resolve the issue:
    1. **sudo –i**
    2. **swapoff -a**
    3. **exit**
    4. **strace -eopenat kubectl version**
