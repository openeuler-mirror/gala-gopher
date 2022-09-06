import sys
import time

import redis
import subprocess

REDIS_HOST = "127.0.0.1"
REDIS_PORT = "6379"


class RedisProbe(object):

    def __init__(self, host, port):
        self._host = host
        self._port = port
        self._redis_info = None

    def _get_redis_info_server(self):
        redis_version = self._redis_info['redis_version']
        tcp_port = self._redis_info['tcp_port']
        hz = self._redis_info['hz']
        io_threads_active = self._redis_info['io_threads_active']
        print("|redis_server|%s|%s|%s|%s|" % (redis_version, tcp_port, hz, io_threads_active))
        sys.stdout.flush()

    def _get_redis_info_clients(self):
        connected_clients = self._redis_info['connected_clients']
        cluster_connections = self._redis_info['cluster_connections']
        print("|redis_clients|%s|%s|" % (connected_clients, cluster_connections))
        sys.stdout.flush()

    def _get_redis_info_memory(self):
        used_memory = self._redis_info['used_memory']
        print("|redis_memory|%s|" % used_memory)
        sys.stdout.flush()

    def _get_redis_info_stats(self):
        total_connections_received = self._redis_info['total_connections_received']
        total_commands_processed = self._redis_info['total_commands_processed']
        instantaneous_ops_per_sec = self._redis_info['instantaneous_ops_per_sec']
        total_net_input_bytes = self._redis_info['total_net_input_bytes']
        total_net_output_bytes = self._redis_info['total_net_output_bytes']
        print("|redis_stats|%s|%s|%s|%s|%s|" % (
            total_connections_received,
            total_commands_processed,
            instantaneous_ops_per_sec,
            total_net_input_bytes,
            total_net_output_bytes))
        sys.stdout.flush()

    def _get_redis_info(self):
        redis_conn = redis.Redis(host=self._host, port=self._port)
        self._redis_info = redis_conn.info()
        redis_conn.close()

        self._get_redis_info_server()
        self._get_redis_info_clients()
        self._get_redis_info_memory()
        self._get_redis_info_stats()

    def _get_redis_latency(self):
        command = "redis-cli -h %s -p %s --intrinsic-latency 1 | grep total | awk -F ' ' '{print $6}'" % (
            self._host, self._port)
        ex = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        out, err = ex.communicate()
        print("|redis_latency|%f|" % float(out.decode()))
        sys.stdout.flush()

    def get_data(self):
        self._get_redis_info()
        self._get_redis_latency()


if __name__ == "__main__":
    probe = RedisProbe(REDIS_HOST, REDIS_PORT)
    while True:
        probe.get_data()
        time.sleep(1)
