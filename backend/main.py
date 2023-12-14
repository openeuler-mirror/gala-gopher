import http.client
import os
import time
import urllib
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import threading
from urllib.parse import urlparse
import logging

IP = '127.0.0.1'
PORT = 0

user_login = '{"tenantName": "admin","username": "admin","password": "admin123","rememberMe": false}'
user_create = '{"username": "tf9o8mp3dy","password": "testcurl11","nickname": "umw5rbsdu5","email": "fe3dt544qb@163.com","mobile": "","deptId": 100,"postIds": [],"status": 0,"remark": ""}'
user_update = '{"id": 101,"name": "tf9o8mp3dy","code": "ftlbpf66s1","sort": 0,"remark": "5a9rluvx1v","status": 0,"dataScope": 1,"dataScopeDeptIds": [],"type": 2,"createTime": 1609912175000}'
login_headers = {"tenant-id": "1", "Content-Type": "application/json"}
user_id = []
batch_write_disk = ""
operate_url_prefix = "/admin-api/system/user/"
update_operate_url_prefix = "/admin-api/system/role/"
keep_alive_url_prefix = "/a-ops/keepalive"
next = []
keep_alive_wait_port = ""
is_batch_write_disk = []

count = []

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s',
    filename="log.txt",
    filemode="w"  # 每次重启程序，覆盖之前的日志
)


def build_url(ip, port, url_prefix, operate, id):
    url = "http://" + ip + ":" + str(port) + url_prefix
    if operate != "":
        url = url + operate
    if id != "":
        url = url + "?id=" + str(id)
    return url


class Next:
    def __init__(self, is_auth, ip, url_port, keep_alive_port):
        self.is_auth = is_auth
        self.ip = ip
        self.url_port = url_port
        self.keep_alive_port = keep_alive_port
        self.token = ""


class BatchWriteDiskThread(threading.Thread):
    def __init__(self, if_file, of_file, bs, count):
        threading.Thread.__init__(self)
        self.if_file = if_file
        self.of_file = of_file
        self.bs = bs
        self.count = count

    # 执行linux命令进行写盘操作
    def run(self):
        if (os.path.exists(self.of_file) is None):
            return
        cmd = "dd if=" + self.if_file + " " + "of=" + self.of_file + " " + "bs=" + str(self.bs) + " " + "count=" + str(
            self.count)
        os.system(cmd)
        return


class GetTokenThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    # 每隔一分钟刷新token,token列表中只保存最新的token,旧的token会删除掉
    def run(self):
        while True:
            get_token()

            # 动态监控是否开启磁盘
            with open('backend.json', 'r') as backend_file:
                backend_data = json.load(backend_file)
                is_write = backend_data['batch_write_disk']
                if is_write is not None:
                    batch_write_disk = backend_data['batch_write_disk']
                    if (batch_write_disk != None):
                        is_batch_write_disk.clear()
                        is_batch_write_disk.append(batch_write_disk)
            time.sleep(60)


class KeepAliveHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        url = self.path[1:]
        response = urllib.request.urlopen(url)
        content = response.read()

        # 发送响应
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(content)


class KeepAliveThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        with HTTPServer((IP, keep_alive_wait_port), KeepAliveHandler) as httpd:
            logging.debug("KeepAliveThread serving at port %d", keep_alive_wait_port)
            httpd.serve_forever()


class ReceiveHttpRequestThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        with HTTPServer((IP, PORT), Handler) as httpd:
            logging.debug("ReceiveHttpRequestThread serving at port %d", PORT)
            httpd.serve_forever()


class Handler(BaseHTTPRequestHandler):
    # 接收web or backend的put请求
    def do_PUT(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        path_list = path.split('/')
        operate = path_list[len(path_list) - 1]

        if operate == 'create':

            # 创建文件
            batch_write_disk_thread = BatchWriteDiskThread("/dev/null", "/dev/zero", 4, 10)
            batch_write_disk_thread.start()

            # 发送请求给下游
            self.send_request_next(operate, None)
        elif operate == 'update' and is_batch_write_disk[len(is_batch_write_disk) - 1] == 1:

            # 开启线程进行更新文件、写盘操作
            batch_write_disk_thread = BatchWriteDiskThread("/dev/null", file_name, 4, 100000)
            batch_write_disk_thread.start()

            self.send_request_next(operate, None)
        elif operate == 'delete' and len(user_id) != 0:
            self.send_request_next(operate, user_id[len(user_id) - 1])

    # 发送数据给下游，backend or java_app
    def send_request_next(self, operate, id):
        if len(next) != 0:
            element = next[0]
            ip = element.ip
            port = element.url_port
            is_auth = element.is_auth

            conn = http.client.HTTPConnection(ip, port)
            try:
                # 下游是backend
                if is_auth == 0:
                    if operate == 'create':
                        conn.request("PUT", build_url(ip, port, operate_url_prefix, "create", ""))
                    elif operate == 'update':
                        conn.request("PUT", build_url(ip, port, update_operate_url_prefix, "update", ""))
                    elif operate == 'delete':
                        conn.request("PUT", build_url(ip, port, operate_url_prefix, "delete", ""))
                # 下游是java_app
                elif is_auth == 1:
                    if element.token != "":
                        token_header = {"Authorization":"Bearer " + element.token , "tenant-id": "1",
                                        "Content-Type": "application/json"}
                        if operate == 'create':
                            conn.request("POST", build_url(ip, port, operate_url_prefix, "create", ""), user_create,
                                         token_header)
                            response = conn.getresponse()
                            context = response.read()
                            id = json.loads(context)["data"]
                            user_id.append(id)
                        elif operate == 'update':
                            conn.request("PUT", build_url(ip, port, update_operate_url_prefix, "update", ""), user_update,
                                         token_header)
                        elif operate == 'delete':
                            conn.request("DELETE", build_url(ip, port, operate_url_prefix, "delete", user_id[0]), "", token_header)
                            user_id.remove(user_id[0])
            except Exception:
                conn.close()
                return
            conn.close()

def get_token():
    for elem in next:
        if elem.is_auth == 1:
            try:
                conn = http.client.HTTPConnection(elem.ip, elem.url_port)
                # 获取token
                conn.request("POST", build_url(elem.ip, elem.url_port, "/admin-api/system/auth/login", "", ""),
                             user_login, login_headers)
                response = conn.getresponse()
                response_token = json.loads(response)["accessToken"]
                elem.token = response_token
                conn.close()
            except Exception:
                elem.token = None


if __name__ == "__main__":

    with open('backend.json', 'r') as backend_file:
        backend_data = json.load(backend_file)
        PORT = backend_data['port']
        next_array = backend_data['next']
        keep_alive_wait_port = backend_data['keep_alive_wait_port']
        for elem in next_array:
            e = Next(elem["is_auth"], elem["ip"], elem["url_port"], elem["keep_alive_port"])
            next.append(e)

    # 周期刷新token
    get_token_thread = GetTokenThread()
    get_token_thread.start()

    # 接收心跳
    thread = KeepAliveThread()
    thread.start()

    # 接收web或backend的http请求
    http_request_thread = ReceiveHttpRequestThread()
    http_request_thread.start()

    # 周期发送心跳
    while True:
        for elem in next:
            if elem.keep_alive_port > 0:
                try:
                    conn = http.client.HTTPConnection(elem.ip, elem.keep_alive_port)
                    conn.request("POST", build_url(elem.ip, elem.keep_alive_port, keep_alive_url_prefix, "", ""))
                    conn.close()
                    time.sleep(30)
                except Exception:
                    break
