import http.client
import os
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from urllib.parse import urlparse
import logging
import random
import json

IP = '0.0.0.0'
PORT = 0

user_login = '{"tenantName": "admin","username": "admin","password": "admin123","rememberMe": false}'
user_create = {"username": "tf9o8mp3dd", "password": "testcurl11", "nickname": "umw5rbsdu4",
               "email": "fe3dt444qb@163.com", "mobile": "", "deptId": 100, "postIds": [], "status": 0, "remark": ""}
user_update = {"id": 101, "username": "tf9o8mp3dd", "password": "testcurl11", "nickname": "umw5rbsdu4",
                "email": "fe3dt444qb@163.com", "mobile": "", "deptId": 100, "postIds": [], "status": 0, "remark": ""}
login_headers = {"tenant-id": "1", "Content-Type": "application/json",
                "User-Agent":"Mozillla/5.0 Chrome/111.0.0.0 Safari/537.36 Edg/111.0.1661.54"}
body_of_send_backend_request = {"body":"body of send request to backend"}
user_id = []
batch_write_disk = ""
operate_url_prefix = "/admin-api/system/user/"
keep_alive_url_prefix = "/a-ops/keepalive"
next = []
keep_alive_wait_port = ""
is_batch_write_disk = []
count = []
lock = threading.Lock()
update_file = "/home/file.txt"

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s',
    filename="log.txt",
    filemode="w"  # 每次重启程序，覆盖之前的日志
)


# 随机生成email
def random_email():
    prefix = 'abcdefghijklmnopqrstuvwsyz'
    end = ['@163.com', '@qq.com', '@163.net', '@live.com', '@sohu.com', '@126.com']
    return ''.join([random.choice(prefix) for i in range(random.randint(5, 14))]) + random.choice(end)


# 随机生成用户名
def random_name():
    name = "AaBbCcDdEdFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789"
    last = ""
    # 随机生成10个字符组成name
    for i in range(10):
        index = random.randint(0, len(name) - 1)
        last += name[index]
    return last


def build_url(ip, port, url_prefix, operate, id):
    url = "http://" + ip + ":" + str(port) + url_prefix
    if operate != "":
        url = url + operate
    if id != "":
        url = url + "?id=" + str(id)
    return url


def send_response(self, response, context):
    self.send_response(200)
    self.send_header('Content-type', 'application/json')
    self.end_headers()
    self.wfile.write(bytes(context, 'utf-8'))


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
        cmd = "dd if=" + self.if_file + " " + "of=" + self.of_file + " " + "bs=" + bs + " " + "count=" + str(
            self.count)
        os.system(cmd)

        if of_file == update_file:
            try:
                os.remove(update_file)
            except OSError as error:
                logging.debug("os.remove %s", error)
        return


class IsBatchWriteThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    # 动态监测是否支持批量写盘
    def run(self):
        while True:
            with open('backend.json', 'r') as backend_file:
                backend_data = json.load(backend_file)
                is_write = backend_data['batch_write_disk']
                if is_write is not None:
                    batch_write_disk = backend_data['batch_write_disk']
                    if (batch_write_disk != None):
                        is_batch_write_disk.clear()
                        is_batch_write_disk.append(batch_write_disk)


class KeepAliveHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # 发送响应
        send_response(self, None, 'received keep-alive')


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
        logging.debug("received %s request", operate)
        if operate == 'create':
            # 创建文件
            batch_write_disk_thread = BatchWriteDiskThread("/dev/zero", "/dev/null", "4M", 100)
            batch_write_disk_thread.start()

            # 发送请求给下游
            self.send_request_next(operate, None)
        elif operate == 'update' and is_batch_write_disk[len(is_batch_write_disk) - 1] == 1:
            # 开启线程进行更新文件、写盘操作
            batch_write_disk_thread = BatchWriteDiskThread("/dev/zero", update_file, "4M", 1000)
            batch_write_disk_thread.start()

            self.send_request_next(operate, None)
        elif operate == 'delete':
            self.send_request_next(operate, None)

    # 发送数据给下游，backend or java_app
    def send_request_next(self, operate, id):
        if len(next) != 0:
            i = random.randint(0, len(next) - 1)
            element = next[i]
            ip = element.ip
            port = element.url_port
            is_auth = element.is_auth

            conn = http.client.HTTPConnection(ip, port)
            try:
                # 下游是backend
                if is_auth == 0 and port > 0:
                    if operate == 'create':
                        conn.request("PUT", build_url(ip, port, operate_url_prefix, "create", ""))

                        send_response(self, conn.getresponse(), 'successfully sent create request!')
                    elif operate == 'update':
                        conn.request("PUT", build_url(ip, port, update_operate_url_prefix, "update", ""))

                        send_response(self, conn.getresponse(), 'successfully sent update request!')
                    elif operate == 'delete':
                        conn.request("PUT", build_url(ip, port, operate_url_prefix, "delete", ""))

                        send_response(self, conn.getresponse(), 'successfully sent delete request!')
                # 下游是java_app
                elif is_auth == 1 and port > 0:
                    # 获取token
                    conn.request("POST",
                                 build_url(element.ip, element.url_port, "/admin-api/system/auth/login", "", ""),
                                 user_login, login_headers)
                    response = conn.getresponse()
                    msg = response.read()
                    data = json.loads(msg)["data"]
                    response_token = data["accessToken"]
                    element.token = response_token

                    if element.token == "":
                        return

                    token_header = {"Authorization": "Bearer " + element.token, "tenant-id": "1",
                                    "Content-Type": "application/json",
                                    "User-Agent":"Mozillla/5.0 Chrome/111.0.0.0 Safari/537.36 Edg/111.0.1661.54"}
                    if operate == 'create':
                        user_create["username"] = random_name()
                        user_create["email"] = random_email()

                        conn.request("POST", build_url(ip, port, operate_url_prefix, "create", ""),
                                     json.dumps(user_create),
                                     token_header)

                        response = conn.getresponse()
                        context = response.read()
                        id = json.loads(context)["data"]
                        logging.debug("id %d", id)
                        lock.acquire()
                        user_id.append(id)
                        lock.release()

                        send_response(self, response, 'successfully sent create request!')
                    elif operate == 'update' and len(user_id) > 0:
                        user_update["id"] = user_id[len(user_id) - 1]
                        user_update["email"] = random_email()

                        conn.request("PUT", build_url(ip, port, operate_url_prefix, "update", ""),
                                     json.dumps(user_update),
                                     token_header)

                        send_response(self, conn.getresponse(), 'successfully sent update request!')
                    elif operate == 'delete' and len(user_id) > 0:
                        conn.request("DELETE",
                                     build_url(ip, port, operate_url_prefix, "delete", user_id[len(user_id) - 1]),
                                     "", token_header)

                        lock.acquire()
                        user_id.remove(user_id[len(user_id) - 1])
                        lock.release()

                        send_response(self, conn.getresponse(), 'successfully sent delete request!')

            except Exception as e:
                logging.debug("failed. Err: %s", repr(e))
                conn.close()
        conn.close()


if __name__ == "__main__":

    with open('backend.json', 'r') as backend_file:
        backend_data = json.load(backend_file)
        PORT = backend_data['port']
        next_array = backend_data['next']
        keep_alive_wait_port = backend_data['keep_alive_wait_port']

        for elem in next_array:
            e = Next(elem["is_auth"], elem["ip"], elem["url_port"], elem["keep_alive_port"])
            next.append(e)

    # 动态监测是否支持批量写盘
    is_batch_write_thread = IsBatchWriteThread()
    is_batch_write_thread.start()

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
