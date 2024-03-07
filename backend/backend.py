import http.client
import os
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from collections import deque
import threading
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
                 "User-Agent": "Mozillla/5.0 Chrome/111.0.0.0 Safari/537.36 Edg/111.0.1661.54"}
body_of_send_backend_request = {"body": "body of send request to backend"}
body_of_send_keep_alive_request = {"body": "body of send keep-alive request to backend"}
batch_write_disk = ""
operate_url_prefix = "/admin-api/system/user/"
keep_alive_url_prefix = "/a-ops/keepalive"
next = []
keep_alive_wait_port = ""
is_batch_write_disk = 0
count = []

update_file_deque = deque()
update_user_id_deque = deque()

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


# 随机生成数字
def random_number():
    number = "0123456789"
    last = ""
    # 随机生成5个字符组成number
    for i in range(5):
        index = random.randint(0, len(number) - 1)
        last += number[index]
    return last


def build_url(ip, port, url_prefix, operate, id):
    url = "http://" + ip + ":" + str(port) + url_prefix
    if operate != "":
        url = url + operate
    if id != "":
        url = url + "?id=" + str(id)
    return url


def send_response(self, context):
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


class IsBatchWriteThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    # 动态监测是否支持批量写盘
    def run(self):
        while True:
            try:
                with open('backend.json', 'r') as backend_file:
                    global is_batch_write_disk
                    backend_data = json.load(backend_file)
                    is_batch_write_disk = backend_data['batch_write_disk']
            except:
                logging.debug("open backend.json error!")
            time.sleep(5)


class KeepAliveHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # 发送响应
        send_response(self, 'received keep-alive')


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

        logging.debug("received %s %s request", self.client_address, operate)

        if operate == 'create':
            file = "/home/file_" + str(random_number()) + ".txt"
            try:
                # 创建文件
                os.mknod(file)
                update_file_deque.append(file)
            except Exception as e:
                logging.debug("failed to create update_file. Err: %s", repr(e))

            # 发送请求给下游
            self.send_request_next(operate, None)
        elif operate == 'update' and len(update_file_deque) != 0:
            file = update_file_deque.popleft()
            try:
                fp = open(file, 'a', encoding='utf-8')
                file_size = 1024 * 5
                while fp.tell() < file_size:
                    fp.write("update")
                fp.close()
            except Exception as e:
                logging.debug("failed to update update_file. Err: %s", repr(e))

            update_file_deque.appendleft(file)

            if is_batch_write_disk == 1:
                file_path = "/home/batch_update_file_" + str(random_number()) + ".txt"

                # 批量写盘操作
                cmd = "dd if=/dev/zero of=" + file_path + " bs= 500 count=" + str(1000000)
                os.system(cmd)

                os.remove(file_path)
            self.send_request_next(operate, None)
        elif operate == 'delete' and len(update_file_deque) != 0:
            try:
                delete_file = update_file_deque.popleft()
                os.remove(delete_file)
            except Exception as e:
                logging.debug("failed to os.remove(update_file). Err: %s", repr(e))

            self.send_request_next(operate, None)

    # 发送数据给下游，backend or java_app
    def send_request_next(self, operate, id):
        if len(next) != 0:
            i = random.randint(0, len(next) - 1)
            element = next[i]
            ip = element.ip
            port = element.url_port
            is_auth = element.is_auth

            try:
                conn = http.client.HTTPConnection(ip, port, timeout=30)
                # 下游是backend
                if is_auth == 0 and port > 0:
                    header = {"Content-Type": "application/json",
                              "User-Agent": "Mozillla/5.0 Chrome/111.0.0.0 Safari/537.36 Edg/111.0.1661.54"}
                    if operate == 'create':
                        conn.request("PUT", build_url(ip, port, operate_url_prefix, "create", ""),
                                     json.dumps(body_of_send_backend_request), header)
                        response = conn.getresponse()
                        send_response(self, 'successfully sent create request!')
                    elif operate == 'update':
                        conn.request("PUT", build_url(ip, port, operate_url_prefix, "update", ""),
                                     json.dumps(body_of_send_backend_request), header)
                        response = conn.getresponse()
                        send_response(self, 'successfully sent update request!')
                    elif operate == 'delete':
                        conn.request("PUT", build_url(ip, port, operate_url_prefix, "delete", ""),
                                     json.dumps(body_of_send_backend_request), header)
                        response = conn.getresponse()
                        send_response(self, 'successfully sent delete request!')
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
                                    "User-Agent": "Mozillla/5.0 Chrome/111.0.0.0 Safari/537.36 Edg/111.0.1661.54"}
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

                        update_user_id_deque.append(id)

                        send_response(self, 'successfully sent create request!')
                    elif operate == 'update' and len(update_user_id_deque) != 0:
                        user_id = update_user_id_deque.popleft()
                        user_update["id"] = user_id
                        user_update["email"] = random_email()
                        conn.request("PUT", build_url(ip, port, operate_url_prefix, "update", ""),
                                     json.dumps(user_update),
                                     token_header)
                        response = conn.getresponse()

                        update_user_id_deque.appendleft(user_id)

                        send_response(self, 'successfully sent update request!')
                    elif operate == 'delete' and len(update_user_id_deque) != 0:
                        user_id = update_user_id_deque.popleft()
                        conn.request("DELETE",
                                         build_url(ip, port, operate_url_prefix, "delete", user_id),
                                         "", token_header)
                        response = conn.getresponse()
                        send_response(self, 'successfully sent delete request!')
                conn.close()
            except Exception as e:
                logging.debug("failed to send request to %s:%d. Err: %s", ip, port, repr(e))


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
    receive_http_request_thread = ReceiveHttpRequestThread()
    receive_http_request_thread.start()

    # 周期发送心跳
    while True:
        for elem in next:
            if elem.keep_alive_port > 0:
                try:
                    conn = http.client.HTTPConnection(elem.ip, elem.keep_alive_port, timeout=30)
                    conn.request("POST", build_url(elem.ip, elem.keep_alive_port, keep_alive_url_prefix, "", ""),
                                 json.dumps(body_of_send_keep_alive_request))
                    response = conn.getresponse()
                    context = response.read()
                    logging.debug("successfully send keep-alive to %s:%d, response data is %s", elem.ip,
                                  elem.keep_alive_port, context)
                    conn.close()
                    time.sleep(30)
                except Exception as e:
                    logging.debug("failed to send keep-alive to %s:%d. Err: %s", elem.ip, elem.keep_alive_port, repr(e))
                    break
