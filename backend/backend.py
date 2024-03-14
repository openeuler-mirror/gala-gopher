import http.client
import os
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from collections import deque
from datetime import datetime
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
               "mobile": "", "deptId": 100, "postIds": [], "status": 0, "remark": ""}
login_headers = {"tenant-id": "1", "Content-Type": "application/json",
                 "User-Agent": "Mozillla/5.0 Chrome/111.0.0.0 Safari/537.36 Edg/111.0.1661.54"}
body_of_send_backend_request = {"body": "body of send request to backend"}
body_of_send_keep_alive_request = {"body": "body of send keep-alive request to backend"}
batch_write_disk = ""
operate_url_prefix = "/admin-api/system/user/"
keep_alive_url_prefix = "/a-ops/keepalive"
api_servers = []
keep_alive_servers = []
keep_alive_wait_port = ""
is_batch_write_disk = 0

update_file_deque = deque()

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

def send_response(self, context, code):
    context_str = bytes(context, 'utf-8')
    self.send_response(code)
    self.send_header('Content-Type', 'application/json')
    self.send_header('Content-Length', len(context_str))
    self.end_headers()
    self.wfile.write(context_str)


class API_SERVER:
    def __init__(self, is_auth, ip, url_port):
        self.is_auth = is_auth
        self.ip = ip
        self.url_port = url_port
        self.token = ""
        self.token_access_time = ""

class KEEPALIVE_SERVER:
    def __init__(self, ip, keep_alive_port):
        self.ip = ip
        self.keep_alive_port = keep_alive_port


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
        send_response(self, '{"data":0, "msg":"received keep-alive!"}', 200)


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
        content_len = int(self.headers.get('Content-Length'))
        request_body = self.rfile.read(content_len).decode('utf-8')

        logging.debug("received %s %s request %s", self.client_address, operate, request_body)
        file = "/home/file_" + self.client_address[0] + ".txt"
        if operate == 'create':
            try:
                os.mknod(file)
            except Exception as e:
                pass

            # 发送请求给下游
            self.send_request_next(operate, request_body)
        elif operate == 'update':
            try:
                fp = open(file, 'a', encoding='utf-8')
                file_size = 1024 * 5
                while fp.tell() < file_size:
                    fp.write("update")
                fp.close()
            except Exception as e:
                logging.debug("failed to update update_file. Err: %s", repr(e))

            if is_batch_write_disk == 1:
                batch_file = "/home/batch_update_file_" + str(random_number()) + ".txt"

                # 批量写盘操作
                cmd = "dd if=/dev/zero of=" + batch_file + " bs=50 count=" + str(1000000)
                os.system(cmd)
                os.remove(batch_file)
            self.send_request_next(operate, request_body)
        elif operate == 'delete':
            try:
                os.remove(file)
            except Exception as e:
                pass

            self.send_request_next(operate, request_body)
        else:
            send_response(self, '{"data":-1, "msg":"invalid request!"}', 403)

    # 发送数据给下游，backend or java_app
    def send_request_next(self, operate, body):
        if len(api_servers):
            i = random.randint(0, len(api_servers) - 1)
            element = api_servers[i]
            ip = element.ip
            port = element.url_port
            is_auth = element.is_auth

            try:
                conn = http.client.HTTPConnection(ip, port, timeout=30)
                # 下游是backend
                if is_auth == 0 and port > 0:
                    header = {"Content-Type": "application/json",
                              "User-Agent": "Mozillla/5.0 Chrome/111.0.0.0 Safari/537.36 Edg/111.0.1661.54"}

                    conn.request("PUT", build_url(ip, port, operate_url_prefix, operate, ""), body, header)
                    response = conn.getresponse()
                    send_response(self, response.read().decode('utf-8'), response.status)
                # 下游是java_app
                elif is_auth == 1 and port > 0:
                    # 获取token或者每隔2min刷新token
                    if not element.token or (datetime.now() - element.token_access_time).seconds >= 120:
                        conn.request("POST",
                                     build_url(element.ip, element.url_port, "/admin-api/system/auth/login", "", ""),
                                     user_login, login_headers)
                        response = conn.getresponse()
                        msg = response.read()

                        data = json.loads(msg)["data"]
                        response_token = data["accessToken"]
                        element.token = response_token
                        element.token_access_time = datetime.now()
                        logging.debug("login to %s:%d, Token is %s", ip, port, response_token)

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
                        user_id = json.loads(context)["data"]
                        code = json.loads(context)["code"]
                        if code == 0:
                            send_response(self, '{"data":'+ str(user_id) + ', "msg":"create success!"}', 200)
                        else:
                            send_response(self, '{"data":-1, "msg":"create failed!"}', 400)
                    elif operate == 'update':
                        user_id = json.loads(body)["data"]
                        user_update["id"] = user_id
                        user_update["username"] = random_name()
                        user_create["nickname"] = random_name()
                        conn.request("PUT", build_url(ip, port, operate_url_prefix, "update", ""),
                                     json.dumps(user_update),
                                     token_header)
                        response = conn.getresponse()
                        context = response.read()
                        logging.debug("update response is %s", context.decode("utf-8"))
                        code = json.loads(context)["code"]
                        if code == 0:
                            send_response(self, '{"data":'+ str(user_id) + ', "msg":"update success!"}', 200)
                        else:
                            send_response(self, '{"data":-1, "msg":"update failed!"}', 400)
                    elif operate == 'delete':
                        user_id = json.loads(body)["data"]
                        conn.request("DELETE",
                                         build_url(ip, port, operate_url_prefix, "delete", user_id),
                                         "", token_header)
                        response = conn.getresponse()
                        context = response.read()
                        code = json.loads(context)["code"]
                        if code == 0:
                            send_response(self, '{"data":'+ str(user_id) + ', "msg":"delete success!"}', 200)
                        else:
                            send_response(self, '{"data":-1, "msg":"delete failed!"}', 400)
            except Exception as e:
                logging.debug("failed to send request to %s:%d. Err: %s", ip, port, repr(e))
            finally:
                conn.close()


if __name__ == "__main__":
    with open('backend.json', 'r') as backend_file:
        backend_data = json.load(backend_file)
        PORT = backend_data['port']
        next_array = backend_data['next']
        keep_alive_wait_port = backend_data['keep_alive_wait_port']

        for elem in next_array:
            if elem["url_port"] > 0 and elem["keep_alive_port"] <= 0:
                e = API_SERVER(elem["is_auth"], elem["ip"], elem["url_port"])
                api_servers.append(e)

            if elem["keep_alive_port"] > 0 and elem["url_port"] <= 0:
                e = KEEPALIVE_SERVER(elem["ip"], elem["keep_alive_port"])
                keep_alive_servers.append(e)

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
    if len(keep_alive_servers):
        while True:
            for elem in keep_alive_servers:
                try:
                    conn = http.client.HTTPConnection(elem.ip, elem.keep_alive_port, timeout=30)
                    conn.request("POST", build_url(elem.ip, elem.keep_alive_port, keep_alive_url_prefix, "", ""),
                                 json.dumps(body_of_send_keep_alive_request))
                    response = conn.getresponse()
                    context = response.read()
                    logging.debug("successfully send keep-alive to %s:%d, response data is %s", elem.ip,
                                  elem.keep_alive_port, context)
                    conn.close()
                except Exception as e:
                    logging.debug("failed to send keep-alive to %s:%d. Err: %s", elem.ip, elem.keep_alive_port, repr(e))
            time.sleep(30)
