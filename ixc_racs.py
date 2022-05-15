#!/usr/bin/env python3
import sys, getopt, os, signal, json, time

BASE_DIR = os.path.dirname(sys.argv[0])

if not BASE_DIR: BASE_DIR = "."

sys.path.append(BASE_DIR)

PID_FILE = "/tmp/ixc_racs.pid"
LOG_FILE = "/tmp/ixc_racs.log"
ERR_FILE = "/tmp/ixc_racs_error.log"

import pywind.evtframework.evt_dispatcher as dispatcher
import pywind.lib.configfile as configfile

import acs.handlers.tundev as tundev
import acs.handlers.tunnels as tunnels

import acs.lib.racs as racs
import acs.lib.logging as logging
import acs.lib.proc as proc

import acs.lib.crypto as crypto
import acs.lib.rule as rule


class racs_d(dispatcher.dispatcher):
    __configs = None
    __debug = None
    __udp6_fileno = -1
    __udp_fileno = -1

    __tundev_fileno = -1

    __DEVNAME = "ixcracs"

    __racs = None

    __encrypt = None
    __decrypt = None

    __users = None
    __rule_manager = None

    def netpkt_sent_cb(self, _id: bytes, byte_data: bytes, _from: int):

        # 如果数据来源于LAN那么发送到TUN设备
        if _from == racs.FROM_LAN:
            self.get_handler(self.__tundev_fileno).send_msg(byte_data)
            return

        if _id not in self.__users: return

        user = self.__users[_id]
        address = user["address"]
        fileno = user["fileno"]

        if not address: return
        self.get_handler(fileno).send_msg(_id, address, byte_data)

    def init_func(self, debug, configs):
        self.create_poll()

        self.__configs = configs
        self.__debug = debug

        self.__racs = racs.racs(self.netpkt_sent_cb)
        self.__rule_manager = rule.rule_manager()

        signal.signal(signal.SIGINT, self.__exit)
        signal.signal(signal.SIGUSR1, self.__handle_user_change_signal)

        sec_config = self.__configs["security"]
        conn_config = self.__configs["listen"]
        enable_ipv6 = bool(int(conn_config["enable_ipv6"]))
        listen_port = int(conn_config["listen_port"])

        listen_ip = conn_config["listen_ip"]
        listen_ip6 = conn_config["listen_ip6"]

        listen = (listen_ip, listen_port,)
        listen6 = (listen_ip6, listen_port)

        self.__encrypt = crypto.encrypt(sec_config["key"])
        self.__decrypt = crypto.decrypt(sec_config["key"])

        self.__users = {}

        if enable_ipv6:
            self.__udp6_fileno = self.create_handler(-1, tunnels.udp_tunnel, listen6, is_ipv6=True)

        self.__udp_fileno = self.create_handler(-1, tunnels.udp_tunnel, listen, is_ipv6=False)

        self.__tundev_fileno = self.create_handler(-1, tundev.tundev, self.__DEVNAME)

        if not debug:
            sys.stdout = open(LOG_FILE, "a+")
            sys.stderr = open(ERR_FILE, "a+")

            self.racs.clog_set("/tmp/ixc_racs_stdout.log", "/tmp/ixc_racs_stderr.log")

        self.load_users()

    def myloop(self):
        io_wait = self.racs.loop()
        if not io_wait:
            self.set_default_io_wait_time(0)
        else:
            self.set_default_io_wait_time(5)

    @property
    def racs(self):
        return self.__racs

    @property
    def encrypt(self):
        return self.__encrypt

    @property
    def decrypt(self):
        return self.__decrypt

    def user_exists(self, user_id: bytes):
        return user_id in self.__users

    def update_user_conn(self, user_id, fd, address):
        user = self.__users[user_id]
        user["fileno"] = fd
        user["address"] = address

    def handle_msg_from_tunnel(self,user_id,message):
        if user_id not in self.__users: return

        self.racs.netpkt_handle(user_id, message, racs.FROM_LAN)

    def handle_ippkt_from_tundev(self, msg: bytes):
        print(len(msg))
        self.racs.netpkt_handle(bytes(16), msg, racs.FROM_WAN)

    def __os_route_add(self, address, is_ipv6=False):
        """ 操作系统路由增加
        """
        if is_ipv6:
            cmd = "ip -6 route add %s/128 dev %s" % (address, self.__DEVNAME)
        else:
            cmd = "ip route add %s/32 dev %s" % (address, self.__DEVNAME)

        os.system(cmd)

    def __os_route_del(self, address, is_ipv6=False):
        """ 操作系统路由删除
        """
        if is_ipv6:
            cmd = "ip -6 route del %s/128" % address
        else:
            cmd = "ip route del %s/32" % address

        os.system(cmd)

    def __exit(self, signum, frame):
        if self.__udp6_fileno > 0:
            self.delete_handler(self.__udp6_fileno)
        if self.__udp_fileno > 0:
            self.delete_handler(self.__udp_fileno)

        sys.exit(0)

    def __handle_user_change_signal(self, signum, frame):
        self.__access.handle_user_change_signal()

    def load_users(self):
        path = "%s/ixc_configs/users.json" % BASE_DIR

        with open(path, "r") as f: s = f.read()
        f.close()
        _list = json.loads(s)

        for dic in _list:
            rule_path = dic["rule_path"]
            key = dic["key"]
            user_id = crypto.calc_str_md5(key)
            rule_path = "%s/ixc_configs/%s" % (BASE_DIR, rule_path,)
            self.__rule_manager.load(user_id, rule_path)
            self.__users[user_id] = {
                "fileno": -1,
                "address": None,
            }

        self.add_rules()

    def reset_users(self):
        rules = self.__rule_manager.rules
        for left_ip in rules:
            user_id, right_ip, is_ipv6 = rules[left_ip]
            self.racs.rule_del(left_ip, is_ipv6)
            self.__os_route_del(left_ip, is_ipv6=is_ipv6)
        self.__users = {}
        self.__rule_manager.reset()

        self.load_users()

    def add_rules(self):
        rules = self.__rule_manager.rules
        for left_ip in rules:
            user_id, right_ip, is_ipv6 = rules[left_ip]
            self.racs.rule_add(user_id, left_ip, right_ip, is_ipv6)
            self.__os_route_add(left_ip, is_ipv6=is_ipv6)
        ''''''


def __start_service(debug):
    if not debug and os.path.isfile(PID_FILE):
        print("the acs server process exists")
        return

    if not debug:
        pid = os.fork()
        if pid != 0: sys.exit(0)

        os.setsid()
        os.umask(0)
        pid = os.fork()

        if pid != 0: sys.exit(0)
        proc.write_pid(PID_FILE)

    configs = configfile.ini_parse_from_file("%s/ixc_configs/config.ini" % BASE_DIR)
    cls = racs_d()

    if debug:
        cls.ioloop(debug, configs)
        return
    try:
        cls.ioloop(debug, configs)
    except:
        logging.print_error()

    os.remove(PID_FILE)
    sys.exit(0)


def __stop_service():
    pid = proc.get_pid(PID_FILE)

    if pid < 0:
        print("cannot found acs server process")
        return

    os.kill(pid, signal.SIGINT)


def __update_user_configs():
    pid = proc.get_pid(PID_FILE)

    if pid < 0:
        print("cannot found racs process")
        return

    os.kill(pid, signal.SIGUSR1)


def main():
    help_doc = """
    -d      debug | start | stop    debug,start or stop application
    -u      user_configs            update configs         
    """
    try:
        opts, args = getopt.getopt(sys.argv[1:], "u:m:d:", [])
    except getopt.GetoptError:
        print(help_doc)
        return
    d = ""
    u = ""

    for k, v in opts:
        if k == "-d": d = v
        if k == "-u": u = v

    if not u and not d:
        print(help_doc)
        return

    if u and u != "user_configs":
        print(help_doc)
        return

    if u:
        __update_user_configs()
        return

    if not d:
        print(help_doc)
        return

    if d not in ("debug", "start", "stop"):
        print(help_doc)
        return

    debug = False

    if d == "stop":
        __stop_service()
        return

    if d == "debug": debug = True
    if d == "start": debug = False

    __start_service(debug)


if __name__ == '__main__': main()
