#!/usr/bin/env python3
import socket, time

import pywind.evtframework.handlers.udp_handler as udp_handler
import pywind.evtframework.handlers.tcp_handler as tcp_handler

import acs.lib.crypto as crypto
import acs.lib.logging as logging


class udp_tunnel(udp_handler.udp_handler):
    __encrypt = None
    __decrypt = None

    def init_func(self, creator, address, is_ipv6=False):
        self.__encrypt = crypto.encrypt(self.dispatcher.crypt_key, is_tcp=False)
        self.__decrypt = crypto.decrypt(self.dispatcher.crypt_key, is_tcp=False)

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_DGRAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        self.set_socket(s)
        self.bind(address)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    @property
    def encrypt(self):
        return self.__encrypt

    @property
    def decrypt(self):
        return self.__decrypt

    def udp_readable(self, message, address):
        rs = self.decrypt.unwrap(message)
        if not rs: return

        user_id, msg = rs
        if not self.dispatcher.user_exists(user_id): return

        self.dispatcher.update_user_conn(user_id, self.fileno, address)
        # 如果为空包,那么回一个相同的数据包,保持UDP心跳
        if not msg:
            self.sendto(message, address)
            return

        self.dispatcher.handle_msg_from_tunnel(self.fileno, user_id, msg, address)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_timeout(self):
        pass

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def send_msg(self, _id, address, message: bytes):
        wrap_data = self.encrypt.wrap(_id, message)

        self.add_evt_write(self.fileno)
        self.sendto(wrap_data, address)


class tcp_tunnel_listener(tcp_handler.tcp_handler):
    def init_func(self, creator, address, is_ipv6=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.set_socket(s)
        self.bind(address)
        self.listen(10)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def tcp_accept(self):
        while 1:
            try:
                cs, caddr = self.accept()
                self.create_handler(self.fileno, tcp_tunnel_handler, cs, caddr)
            except BlockingIOError:
                break
            ''''''

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class tcp_tunnel_handler(tcp_handler.tcp_handler):
    __caddr = None

    __encrypt = None
    __decrypt = None

    __header_ok = None
    __payload_len = None
    __crc32 = None
    __user_id = None
    __update_time = None

    def init_func(self, creator_fd, cs, caddr):
        self.__caddr = caddr
        self.__header_ok = False
        self.__payload_len = 0
        self.__user_id = b""
        self.__update_time = time.time()

        self.__encrypt = crypto.encrypt(self.dispatcher.crypt_key, is_tcp=True)
        self.__decrypt = crypto.decrypt(self.dispatcher.crypt_key, is_tcp=True)

        self.set_socket(cs)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.set_timeout(self.fileno, 10)

        logging.print_general("connected", self.__caddr)

        return self.fileno

    def parse_header(self):
        if self.reader.size() < crypto.TCP_HEADER_SIZE: return

        self.__crc32, self.__payload_len = self.__decrypt.unwrap_tcp_header(self.reader.read(crypto.TCP_HEADER_SIZE))
        self.__header_ok = True

    def tcp_readable(self):
        if not self.__header_ok:
            self.parse_header()
        if not self.__header_ok:
            return

        if self.reader.size() < self.__payload_len: return

        try:
            user_id, msg = self.__decrypt.unwrap_tcp_body(self.reader.read(self.__payload_len), self.__crc32)
        except crypto.TCPPktWrong:
            self.delete_handler(self.fileno)
            return

        if not self.__user_id:
            self.__user_id = user_id
            self.dispatcher.update_user_conn(user_id, self.fileno, self.__caddr)

        if self.__user_id != user_id:
            self.delete_handler(self.fileno)
            return

        self.__header_ok = False
        self.__update_time = time.time()

        if not msg:
            self.send_msg(self.__user_id, self.__caddr, b"")
            return

        self.dispatcher.handle_msg_from_tunnel(self.fileno, user_id, msg, self.__caddr)
        self.tcp_readable()

    def tcp_writable(self):
        self.remove_evt_write(self.fileno)

    def tcp_timeout(self):
        t = time.time()
        v = t - self.__update_time

        if v > 180:
            logging.print_general("timeout", self.__caddr)
            self.delete_handler(self.fileno)
            return

        self.set_timeout(self.fileno, 10)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        logging.print_general("disconnected", self.__caddr)
        self.unregister(self.fileno)
        self.close()

    def send_msg(self, _id, address, message: bytes):
        if not self.__user_id: return
        if _id != self.__user_id: return

        wrap_data = self.__encrypt.wrap(_id, message)

        self.writer.write(wrap_data)
        self.add_evt_write(self.fileno)
