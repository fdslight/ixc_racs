#!/usr/bin/env python3
import socket

import pywind.evtframework.handlers.udp_handler as udp_handler


class udp_tunnel(udp_handler.udp_handler):
    def init_func(self, creator, address, is_ipv6=False):
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
        return self.dispatcher.encrypt

    @property
    def decrypt(self):
        return self.dispatcher.decrypt

    def udp_readable(self, message, address):
        rs = self.decrypt.unwrap(message)
        if not rs: return

        user_id, msg = rs
        if not self.dispatcher.user_exists(user_id): return

        self.dispatcher.update_user_conn(user_id, self.fileno, address)
        print(user_id)
        # 如果为空包,那么回一个相同的数据包,保持UDP心跳
        if not msg:
            self.sendto(message, address)
            return

        self.dispatcher.handle_msg_from_tunnel(user_id, msg)

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
