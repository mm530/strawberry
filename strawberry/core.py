import socket
import os
from ctypes import *
import struct
import logging


SOCKET_PROTOCOL = socket.IPPROTO_ICMP
HOST = socket.gethostbyname(socket.gethostname())
if os.name == 'nt':
    SOCKET_PROTOCOL = socket.IPPROTO_IP

class IP(Structure):
    _fields_ = [
        ('ihl', c_ubyte, 4),  # 字节偏移
        ('version', c_ubyte, 4),  # 版本号
        ('tos', c_ubyte),  # 头长度
        ('len', c_ushort),  # 服务类型
        ('id', c_ushort),  # IP数据包总长
        ('offset', c_ushort),  # 片偏移
        ('ttl', c_ubyte),  # 生存时间
        ('protocol_num', c_ubyte), # 协议类型
        ('sum', c_ushort),  #
        ('src', c_ulong),  # 源IP
        ('dst', c_ulong),  # 目标IP
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # 协议字段与协议名称对应
        self.protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        # 可读性更强的IP地址
        self.src_address = socket.inet_ntoa(struct.pack('<L', self.src))
        self.dst_address = socket.inet_ntoa(struct.pack('<L', self.dst))
        # 协议类型
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)


class ICMP(Structure):
    _fields_ = [
        ('type', c_ubyte),  # 类型=3
        ('code', c_ubyte),  # 代码值
        ('checksum', c_ushort),  #
        ('unused', c_ushort),
        ('next_hop_mtu', c_ushort),
    ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass

class Sniffer:
    m_protocl = ['ICMP', 'TCP', 'UDP']
    m_tcp_sport = list(range(0, 65536))
    m_tcp_dport = list(range(0, 65536))
    m_ip_src = ['*.*.*.*']   # *.*.*.*代表所有IP，如果只显示特定IP，则不能包含这个
    m_ip_dst = ['*.*.*.*']

    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, SOCKET_PROTOCOL)
        self.s.bind((HOST, 0))
        self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) # 捕获数据包中包含IP头
        if os.name == 'nt':  # Windows设置IOCTL启用混杂模式
            self.s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def close(self):
        # linux平台只支持嗅探ICMP数据包，windows则允许嗅探传输层的所有协议
        if os.name == 'nt':
            self.s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)  # 关闭混杂模式

    def run(self):
        while 1:
            raw_buffer = self.s.recvfrom(65565)[0]
            ip_header = self.unpack_ip(raw_buffer)
            self.unpack_icmp(raw_buffer, ip_header)

            # TODO

    def unpack_ip(self, raw_buffer):
        ip_header = IP(raw_buffer[0:20])
        print('Protocol: %s %s -> %s' % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))

        return ip_header

    def unpack_icmp(self, raw_buffer, ip_header):
        '''解析icmp数据包，并返回，返回的原因是可能后期要保存到磁盘中'''
        if ip_header.protocol == 'ICMP':
            # 计算ICMP数据包的开始位置
            offset = ip_header.ihl * 4
            buf = raw_buffer[offset:offset + sizeof(ICMP)]
            # 解析ICMP数据包
            icmp_header = ICMP(buf)
            print('ICMP -> Type: %d Code: %d' % (icmp_header.type, icmp_header.code))
            return icmp_header
        else:
            return None

    def unpack_tcp(self, raw_buffer, ip_header):
        # TODO
        pass

    def unpack_udp(self, raw_buffer, ip_header):
        # TODO
        pass

    def save_packet(self):
        # TODO
        pass