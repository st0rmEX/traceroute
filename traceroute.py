import util

TRACEROUTE_MAX_TTL = 30

# Cisco traceroute port numbe
TRACEROUTE_PORT_NUMBER = 33434  

# max number of probes before giving up
PROBE_ATTEMPT_COUNT = 3

class IPv4:
    
    version: int
    header_len: int 
    tos: int        
    length: int     
    id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    cksum: int
    src: str
    dst: str

    def __init__(self, buffer: bytes):
        b = ''.join(format(byte, '08b') for byte in [*buffer])
        self.version = int(b[0:4], 2)
        self.header_len = int(b[4:8], 2) * 4
        self.tos = int(b[8:16], 2)
        self.length = int(b[16:32], 2)
        self.id = int(b[32:48], 2)
        self.flags = int(b[48:51], 2)
        self.frag_offset = int(b[51:64], 2)
        self.ttl = int(b[64:72], 2)
        self.proto = int(b[72:80], 2)
        self.cksum = int(b[80:96], 2)
        self.src = turn_into_ip(b[96:128])
        self.dst = turn_into_ip(b[128:160])




    def __str__(self) -> str:
        return f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, " + \
            f"id {self.id}, flags 0x{self.flags:x}, " + \
            f"ofsset {self.frag_offset}, " + \
            f"proto {self.proto}, header_len {self.header_len}, " + \
            f"len {self.length}, cksum 0x{self.cksum:x}) " + \
            f"{self.src} > {self.dst}"


class ICMP:
    type: int
    code: int
    cksum: int

    def __init__(self, buffer: bytes):
        b = ''.join(format(byte, '08b') for byte in [*buffer])
        self.type = int(b[0:8], 2)
        self.code = int(b[8:16], 2)
        self.cksum = int(b[16:32], 2)
        
    def __str__(self) -> str:
        return f"ICMP (type {self.type}, code {self.code}, " + \
            f"cksum 0x{self.cksum:x})"


class UDP:
    src_port: int
    dst_port: int
    len: int
    cksum: int

    def __init__(self, buffer: bytes):
        b = ''.join(format(byte, '08b') for byte in [*buffer])
        self.src_port = int(b[0:16], 2)
        self.dst_port = int(b[16:32], 2)
        self.len = int(b[32:48], 2)
        self.cksum = int(b[48:64], 2)

    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"

def turn_into_ip(buf):
            one = int(buf[0:8], 2)
            two = int(buf[8:16], 2)
            three = int(buf[16:24], 2)
            four = int(buf[24:32], 2)
            return (str(one) + '.' + str(two) + '.' + str(three) + '.' + str(four))

def traceroute(sendsock: util.Socket, recvsock: util.Socket, ip: str) \
        -> list[list[str]]:
    port_num = TRACEROUTE_PORT_NUMBER
    n = 0
    router_list = []
    address_list = {}
    addresses = {}
    for ttl in range(1, TRACEROUTE_MAX_TTL+1):
        temp_list = []
        for p in range(0, PROBE_ATTEMPT_COUNT):
            sendsock.set_ttl(ttl)
            msg = 'Potato'
            sendsock.sendto(msg.encode(), (ip, port_num + n))
            n = n+ 1
        p = 0
        while p < PROBE_ATTEMPT_COUNT:
            p = p + 1
            if recvsock.recv_select():
                buf, address = recvsock.recvfrom()
            
                if process_buffer(buf):
                    continue
                ip_header, icmp_header, udp_header, ip_sender = parse_buffer(buf)


                if IP_helper(ip_header) or ICMP_helper(icmp_header):
                    continue
                
                if ip_sender.dst != ip:
                    continue

                if check_duplicate(udp_header, ip_header, address_list, address[0]):
                    p = p - 1
                    continue
                

                if address[0] not in temp_list:
                    temp_list.append(address[0])

                if address[0] == ip:
                    router_list.append(temp_list)
                    util.print_result(temp_list, ttl)
                    return router_list
        
        router_list.append(temp_list)
        util.print_result(temp_list, ttl)
    return router_list

def process_buffer(buf):
    if len(buf) < 56:
        return True
    return False

    
def parse_buffer(buf):
    ip_buf = buf[0:20]
    ip_header = IPv4(ip_buf)
    offset = ip_header.header_len - 20

    s = 20 + offset
    e = 28 + offset
    icmp_buf = buf[s:e]
    icmp_header = ICMP(icmp_buf)

    s = 48 + offset
    e = 56 + offset
    udp_buf = buf[s:e]
    udp_header = UDP(udp_buf)

    s = 28+offset
    e = 48 + offset
    ip_sender_buf = buf[s:e]
    ip_sender = IPv4(ip_sender_buf)
    return ip_header, icmp_header, udp_header, ip_sender

def check_duplicate(udp_header, ip_header, address_list, address):
    hash = str(udp_header.dst_port)
    if hash in address_list:
        return True
    address_list[hash] = 1
    return False

def IP_helper(header):
    if header.proto != 1:
        return True
    return False

def ICMP_helper(header):
    if header.type != 11 and header.type != 3:
        return True
    if header.type == 11 and header.code != 0:
        return True
    return False

if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)