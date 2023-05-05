import binascii
import socket
import struct
import time

from cache_class import Record, Cache

PORT = 53
LOCAL_HOST = '127.0.0.1'
REMOTE_HOST = 'ns1.google.com'
REMOTE_PORT = 53


def get_name(data: bytes, offset=0, full_domain_name=b'') -> tuple:
    """Определяет имя домена из данных"""
    while data[offset] != 0:
        i = data[offset]
        if data[offset] != 192:
            length = data[offset]
            domain_prefix = data[offset + 1:offset + length + 1]
            full_domain_name += domain_prefix + b'\x00'
            offset += length + 1
        elif data[offset] == 192:
            off = data[offset + 1]
            label = off - 12
            domain_prefix, _ = get_name(data, label, b'')
            full_domain_name += domain_prefix
            offset += 2
            return full_domain_name, offset
    offset += 1
    return full_domain_name, offset


def get_type(data: bytes, offset: int):
    """Определяет тип ресурсной записи"""
    code = data[offset + 1]
    match code:
        case 1:
            return 'A', offset + 4
        case 28:
            return 'AAAA', offset + 4
        case 5:
            return 'CNAME', offset + 4
        case 2:
            return 'NS', offset + 4
        case 6:
            return 'SOA', offset + 4
    return '', 0


def unpack_a(data: bytes, count: int, cache: Cache, now: float, offset=0):
    """Парсит запись типа А и AAAA(IP 4 версии и IP 6 версии)"""
    for i in range(count):
        domain_name, offset = get_name(data, offset)
        type_data, offset = get_type(data, offset)
        ttl = int(binascii.hexlify(data[offset + 1:offset + 4]).decode(),
                  16)
        offset += 6
        if type_data == 'A':
            ip = data[offset:offset + 4]
            offset += 4
        else:
            ip = data[offset:offset + 16]
            offset += 16
        key = (domain_name, type_data)
        if key not in cache.cache.keys():
            cache.put(Record(domain_name, type_data, data, ttl + now, ip))
        else:
            cache.cache[key]['valid'].append((ip, ttl + now))


def unpack_ns(data: bytes, cache: Cache, now: float, offset=0, count=1):
    """Парсит запись типа NS"""
    for i in range(count):
        domain_name, offset = get_name(data, offset)
        type_data, offset = get_type(data, offset)
        ttl = int(binascii.hexlify(data[offset + 1:offset + 5]).decode(),
                  16)
        offset += 4
        offset += 2
        server_name, offset = get_name(data, offset)
        key = (domain_name, type_data)
        if key not in cache.cache.keys():
            cache.put(Record(domain_name, type_data, data, ttl + now,
                             server=server_name))
        else:
            cache.cache[key]['servers'].append((server_name, ttl + now))
    return offset


def correct_ip_data(servers, cache: Cache):
    """Формируем ответную записи типа А и АААА для помещения в кэш"""
    remote_data = b''
    for server in servers:
        type = 'A'
        code = b'\x01'
        data_len = b'\x00\x04'
        for i in range(2):
            key = (server[0], type)
            if key in cache.cache.keys():
                domain_parts = server[0].split(b'\x00')[:-1]
                for part in domain_parts:
                    remote_data += struct.pack('B', len(part)) + part
                remote_data += b'\x00\x00' + code + b'\x00\x01\xc0\x0c\x00' + \
                               code + b'\x00\x01'
                ips = cache.cache[key]['valid']
                for pair in ips:
                    ip, ttl = pair
                    remote_data += struct.pack('I', round(ttl)) + data_len
                    remote_data += ip
                cache.cache[key]['data'] = remote_data
            remote_data = b''
            type = 'AAAA'
            code = b'\x1c'
            data_len = b'\x00\x10'


def create_answer(record_type: str, key: tuple, cache: Cache, id: bytes):
    """Формирует ответную запись, полученную из кэша"""
    if record_type == 'A' or record_type == 'AAAA':
        answer_ips = [pair[0] for pair in cache.cache[key]['valid']]
        answer_data = cache.cache[key]['data']
        answer_count = len(answer_ips)
        answer_header = id + b'\x85\x00\x00\x01\x00' + \
                        struct.pack('b', answer_count) + \
                        b'\x00\x00\x00\x00'
        return answer_header + answer_data
    elif record_type == 'NS':
        answer_data = cache.cache[key]['data']
        servers = cache.cache[key]['servers']
        answer_count = len(servers)
        add_count = 0
        for server in servers:
            ip_key = (server[0], 'A')
            if ip_key in cache.cache.keys():
                add_count += 1
            ip_key = (server[0], 'AAAA')
            if ip_key in cache.cache.keys():
                add_count += 1
        answer_header = id + b'\x85\x00\x00\x01\x00' + \
                        struct.pack('b', answer_count) + \
                        b'\x00\x00\x00' + struct.pack('b', add_count)
        return answer_header + answer_data


def remote_request(deliver_data: bytes, offset: int, data_type: str,
                   cache: Cache):
    """Обращается к удаленному авторитетному серверу"""
    global now
    remote_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    remote_data = ''
    try:
        remote_server.sendto(deliver_data, (REMOTE_HOST, PORT))
        remote_data, _ = remote_server.recvfrom(1024)
        now = time.time()
    except:
        print("FAILED CONNECTION TO REMOTE SERVER")
    header, data = remote_data[:12], remote_data[12:]
    request_count = header[5]
    answer_count = header[7]
    auth_count = header[9]
    add_count = header[11]

    if data_type == 'A' or data_type == 'AAAA':
        unpack_a(data, answer_count, cache, now, offset)
    elif data_type == 'NS':
        offset = unpack_ns(data, cache, now, offset, answer_count)
        unpack_a(data, add_count, cache, now, offset)
    return remote_data


def response():
    local_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    local_server.bind((LOCAL_HOST, PORT))
    cache = Cache()
    cache.clean_cache()
    local_address = ''
    local_data = ''
    print(f'Listening {LOCAL_HOST}:{PORT}')
    while True:
        try:
            local_data, local_address = local_server.recvfrom(1024)
        except:
            print("FAILED READ REQUEST")
        local_header, slice_data = (local_data[:12], local_data[12:])
        head_id = local_header[0:2]
        request_name, offset = get_name(slice_data)
        data_type, offset = get_type(slice_data, offset)
        key = (request_name, data_type)
        try:
            if key in cache.cache.keys():
                print("Get from cache")
                remote_data = create_answer(data_type, key, cache, head_id)
            else:
                remote_data = remote_request(local_data, offset, data_type, cache)
                if data_type == 'NS':
                    correct_ip_data(cache.cache[key]['servers'], cache)
                cache.write()
            try:
                local_server.sendto(remote_data, local_address)
            except:
                print('SENDING ERROR')
        except KeyboardInterrupt:
            cache.write()


if __name__ == '__main__':
    response()
