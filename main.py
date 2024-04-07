from urllib.parse import quote_plus
from typing import Union
import ipaddress
import random
import csv
import re
import os
import sys


# 读取WireGuard.conf文件中WireGuard参数
def read_wireguard_file(filename: str) -> dict:
    if not os.path.exists(filename):
        return dict()
    with open(filename, mode='r', encoding='utf-8') as file:
        data = file.readlines()
        parameters = dict()
        for parameter in data:
            if ("[" not in parameter) and ("]" not in parameter) and ("#" not in parameter) and parameter:
                key, value = parameter.strip().replace(' ', '').split('=', 1)
                if key == "Address" and key in parameters:
                    value = parameters.get('Address') + ',' + value
                    parameters.update({key: value})
                elif key == "AllowedIPs" and key in parameters:
                    value = parameters.get('AllowedIPs') + ',' + value
                    parameters.update({key: value})
                else:
                    parameters.update({key: value})
        return parameters


# 读取result.csv文件中，第一列的内容，剔除延迟等于大于1000ms的，以及第一行标题的内容
def read_result_csv(filename: str) -> list:
    if not os.path.exists(filename):
        return []
    with open(filename, mode='r', encoding='utf-8', newline='') as csvfile:
        # 创建 CSV 读取器对象
        reader = csv.reader(csvfile)
        # 跳过标题行
        next(reader)
        pattern = re.compile(r'(\d+)\s*(ms)*')
        # 创建空列表用于存储处理后的数据
        ip_with_port_li = []
        # 遍历每一行数据
        for row in reader:
            # 对倒数第一列字符串操作，使用正则表达式提取数字+ms格式的字符串
            match = pattern.search(row[-1])
            # 如果找到匹配项
            if match:
                # 提取数字部分并转换为整数
                milliseconds = int(match.group(1))
                # 如果小于1000毫秒，则将该行的第一列数据添加到处理后的数据中
                if milliseconds < 1000:
                    ip_with_port_li.append(row[0])
        return ip_with_port_li


# 判断是否为IPv4地址？
def is_ipv4_address(address: str) -> bool:
    try:
        ipaddress.IPv4Address(address)
        return True
    except ipaddress.AddressValueError:
        return False


# 判断是否为IPv6地址？
def is_ipv6_address(address: str) -> bool:
    try:
        ipaddress.IPv6Address(address)
        return True
    except ipaddress.AddressValueError:
        return False


# 生成IPv4 CIDR范围内，所有IPv4地址
def generate_ipv4_in_network(cidr: str) -> Union[list, Exception]:
    try:
        network = ipaddress.IPv4Network(cidr)  # 尝试解析 CIDR
        ips = []
        # 生成 CIDR 范围内的所有 IP 地址
        for ipv4_address in network.hosts():
            ips.append(str(ipv4_address))
        return ips
    except ValueError:
        return ValueError("Invalid CIDR notation")


# 生成IPv6 CIDR范围内，指定数量、随机的IPv6地址
def generate_random_ipv6_in_network(cidr: str, count=500) -> Union[list, Exception]:
    try:
        network = ipaddress.IPv6Network(cidr)
        ipv6_address = []
        for i in range(count):
            random_int = random.randint(int(network.network_address), int(network.broadcast_address))
            random_addr = ipaddress.IPv6Address(random_int)
            if random_addr not in ipv6_address:
                ipv6_address.append(str(random_addr))
        return ipv6_address
    except ValueError:
        return ValueError("Invalid CIDR notation")


# 处理从ips-v4.txt文件中，读取到每行数据
def processed_ip_address(address: str) -> list:
    """
    ipv4、ipv6地址，直接添加到ips中，
    cidr的，先生成IP地址，然后添加到ips中，
    ip:port的地址，直接添加ips中。
    param address: 传入的单个ipv4/ipv6/ipv4 cidr/ipv6 cidr/ip:port
    return ips: 由多个地址组成的ips列表
    """
    ips = []
    if is_ipv4_address(address):  # 判断是否为IPv4地址
        ips.append(address)
    elif is_ipv6_address(address):  # 判断是否为IPv6地址
        ips.append(address)
    else:
        ipv4_addresses = generate_ipv4_in_network(address)  # 尝试生成IPv4地址
        if isinstance(ipv4_addresses, list):
            ips.extend(ipv4_addresses)
        else:
            ipv6_addresses = generate_random_ipv6_in_network(address)  # 尝试生成IPv6地址
            if isinstance(ipv6_addresses, list):
                ips.extend(ipv6_addresses)
            else:
                ips.append(parse_ip_address_with_port(address))
    return ips


# 解析(提取)IPv4:PORT地址或IPv6:PORT地址
def parse_ip_address_with_port(address: str) -> str:
    # 注意：这两个正则只匹配格式，可能不适配其它程序，需要对ipv4、ipv6部分的字符串进行验证
    ipv4_with_port_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})$'
    ipv6_with_port_pattern = r'^\[?([0-9a-fA-F:]+)\]?:\d{1,5}$'
    for pattern in [ipv4_with_port_pattern, ipv6_with_port_pattern]:
        match = re.search(pattern, address)
        if match:
            return match.group(0)


# 读取ips-v4.txt的内容到列表中
def read_ips_file(filename: str) -> list:
    if not os.path.exists(filename):
        return []
    with open(filename, mode='r', encoding='utf-8') as f:
        return [f'{address.strip()}' for address in f.readlines() if address.strip() != '']


# 添加端口(默认全部端口54个)
def add_port(address: str, ports: list, random_count=54) -> list:
    select_random_ports = random.sample(ports, random_count)
    ip_with_port_li = []
    # 已经是由端口的地址，就直接添加到ip_with_port_li中
    if ('[' in address and ']' in address and ':' in address) or (address.count(':') == 1 and ':' in address):
        ip_with_port_li.append(address)
    else:
        address = address if is_ipv4_address(address) else f"[{address}]"
        for port in select_random_ports:
            ip_with_port_li.append(f"{address}:{port}")
    return ip_with_port_li


# 拼接wireguard链接
def splicing_wireguard_link(public_key: str, private_key: str, interface_address: str,
                            interface_mtu: str, reserved: str, socket_address: str) -> str:
    if reserved == '':
        wireguard_link = f"wireguard://{quote_plus(private_key)}@{socket_address}/?publickey={quote_plus(public_key)}&address={quote_plus(interface_address)}&mtu={interface_mtu}#{quote_plus(socket_address)}"
    else:
        wireguard_link = f"wireguard://{quote_plus(private_key)}@{socket_address}/?publickey={quote_plus(public_key)}&reserved={quote_plus(reserved)}&address={quote_plus(interface_address)}&mtu={interface_mtu}#{quote_plus(socket_address)}"
    return wireguard_link


# 将最后生成wireguard链接写入到txt文件中
def write_to_output_file(filename: str, wireguard_list: list) -> None:
    with open(filename, mode='w', encoding='utf-8') as file:
        file.writelines([f"{item}\n" for item in wireguard_list])


if __name__ == '__main__':
    wireguard_file = 'WireGuard.conf'
    input_csv_file = 'result.csv'
    input_ips_v4_file = 'ips-v4.txt'

    ports = [854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968, 987, 988,
             1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233,
             5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886, 2408, 500, 4500, 1701]
    # 读取wireguard配置文件的参数
    wireguard_parameters = read_wireguard_file(wireguard_file)

    # 分别获取wireguard的主要参数：PublicKey、PrivateKey、Address、MTU、Reserved
    PublicKey = wireguard_parameters.get('PublicKey')
    PrivateKey = wireguard_parameters.get('PrivateKey')
    Address = wireguard_parameters.get('Address')
    MTU = wireguard_parameters.get('MTU', '1280')
    Reserved = wireguard_parameters.get('Reserved', '')

    # 读取result.csv的第一列IP:PORT数据
    ip_with_port_li = read_result_csv(input_csv_file)
    results = []
    if len(ip_with_port_li) > 0:  # 能读取result.csv的第一列ip:port数据，就有一个列表长度
        for ip_with_port in ip_with_port_li:
            wireguard = splicing_wireguard_link(socket_address=ip_with_port, public_key=PublicKey,
                                                private_key=PrivateKey, interface_address=Address,
                                                interface_mtu=MTU, reserved=Reserved)
            results.append(wireguard)
    else:  # 读取ips-v4.txt文件的地址(IPv4/IPv6、IPv4 CIDR/IPv6 CIDR、IP:PORT)
        random_count = input(f"设置随机端口数(默认为10，可选数字范围[1,{len(ports)}])：")
        try:
            random_count = int(random_count)
            if random_count < 1 or random_count > 54:
                raise ValueError
        except ValueError:
            random_count = 10
        line_list = read_ips_file(input_ips_v4_file)  # 读取ips-v4.txt文件中的数据
        ips = []
        if len(line_list) > 0:
            for line in line_list:
                ips.extend(processed_ip_address(line))  # 处理从txt文件中读取到内容，是ip:port、cidr、ip的处理方法
        ips_with_ports = []
        for ip in ips:
            ip_port_li = add_port(ip, ports, random_count=random_count)
            for ip_with_port in ip_port_li:
                if ip_with_port not in ips_with_ports:
                    ips_with_ports.append(ip_with_port)
                    wireguard = splicing_wireguard_link(socket_address=ip_with_port, public_key=PublicKey,
                                                        private_key=PrivateKey, interface_address=Address,
                                                        interface_mtu=MTU, reserved=Reserved)
                    results.append(wireguard)
    # 打印拼接成到wireguard链接
    for wireguard_link in results[:100]:
        print(wireguard_link)
    if len(results) > 100:
        print(f"↪ 省略未显示的WireGuard链接。")
    # 将wireguard链接写入
    output_file = "output.txt"
    write_to_output_file(output_file, results)
    print(f"要查看全部WireGuard链接，前往{output_file}文件中查看。")
    input("按Enter键退出程序: ")
    sys.exit()
