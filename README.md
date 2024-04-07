

以`WireGuard.conf`文件的参数为模板，`result.csv`或`ips-v4.txt`文件中的数据为数据来源，批量生成WireGuard链接，输出到`output.txt`文件中。程序中内置Cloudflare WARP的54个端口(UDP)，特别适合使用WARP对应的WireGuard配置文件生成WireGuard链接。

### 一、程序运行，转为WireGuard链接的大致示意图：

<img src="images\图1.png" />

### 二、result.csv文件

由其它[warp扫描工具](https://github.com/MiSaturo/CFWarp-Windows)产生，本程序提取第一列的IP:PORT数据，而且对延迟等于或大于1000毫秒的数据剔除。当程序发现这个文件不存在，或数据长度(个数)为0时，程序才寻找ips-v4.txt文件的数据。

### 三、ips-v4.txt文件

每条数据独占一行，支持的数据格式如下：

```
1、IP => 例如：162.159.192.9、2606:4700:d1:79ab:f8c7:76fe:9449:355c
2、IP:PORT => 例如：162.159.192.9:2408、[2606:4700:d1:79ab:f8c7:76fe:9449:355c]:2408
3、CIDR => 例如：162.159.192.0/24、2606:4700:d0::/48
```

注意：

- IPv4 CIDR的，先生成CIDR范围内所有的IP地址(主机IP)，最后生成WireGuard链接。
- IPv6 CIDR的，先生成最多500个CIDR范围内、随机不重复的IPv6地址，最后生成WireGuard链接。
- 纯IP地址的，先直接添加端口，最后生成WireGuard链接。

- 带端口的IP地址，就直接生成WireGuard链接。

### 四、哪些情况才使用程序内置的端口？

```
1、ip => 162.159.192.9、2606:4700:d1:79ab:f8c7:76fe:9449:355c
2、CIDR => 162.159.192.0/24、2606:4700:d0::/48
```

### 五、温馨提示：

目前支持WireGuard协议前缀的链接，只有[新版v2rayN客户端](https://github.com/2dust/v2rayN/releases)支持使用。WireGuard链接的格式如下：

```
wireguard://OOrigZsSjw2YaY4urjbbU4%2FBNOZKXqW6EYNm8XKLtkU%3D@162.159.192.127:7152/?publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&address=172.16.0.2%2F32%2C2606%3A4700%3A110%3A82ce%3Abdeb%3Ae72d%3A572a%3Ae280%2F128&mtu=1280#162.159.192.127%3A7152
```