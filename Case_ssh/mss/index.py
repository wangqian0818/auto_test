# coding:utf-8
# 此文件的参数配置均与用例强相关，与执行环境无关

from common import baseinfo

pcap_sip = baseinfo.clientOpeIp
pcap_dip = baseinfo.serverOpeIp
ciface = baseinfo.pcapSendIface
siface = baseinfo.pcapReadIface
strip = baseinfo.strip

# 报文发送,读取和预期结果
# 列表里面的命令依次为：
# 发送端：发送报文接口，发送报文数量，发送报文名称；
# 抓包：接口名称，过滤规则，抓包数量，报文命名（以用例名称.pcap命名）
# 报文读取：保存的报文名称，要读取的包的序号；这里读取的报文名称和上面抓包的保存报文名称应该一致
# 期望结果：预期结果（协议字段），是否有偏差（保留），偏差值（保留）
pkt1_cfg = {
    "send": [ciface, 1, "0001_TCP_ETH_IPV4_TCP.pcap"],
    "capture": [siface, f'tcp and host {pcap_dip}', 1, "test_mss_a1_01.pcap", "test_mss_a1_02.pcap"],
    "read": ["test_mss_a1_01.pcap", "test_mss_a1_02.pcap", 0],
    "expect1": ['1460\n', 0, 0],
    "expect2": ['500\n', 0, 0]
}
# 配置下发
# 列表里面的顺序依次为：配置命令，查询命令，预期结果
case1_step1 = {
    "step1": ["export cardid=0&&defconf --tcpmss 500", "defconf --show", 'tcp mss: 500'],
    "step2": ["export cardid=1&&defconf --tcpmss 500", "defconf --show", 'tcp mss: 500']
}
case1_step2 = {
    "step1": ["export cardid=0&&defconf --tcpmss 0", "defconf --show", 'tcp mss: 0'],
    "step2": ["export cardid=1&&defconf --tcpmss 0", "defconf --show", 'tcp mss: 0']
}

pkt2_cfg = {
    "send": [ciface, 1, "0001_TCP_ETH_IPV4_TCP.pcap"],
    "capture": [siface, f'tcp and host {pcap_dip}', 1, "test_mss_a2_01.pcap", "test_mss_a2_02.pcap"],
    "read": ["test_mss_a2_01.pcap", "test_mss_a2_02.pcap", 0],
    "expect1": ['65535\n', 0, 0],
    "expect2": ['1460\n', 0, 0]
}
case2_step1 = {
    "step1": ["export cardid=0&&defconf --tcpmss 65535", "defconf --show", 'tcp mss: 65535'],
    "step2": ["export cardid=1&&defconf --tcpmss 65535", "defconf --show", 'tcp mss: 65535']
}
case2_step2 = {
    "step1": ["export cardid=0&&defconf --tcpmss 0", "defconf --show", 'tcp mss: 0'],
    "step2": ["export cardid=1&&defconf --tcpmss 0", "defconf --show", 'tcp mss: 0']
}
