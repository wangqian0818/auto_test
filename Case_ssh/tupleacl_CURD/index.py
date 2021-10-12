# coding:utf-8
from common import baseinfo

pcap_sip = baseinfo.clientOpeIp
pcap_dip = baseinfo.serverOpeIp
ciface = baseinfo.pcapSendIface
siface = baseinfo.pcapReadIface
strip = baseinfo.strip

value = r"b'\x00\x00\x00\x10\x01\x05\x00\x0e\xc0'"
# 报文发送,读取和预期结果
# 列表里面的命令依次为：
# 发送端：发送报文接口，发送报文数量，发送报文名称；
# 抓包：接口名称，过滤规则，抓包数量，报文命名（以用例名称.pcap命名）
# 报文读取：保存的报文名称，要读取的包的序号；这里读取的报文名称和上面抓包的保存报文名称应该一致
# 期望结果：预期结果（协议字段），是否有偏差（保留），偏差值（保留）
pkt_cfg = {
    "send": [ciface, 1, "0001_TCP_ETH_IPV4_TCP__16_14_3_8889.pcap"],
    "capture": [siface, f'tcp and host {pcap_dip}', 1, "test_acl_CURD_a5.pcap"],
    "read": ["test_acl_CURD_a5.pcap", 0],
    "expect": [f'{value}\n', 0, 0]
}

# 配置下发
# 列表里面的顺序依次为：配置命令，查询命令，预期结果
case1_step = {
    "step1": ["export cardid=0&&tupleacl --add --dp 8889 --action forward",
              "export cardid=0&&tupleacl --query --dp 8889", "8889"],
    "step2": ["export cardid=1&&tupleacl --add --dp 9999 --action forward", "export cardid=1&&tupleacl --del --dp 9966",
              "Error"]
}

case2_step = {
    "step1": ["export cardid=1&&tupleacl --add --dp 8889 --action forward",
              "export cardid=1&&tupleacl --query --dp 8889", "8889"],
    "step2": ["export cardid=1&&tupleacl --del --dp 8889 --action forward",
              "export cardid=1&&tupleacl --query --dp 8889", "This item does not exist"]
}

case3_step = {
    "step1": ["export cardid=0&&tupleacl --add --dp 8889 --action forward",
              "export cardid=0&&tupleacl --query --dp 8889", "8889"],
    "step2": ["export cardid=1&&tupleacl --add --dp 8888 --action forward",
              "export cardid=1&&tupleacl --add --dp 8888 --action forward", "Error"]
}

case4_step = {
    "step1": ["export cardid=0&&tupleacl --add --dp 8889 --action forward", "tupleacl --get", "8889"],
    "step2": ["tupleacl --add --dp 8888 --action forward", "tupleacl --get", "8888"],
    "step3": ["tupleacl --clear", "tupleacl --get", "0 rules"]
}

case5_step = {
    "step1": [
        f"export cardid=0&&tupleacl --add --sip {pcap_sip} --action forward --netlbl strip --drop on --match n --mode BLP --doi 16 --level 16 --type 1 --value 0x3,0,0,0",
        f"export cardid=0&&tupleacl --query --sip {pcap_sip}", pcap_sip],
    "step2": [
        f"export cardid=1&&tupleacl --add --dip {pcap_dip} --action forward --netlbl tag --drop off --match n --mode BLP --doi 16 --level 14 --type 1 --value 0x3,0,0,0",
        f"export cardid=1&&tupleacl --query --dip {pcap_dip}", pcap_dip]
}
