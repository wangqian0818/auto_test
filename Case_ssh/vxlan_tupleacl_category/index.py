#coding:utf-8
#此文件的参数配置均与用例强相关，与执行环境无关

from common import baseinfo

pcap_sip = baseinfo.clientOpeIp
pcap_dip = baseinfo.serverOpeIp
vxlan_sip = baseinfo.vxlan_sip
vxlan_dip = baseinfo.vxlan_dip
ciface = baseinfo.pcapSendIface
siface = baseinfo.pcapReadIface
strip = baseinfo.strip

value1 = r"b'\x00\x00\x00\x10\x01\x04\x00\x0e'"
val2 = r'\x00\x00\x00\x10\x01"\x00\x0e\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
value2 = r"b'" + val2 + r"'"
value3 = r"b'\x00\x00\x00\x10\x01\x0c\x00\x0e\xff\xff\xff\xff\xff\xff\xff\xff'"
value4 = r"b'\x00\x00\x00\x10\x01\x14\x00\x0e\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'"
value5 = r"b'\x00\x00\x00\x10\x01\x1c\x00\x0e\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'"
val6 = r'\x00\x00\x00\x10\x01"\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
value6 = r"b'" + val6 + r"'"
val7 = r'\x00\x00\x00\x10\x01"\x00\x0e\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
value7 = r"b'" + val7 + r"'"
val8 = r'\x00\x00\x00\x10\x01"\x00\x0e\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff'
value8 = r"b'" + val8 + r"'"

#报文发送,读取和预期结果
#列表里面的命令依次为：
#发送端：发送报文接口，发送报文数量，发送报文名称；
#抓包：接口名称，过滤规则，抓包数量，报文命名（以用例名称.pcap命名）
#报文读取：保存的报文名称，要读取的包的序号；这里读取的报文名称和上面抓包的保存报文名称应该一致
#期望结果：预期结果（协议字段），是否有偏差（保留），偏差值（保留）
pkt1_cfg={
    "send":[ciface,1,"0001_TCP_VXLAN_TCP__16_14_0.pcap"],
    "capture":[siface,f'udp and host {pcap_dip}',1,"vxlan_acl_category_0.pcap"],
    "read":["vxlan_acl_category_0.pcap",0],
    "expect":[f'{value1}\n',0,0]
}
#配置下发
#列表里面的顺序依次为：配置命令，查询命令，预期结果
case1_step={
    "step1":[f"export cardid=0&&tupleacl --add --sip {vxlan_sip} --action forward --netlbl strip --drop on --match n --mode BLP --doi 16 --level 16 --type 1 --value 0x0,0,0,0",f"export cardid=0&&tupleacl --query --sip {vxlan_sip}",vxlan_sip],
    "step2":[f"export cardid=1&&tupleacl --add --sip {vxlan_sip} --action forward --netlbl tag --drop off --match n --mode BLP --doi 16 --level 14 --type 1 --value 0x0,0,0,0",f"export cardid=1&&tupleacl --query --sip {vxlan_sip}",vxlan_sip]
}


pkt2_cfg={
    "send":[ciface,1,"0001_TCP_VXLAN_TCP__16_14_ffff.pcap"],
    "capture":[siface,f'udp and host {pcap_dip}',1,"vxlan_acl_category_ffff.pcap"],
    "read":["vxlan_acl_category_ffff.pcap",0],
    "expect":[f'{value2}\n',0,0]
}
case2_step={
    "step1":[f"export cardid=0&&tupleacl --add --sip {vxlan_sip} --action forward --netlbl strip --drop on --match n --mode BLP --doi 16 --level 16 --type 1 --value 0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff",f"export cardid=0&&tupleacl --query --sip {vxlan_sip}",vxlan_sip],
    "step2":[f"export cardid=1&&tupleacl --add --sip {vxlan_sip} --action forward --netlbl tag --drop off --match n --mode BLP --doi 16 --level 14 --type 1 --value 0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff",f"export cardid=1&&tupleacl --query --sip {vxlan_sip}",vxlan_sip]
}


pkt3_cfg={
    "send":[ciface,1,"0001_TCP_VXLAN_TCP__16_14_ffff.pcap"],
    "capture":[siface,f'udp and host {pcap_dip}',1,"vxlan_acl_category_f000.pcap"],
    "read":["vxlan_acl_category_f000.pcap",0],
    "expect":[f'{value3}\n',0,0]
}
case3_step={
    "step1":[f"export cardid=0&&tupleacl --add --sip {vxlan_sip} --action forward --netlbl strip --drop on --match n --mode BLP --doi 16 --level 16 --type 1 --value 0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff",f"export cardid=0&&tupleacl --query --sip {vxlan_sip}",vxlan_sip],
    "step2":[f"export cardid=1&&tupleacl --add --sip {vxlan_sip} --action forward --netlbl tag --drop off --match n --mode BLP --doi 16 --level 14 --type 1 --value 0xffffffffffffffff,0x0,0x0,0x0",f"export cardid=1&&tupleacl --query --sip {vxlan_sip}",vxlan_sip]
}


pkt4_cfg={
    "send":[ciface,1,"0001_TCP_VXLAN_TCP__16_14_ffff.pcap"],
    "capture":[siface,f'udp and host {pcap_dip}',1,"vxlan_acl_category_ff00.pcap"],
    "read":["vxlan_acl_category_ff00.pcap",0],
    "expect":[f'{value4}\n',0,0]
}
case4_step={
    "step1":[f"export cardid=0&&tupleacl --add --sip {vxlan_sip} --action forward --netlbl strip --drop on --match n --mode BLP --doi 16 --level 16 --type 1 --value 0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff",f"export cardid=0&&tupleacl --query --sip {vxlan_sip}",vxlan_sip],
    "step2":[f"export cardid=1&&tupleacl --add --sip {vxlan_sip} --action forward --netlbl tag --drop off --match n --mode BLP --doi 16 --level 14 --type 1 --value 0xffffffffffffffff,0xffffffffffffffff,0x0,0x0",f"export cardid=1&&tupleacl --query --sip {vxlan_sip}",vxlan_sip]
}


pkt5_cfg={
    "send":[ciface,1,"0001_TCP_VXLAN_TCP__16_14_ffff.pcap"],
    "capture":[siface,f'udp and host {pcap_dip}',1,"vxlan_acl_category_fff0.pcap"],
    "read":["vxlan_acl_category_fff0.pcap",0],
    "expect":[f'{value5}\n',0,0]
}
case5_step={
    "step1":[f"export cardid=0&&tupleacl --add --sip {vxlan_sip} --action forward --netlbl strip --drop on --match n --mode BLP --doi 16 --level 16 --type 1 --value 0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff",f"export cardid=0&&tupleacl --query --sip {vxlan_sip}",vxlan_sip],
    "step2":[f"export cardid=1&&tupleacl --add --sip {vxlan_sip} --action forward --netlbl tag --drop off --match n --mode BLP --doi 16 --level 14 --type 1 --value 0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0x0",f"export cardid=1&&tupleacl --query --sip {vxlan_sip}",vxlan_sip]
}


pkt6_cfg={
    "send":[ciface,1,"0001_TCP_VXLAN_TCP__16_14_ffff.pcap"],
    "capture":[siface,f'udp and host {pcap_dip}',1,"vxlan_acl_category_0fff.pcap"],
    "read":["vxlan_acl_category_0fff.pcap",0],
    "expect":[f'{value6}\n',0,0]
}
case6_step={
    "step1":[f"export cardid=0&&tupleacl --add --sip {vxlan_sip} --action forward --netlbl strip --drop on --match n --mode BLP --doi 16 --level 16 --type 1 --value 0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff",f"export cardid=0&&tupleacl --query --sip {vxlan_sip}",vxlan_sip],
    "step2":[f"export cardid=1&&tupleacl --add --sip {vxlan_sip} --action forward --netlbl tag --drop off --match n --mode BLP --doi 16 --level 14 --type 1 --value 0x0,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff",f"export cardid=1&&tupleacl --query --sip {vxlan_sip}",vxlan_sip]
}


pkt7_cfg={
    "send":[ciface,1,"0001_TCP_VXLAN_TCP__16_14_ffff.pcap"],
    "capture":[siface,f'udp and host {pcap_dip}',1,"vxlan_acl_category_f0ff.pcap"],
    "read":["vxlan_acl_category_f0ff.pcap",0],
    "expect":[f'{value7}\n',0,0]
}
case7_step={
    "step1":[f"export cardid=0&&tupleacl --add --sip {vxlan_sip} --action forward --netlbl strip --drop on --match n --mode BLP --doi 16 --level 16 --type 1 --value 0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff",f"export cardid=0&&tupleacl --query --sip {vxlan_sip}",vxlan_sip],
    "step2":[f"export cardid=1&&tupleacl --add --sip {vxlan_sip} --action forward --netlbl tag --drop off --match n --mode BLP --doi 16 --level 14 --type 1 --value 0xffffffffffffffff,0x0,0xffffffffffffffff,0xffffffffffff",f"export cardid=1&&tupleacl --query --sip {vxlan_sip}",vxlan_sip]
}


pkt8_cfg={
    "send":[ciface,1,"0001_TCP_VXLAN_TCP__16_14_ffff.pcap"],
    "capture":[siface,f'udp and host {pcap_dip}',1,"vxlan_acl_category_ff0f.pcap"],
    "read":["vxlan_acl_category_ff0f.pcap",0],
    "expect":[f'{value8}\n',0,0]
}
case8_step={
    "step1":[f"export cardid=0&&tupleacl --add --sip {vxlan_sip} --action forward --netlbl strip --drop on --match n --mode BLP --doi 16 --level 16 --type 1 --value 0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffff",f"export cardid=0&&tupleacl --query --sip {vxlan_sip}",vxlan_sip],
    "step2":[f"export cardid=1&&tupleacl --add --sip {vxlan_sip} --action forward --netlbl tag --drop off --match n --mode BLP --doi 16 --level 14 --type 1 --value 0xffffffffffffffff,0xffffffffffffffff,0x0,0xffffffffffff",f"export cardid=1&&tupleacl --query --sip {vxlan_sip}",vxlan_sip]
}