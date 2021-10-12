#coding:utf-8
#此文件的参数配置均与用例强相关，与执行环境无关
#适用用例范围
#1、验证value（即协议字段category）的配置
#2、验证value（即协议字段category）右边界
#3、验证value（即协议字段category）右边界
#4、验证value（即协议字段category）左边界

from common import baseinfo
from common import fun

pcap_sip = baseinfo.clientOpeIp
pcap_dip = baseinfo.serverOpeIp
ciface = baseinfo.pcapSendIface
siface = baseinfo.pcapReadIface
strip = baseinfo.strip

category1 = fun.cipso_category(0,240)
category2 = fun.cipso_category(64,192)
category3 = fun.cipso_category(64,128)
category4 = fun.cipso_category(192,240)
category5 = fun.cipso_category(0,32)
category6 = fun.cipso_category(128,144)
category7 = fun.cipso_category(0,192)
category8 = fun.cipso_category(192,240)


#报文发送,读取和预期结果
#列表里面的命令依次为：
#发送端：发送报文接口，发送报文数量，发送报文名称；
#抓包：接口名称，过滤规则，抓包数量，报文命名（以用例名称.pcap命名）
#报文读取：保存的报文名称，要读取的包的序号；这里读取的报文名称和上面抓包的保存报文名称应该一致
#期望结果：预期结果（协议字段），是否有偏差（保留），偏差值（保留）
pkt1_cfg={
    "send":[ciface,1,"0001_TCP_ETH_IPV4_TCP__16_14_0xffff.pcap"],
    "capture":[siface,f"tcp and host {pcap_dip}",1,"test_selabel_cipso_category_right.pcap"],
    "read":["test_selabel_cipso_category_right.pcap",0],
    "expect":[strip,0,0]
}
pkt2_cfg={
    "send":[ciface,1,"0001_TCP_ETH_IPV4_TCP__16_14_0x0000.pcap"],
    "capture":[siface,f"tcp and host {pcap_dip}",1,"test_selabel_cipso_category_left.pcap"],
    "read":["test_selabel_cipso_category_left.pcap",0],
    "expect":[strip,0,0]
}

pkt3_cfg={
    "send":[ciface,1,"0001_TCP_ETH_IPV4_TCP__16_14_0xffff.pcap"],
    "capture":[siface,f"tcp and host {pcap_dip}",1,"test_selabel_cipso_category_range_1.pcap"],
    "read":["test_selabel_cipso_category_range_1.pcap",0],
    "expect":[r"b'\x00\x00\x00\x10\x01\x1c\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'"'\n',0,0]
}

pkt4_cfg={
    "send":[ciface,1,"0001_TCP_ETH_IPV4_TCP__16_14_0xffff.pcap"],
    "capture":[siface,f"tcp and host {pcap_dip}",1,"test_selabel_cipso_category_range_2.pcap"],
    "read":["test_selabel_cipso_category_range_2.pcap",0],
    "expect":[r"b'\x00\x00\x00\x10\x01"+"\""+r'\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff'+"\'"'\n',0,0]
}

pkt5_cfg={
    "send":[ciface,1,"0001_TCP_ETH_IPV4_TCP__16_14_0xffff.pcap"],
    "capture":[siface,f"tcp and host {pcap_dip}",1,"test_selabel_cipso_category_range_3.pcap"],
    "read":["test_selabel_cipso_category_range_3.pcap",0],
    "expect":[r"b'\x00\x00\x00\x10\x01\x1d\x00\x10\xff\xff\xff\xff\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\xc0'"'\n',0,0]
}

pkt6_cfg={
    "send":[ciface,1,"0001_TCP_ETH_IPV4_TCP__16_14_0xffff.pcap"],
    "capture":[siface,f"tcp and host {pcap_dip}",1,"test_selabel_cipso_category_range_4.pcap"],
    "read":["test_selabel_cipso_category_range_4.pcap",0],
    "expect":[r"b'\x00\x00\x00\x10\x01\x1d\x00\x10\xa0\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x00\xff'"'\n',0,0]
}

pkt7_cfg={
    "send":[ciface,1,"0001_TCP_ETH_IPV4_TCP__16_14_0xffff.pcap"],
    "capture":[siface,f"tcp and host {pcap_dip}",1,"test_selabel_cipso_category_range_5.pcap"],
    "read":["test_selabel_cipso_category_range_5.pcap",0],
    "expect":[r"b'\x00\x00\x00\x10\x01\x1c\x00\x10\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'"'\n',0,0]
}

pkt8_cfg={
    "send":[ciface,1,"0001_TCP_ETH_IPV4_TCP__16_14_0xffff.pcap"],
    "capture":[siface,f"tcp and host {pcap_dip}",1,"test_selabel_cipso_category_range_6.pcap"],
    "read":["test_selabel_cipso_category_range_6.pcap",0],
    "expect":[r"b'\x00\x00\x00\x10\x01"+"\""+r'\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff'+"\'"'\n',0,0]
}
#配置下发
#列表里面的顺序依次为：配置命令，查询命令，预期结果


case1_step={
    "step1":[f"export cardid=0 && selabel --set --netlbl strip --drop on --doi 16  --match n --mode BLP --level 15 --type 1 --value  {category1} ","export cardid=0 &&selabel --get","level:15"],
}

case2_step={
   "step1":["export cardid=0 && selabel --set --netlbl strip --drop on --doi 16  --match n --mode BLP --level 16 --type 1  ","export cardid=0 &&selabel --get","level:16"],
}

case3_step={
    "step1":["export cardid=0 && selabel --set --netlbl strip --drop on --doi 16  --match n --mode BLP --level 16 --type 1  ","export cardid=0 &&selabel --get","level:16"],
    "step2":[f"export cardid=1 && selabel --set --netlbl tag --drop off --doi 16  --match n --mode BLP --level 16 --type 1 --value {category2} ","export cardid=1 &&selabel --get","level:16"],
}

case4_step={
    "step1":["export cardid=0 && selabel --set --netlbl strip --drop on --doi 16  --match n --mode BLP --level 16 --type 1  ","export cardid=0 &&selabel --get","level:16"],
    "step2":[f"export cardid=1 && selabel --set --netlbl tag --drop off --doi 16  --match n --mode BLP --level 16 --type 1 --value {category3+category4} ","export cardid=1 &&selabel --get","level:16"],
}

case5_step={
    "step1":["export cardid=0 && selabel --set --netlbl strip --drop on --doi 16  --match n --mode BLP --level 16 --type 1  ","export cardid=0 &&selabel --get","level:16"],
    "step2":[f"export cardid=1 && selabel --set --netlbl tag --drop off --doi 16  --match n --mode BLP --level 16 --type 1 --value {category5} 67 {category6} 192 193 ","export cardid=1 &&selabel --get","level:16"],
}

case6_step={
    "step1":["export cardid=0 && selabel --set --netlbl strip --drop on --doi 16  --match n --mode BLP --level 16 --type 1  ","export cardid=0 &&selabel --get","level:16"],
    "step2":[f"export cardid=1 && selabel --set --netlbl tag --drop off --doi 16  --match n --mode BLP --level 16 --type 1 --value 0 2 67 128 129 192 193 194 195 196 197 198 199 ","export cardid=1 &&selabel --get","level:16"],
}

case7_step={
    "step1":["export cardid=0 && selabel --set --netlbl strip --drop on --doi 16  --match n --mode BLP --level 16 --type 1  ","export cardid=0 &&selabel --get","level:16"],
    "step2":[f"export cardid=1 && selabel --set --netlbl tag --drop off --doi 16  --match n --mode BLP --level 16 --type 1 --value {category7} ","export cardid=1 &&selabel --get","level:16"],
}

case8_step={
    "step1":["export cardid=0 && selabel --set --netlbl strip --drop on --doi 16  --match n --mode BLP --level 16 --type 1  ","export cardid=0 &&selabel --get","level:16"],
    "step2":[f"export cardid=1 && selabel --set --netlbl tag --drop off --doi 16  --match n --mode BLP --level 16 --type 1 --value {category8} ","export cardid=1 &&selabel --get","level:16"],
}