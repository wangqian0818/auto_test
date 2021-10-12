#coding:utf-8
#此文件的参数配置均与用例强相关，与执行环境无关
#适用用例范围
#验证标记type字段左右边界

from common import baseinfo

pcap_sip = baseinfo.clientOpeIp
pcap_dip = baseinfo.serverOpeIp
ciface = baseinfo.pcapSendIface
siface = baseinfo.pcapReadIface
strip = baseinfo.strip

#报文发送,读取和预期结果
#列表里面的命令依次为：
#发送端：发送报文接口，发送报文数量，发送报文名称；
#抓包：接口名称，过滤规则，抓包数量，报文命名（以用例名称.pcap命名）
#报文读取：保存的报文名称，要读取的包的序号；这里读取的报文名称和上面抓包的保存报文名称应该一致
#期望结果：预期结果（协议字段），是否有偏差（保留），偏差值（保留）

pkt1_cfg={
    "send":[ciface,1,"0001_TCP_ETH_IPV4_TCP__16_14_3_8889.pcap"],
    "capture":[siface,f"tcp and host {pcap_dip}",1,"test_selabel_cipso_type_1.pcap"],
    "read":["test_selabel_cipso_type_1.pcap",0],
    "expect":[strip,0,0]
}


#配置下发
#列表里面的顺序依次为：配置命令，查询命令，预期结果

case1_step={
    "step1":["export cardid=0 && selabel --set --netlbl strip --drop on --doi 16  --match n --mode BLP --level 17 --type 1 --value 0 1 ","export cardid=0 &&selabel --get","type:1"],
}

case2_step={
    "step1":["export cardid=0 && selabel --set --netlbl strip --drop on --doi 16  --match n --mode BLP --level 18 --type -1 --value 0 1 ","export cardid=0 &&selabel --get","There`s no label"],
    "step2":["export cardid=0 && selabel --set --netlbl strip --drop on --doi 16  --match n --mode BLP --level 18 --type 0 --value 0 1 ","export cardid=0 &&selabel --get","There`s no label"],
    "step3":["export cardid=0 && selabel --set --netlbl strip --drop on --doi 16  --match n --mode BLP --level 18 --type 3 --value 0 1 ","export cardid=0 &&selabel --get","There`s no label"],
    "step4":["export cardid=0 && selabel --set --netlbl strip --drop on --doi 16  --match n --mode BLP --level 18 --type 6 --value 0 1 ","export cardid=0 &&selabel --get","There`s no label"],
    "step5":["export cardid=0 && selabel --set --netlbl strip --drop on --doi 16  --match n --mode BLP --level 18 --type 255 --value 0 1 ","export cardid=0 &&selabel --get","There`s no label"],
}

# case3_step={
#     "step1":["export cardid=0 && selabel --set --netlbl strip --drop on --doi 16  --match n --mode BLP --level 18 --type 1 --value 0 1 ","export cardid=0 &&selabel --get","type:1"],
#     "step2":["export cardid=0 && selabel --set --netlbl strip --drop on --doi 16  --match n --mode BLP --level 18 --type 2 --value 0 1 ","export cardid=0 &&selabel --get","type:2"],
#     "step3":["export cardid=0 && selabel --set --netlbl strip --drop on --doi 16  --match n --mode BLP --level 18 --type 5 --value 0 1 ","export cardid=0 &&selabel --get","type:5"],
# }

#
