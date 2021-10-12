#coding:utf-8
#此文件的参数配置均与用例强相关，与执行环境无关
#适用用例范围
#验证标记系统tcp上传功能

from common import baseinfo
from common import fun

pcap_sip = baseinfo.clientOpeIp
pcap_dip = baseinfo.serverOpeIp
ciface = baseinfo.pcapSendIface
siface = baseinfo.pcapReadIface
strip = baseinfo.strip
txt = '100M.txt'

#报文发送,读取和预期结果
#列表里面的命令依次为：
#发送端：发送文件名称，发送文件目标地址；
#抓包：接口名称，过滤规则，抓包数量，报文命名（以用例名称.pcap命名）
#报文读取：保存的报文名称，要读取的包的序号；这里读取的报文名称和上面抓包的保存报文名称应该一致
#期望结果：预期结果（协议字段），是否有偏差（保留），偏差值（保留）
pkt1_cfg={
    "scp":["100M.txt",f"{pcap_dip}"],
    "capture":[siface,f"tcp and host {pcap_dip}",1,"test_selabel_cipso_scp_upload.pcap"],
    "read":["test_selabel_cipso_scp_upload.pcap",0],
    "expect":[strip,0,0],
    "txt":[txt,0]
}

pkt2_cfg={
    "scp":["100M.txt",f"{pcap_dip}"],
    "capture":[siface,f"tcp and host {pcap_dip}",1,"test_selabel_cipso_scp_download.pcap"],
    "read":["test_selabel_cipso_scp_download.pcap",0],
    "expect":[strip,0,0],
    "txt":[txt,0]
}

#配置下发
#列表里面的顺序依次为：配置命令，查询命令，预期结果


# case1_step={
#     "step1":[f"export cardid=0 && selabel --set --netlbl strip --drop on --doi 16  --match n --mode BLP --level 15 --type 1 --value 0 1 ","export cardid=0 &&selabel --get","level:15"],
#     "step2":[f"export cardid=1 && selabel --set --netlbl tag --drop off --doi 16  --match n --mode BLP --level 16 --type 1 --value 0 1 ","export cardid=1 &&selabel --get","level:16"]
# }

