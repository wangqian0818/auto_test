#coding:utf-8
#此文件的参数配置均与用例强相关，与执行环境无关

from common import baseinfo

pcap_sip = baseinfo.clientOpeIp
pcap_dip = baseinfo.serverOpeIp
ciface = baseinfo.pcapSendIface
siface = baseinfo.pcapReadIface
qos_port = baseinfo.qos_port

#配置下发
#列表里面的顺序依次为：配置命令，查询命令，预期结果
case1_step={
    "step1":[f"export cardid=0&&tupleacl --add --dip {pcap_dip} --dp {qos_port} --action forward --qos0 1250000 --qos1 2500000 --qmode rate --qbucket p",f"tupleacl --query --dip {pcap_dip} --dp {qos_port}",pcap_dip]
}


case2_step={
    "step1":[f"export cardid=0&&tupleacl --add --dip {pcap_dip} --dp {qos_port} --action forward --qos0 1250000 --qos1 2500000 --qmode rate --qbucket p",f"tupleacl --query --dip {pcap_dip} --dp {qos_port}",pcap_dip],
    "step2":[f"export cardid=1&&tupleacl --add --dip {pcap_dip} --dp {qos_port} --action forward --qos0 1250000 --qos1 2500000 --qmode rate --qbucket p",f"export cardid=1&&tupleacl --query --dip {pcap_dip} --dp {qos_port}",pcap_dip]
}

