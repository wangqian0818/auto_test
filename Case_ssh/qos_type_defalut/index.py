#coding:utf-8
#此文件的参数配置均与用例强相关，与执行环境无关

from common import baseinfo

pcap_sip = baseinfo.clientOpeIp
pcap_dip = baseinfo.serverOpeIp
ciface = baseinfo.pcapSendIface
siface = baseinfo.pcapReadIface


#配置下发
#列表里面的顺序依次为：配置命令，查询命令，预期结果
case1_step={
    "step1":["export cardid=0&&qos-jsac --set --qos0 1250000 --qos1 2500000 --type d --qmode rate --qbucket s","qos-jsac --get",'1250000']
}


case2_step={
    "step1":["export cardid=0&&qos-jsac --set --qos0 1250000 --qos1 2500000 --type d --qmode rate --qbucket s","qos-jsac --get",'1250000']
}

