#coding:utf-8
#此文件的参数配置均与用例强相关，与执行环境无关
#适用用例范围


from common import baseinfo

pcap_sip = baseinfo.clientOpeIp
pcap_dip = baseinfo.serverOpeIp
# dport=80
attack_port=2221


#获取ddos开关状态
ddos_fwlog = 'firewall-log: on'
netflow_switch = 'flow report: on'
ddos_fwlog1 = 'firewall-log: off'
netflow_switch1 = 'flow report: off'


flood1_icmp={
    "hping3":[f"hping3 -1 {pcap_dip} -c 10000 --faster"],
    "fwlog":['cardid=0&&defconf --fwlog on','cardid=0&&defconf --fwlog off'],
    "netflow":['cardid=0&&defconf --netflow on','cardid=0&&defconf --netflow off'],
    "txt":['icmp mode set','icmp_flood.txt'],
}

flood2_udp={
    "hping3":[f"hping3 -q -n --udp --keep -p {attack_port} --flood {pcap_dip} -c 10000 --faster"],
    "fwlog":['cardid=0&&defconf --fwlog on','cardid=0&&defconf --fwlog off'],
    "netflow":['cardid=0&&defconf --netflow on','cardid=0&&defconf --netflow off'],
    "txt":['udp mode set','udp_flood.txt'],
}


#配置下发
#列表里面的顺序依次为：配置命令，查询命令，预期结果

case_step={
    "step1":['cardid=0&&defconf --show', ddos_fwlog, netflow_switch],
}
case_step1={
    "step1":['cardid=0&&defconf --show', ddos_fwlog1, netflow_switch1],
}
case_step2={
    "step1":['txt']
}


case1_step1={
    "step1":['cardid=0&&tupleacl --get', pcap_dip],
}
case1_step2={
    "step1":['ICMP Flood']
}


case2_step1={
    "step1":['cardid=0&&tupleacl --get', pcap_dip]
}
case2_step2={
    "step1":['UDP Flood']
}