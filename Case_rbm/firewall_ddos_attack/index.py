#coding:utf-8
#此文件的参数配置均与用例强相关，与执行环境无关
#适用用例范围


from common import baseinfo

pcap_sip = baseinfo.clientOpeIp
pcap_dip = baseinfo.serverOpeIp
dport=80
attack_port=2221


#获取ddos开关状态
ddos_syn = 'syn-cookie: on'
ddos_filter = 'filter noflow: on'
ddos_option = 'check no option: on'
ddos_fwlog = 'firewall-log: on'
ddos_syn1 = 'syn-cookie: off'
ddos_filter1 = 'filter noflow: off'
ddos_option1 = 'check no option: off'
ddos_fwlog1 = 'firewall-log: off'

ddos1_rst={
    "fwlog":['cardid=0&&defconf --fwlog on','cardid=0&&defconf --fwlog off'],
    "hping3":[f"hping3 -R {pcap_dip} -p {attack_port} --faster -c 6000 >/opt/hping3_rst.txt", 'cat /opt/hping3_rst.txt', 'R set'],
    "curl":[f"curl http://{pcap_dip}:{dport} >/opt/ddos_rst.txt", 'cat /opt/ddos_rst.txt', "Welcome to nginx!"],
    "txt":['hping3_rst.txt','ddos_rst.txt']
}

ddos2_ack={
    "fwlog":['cardid=0&&defconf --fwlog on'],
    "hping3":[f"hping3 -A {pcap_dip} -p {attack_port} --faster -c 6000 >/opt/hping3_ack.txt", 'cat /opt/hping3_ack.txt', 'A set'],
    "curl":[f"curl http://{pcap_dip}:{dport} >/opt/ddos_ack.txt", 'cat /opt/ddos_ack.txt', "Welcome to nginx!"],
    "txt":['hping3_ack.txt','ddos_ack.txt']
}

ddos3_syn={
    "fwlog":['cardid=0&&defconf --fwlog on'],
    "hping3":[f"hping3 -S {pcap_dip} -p {attack_port} --faster -c 6000 >/opt/hping3_syn.txt", 'cat /opt/hping3_syn.txt', 'S set'],
    "curl":[f"curl http://{pcap_dip}:{dport} >/opt/ddos_syn.txt", 'cat /opt/ddos_syn.txt', "Welcome to nginx!"],
    "txt":['hping3_SYN.txt','ddos_syn.txt']
}


#配置下发
#列表里面的顺序依次为：配置命令，查询命令，预期结果

case_step={
    "step1":['cardid=0&&defconf --show',ddos_syn, ddos_filter, ddos_option, ddos_fwlog],
}
case_step1={
    "step1":['cardid=0&&defconf --show',ddos_syn1, ddos_filter1, ddos_option1, ddos_fwlog1],
}
case_step2={
    "step1":['txt']
}


case1_step1={
    "step1":['RST Flood'],
}


case2_step1={
    "step1":['ACK Flood']
}

case3_step1={
    "step1":['Syn Flood']
}