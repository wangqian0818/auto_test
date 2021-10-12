#coding:utf-8
#此文件的参数配置均与用例强相关，与执行环境无关
#适用用例范围


from common import baseinfo

pcap_sip = baseinfo.clientOpeIp
pcap_dip = baseinfo.serverOpeIp
dport=80
attack_port=2221
cat = '0xe7,0x90,0xf1,0x36'

#配置下发
#列表里面的顺序依次为：配置命令，查询命令，预期结果

cipso_tcp={
    "curl":[f"curl http://{pcap_dip}:{dport} >/opt/cipso_gw_tcp.txt", 'cat /opt/cipso_gw_tcp.txt', "Welcome to nginx!"],
    "txt":['cipso_gw_tcp.txt']
}




case_step={
    "step1":['iptables -t mangle -F']
}
case_step1={
    "step1":['txt']
}


case1_step1={
    "step1":[f'iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat {cat} -d {pcap_dip} --dport {dport}','iptables -t mangle -nL', cat],
    "step2":[f'iptables -I PREROUTING -t mangle -p tcp  -s {pcap_dip} --sport {dport} -j CIPSO --rm', 'iptables -t mangle -nL', 'rm']
}

case1_step2={
    "step1":[f'export cardid=0&&tupleacl --add --sip {pcap_sip} --dip {pcap_dip} --dp {dport} --l4p 6 --action forward --netlbl strip --drop on --mode BLP --doi 16 --level 16 --type 1 --value {cat} ','export cardid=0&&tupleacl --get',pcap_dip],
}
case1_step3={
    "step1":[f'iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat {cat} -d {pcap_dip} --dport {dport}'],
    "step2":[f'iptables -D PREROUTING -t mangle -p tcp  -s {pcap_dip} --sport {dport} -j CIPSO --rm','iptables -t mangle -nL',pcap_dip]
}

case1_step4={
    "step1":['export cardid=0&&tupleacl --clear','export cardid=0&&tupleacl --get',pcap_dip]
}




