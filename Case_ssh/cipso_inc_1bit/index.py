#coding:utf-8
#此文件的参数配置均与用例强相关，与执行环境无关
#适用用例范围


from common import baseinfo

pcap_sip = baseinfo.clientOpeIp
pcap_dip = baseinfo.serverOpeIp
cipso_sip = baseinfo.clientIp
cipso_dip = baseinfo.serverIp
dport=80
attack_port=2221
cat1='0x18,0x8,0x7,0x6'
cat2='0x58,0xa,0xf,0x6'
cat3='0x89,0x1d,0x36,0x71'
cat4='0xaa,0x3,0x12,0xc9'

#配置下发
#列表里面的顺序依次为：配置命令，查询命令，预期结果

cipso={
    "curl":[f"curl http://{cipso_dip}:{dport} >/opt/cipso.txt", 'cat /opt/cipso.txt', "Welcome to nginx!"],
    "txt":['cipso.txt']
}



case_step={
    "step1":['iptables -t mangle -F']
}

case1_step1={
    "step1":[f'iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat {cat1} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','level 12']
}
case1_step2={
    "step1":[f'iptables -I PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 12 --biba --inc  --cat {cat2} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','inc']
}
case1_step3={
    "step1":[f'iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat {cat1} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','level 12']
}
case1_step4={
    "step1":[f'iptables -D PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 12 --biba --inc  --cat {cat2} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','inc']
}



case2_step1={
    "step1":[f'iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat {cat3} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','level 12']
}
case2_step2={
    "step1":[f'iptables -I PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 12 --biba --1bit  --cat {cat4} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','1bit']
}
case2_step3={
    "step1":[f'iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat {cat3} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','level 12']
}
case2_step4={
    "step1":[f'iptables -D PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 12 --biba --1bit  --cat {cat4} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','1bit']
}




