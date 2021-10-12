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
cat = '0x78a,0x6c,0x88e,0x601'

#配置下发
#列表里面的顺序依次为：配置命令，查询命令，预期结果

cipso={
    "curl":[f"curl http://{cipso_dip}:{dport} >/opt/cipso_blp_biba.txt", 'cat /opt/cipso_blp_biba.txt', "Welcome to nginx!"],
    "txt":['cipso_blp_biba.txt']
}




case_step={
    "step1":['iptables -t mangle -F']
}

case1_step1={
    "step1":[f'iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat {cat} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','level 12']
}
case1_step2={
    "step1":[f'iptables -I PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 20 --blp --inc  --cat {cat} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','blp']
}
case1_step3={
    "step1":[f'iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat {cat} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','iptables -t mangle -nL','level 12']
}
case1_step4={
    "step1":[f'iptables -D PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 20 --blp --inc  --cat {cat} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','blp']
}




case2_step1={
    "step1":[f'iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 22 --cat {cat} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','level 22']
}
case2_step2={
    "step1":[f'iptables -I PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 10 --biba --inc  --cat {cat} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','biba']
}
case2_step3={
    "step1":[f'iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 22 --cat {cat} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','level 22']
}
case2_step4={
    "step1":[f'iptables -D PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 10 --biba --inc  --cat {cat} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','biba']
}




