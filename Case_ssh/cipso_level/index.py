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
cat = '0x23,0x53,0x16,0xcc2'

#配置下发
#列表里面的顺序依次为：配置命令，查询命令，预期结果

cipso_level={
    "curl":[f"curl http://{cipso_dip}:{dport} >/opt/cipso_curl_level.txt", 'cat /opt/cipso_curl_level.txt', "Welcome to nginx!"],
    "txt":['cipso_curl_level.txt']
}

case_step={
    "step1":['iptables -t mangle -F']
}

case1_step1={
    "step1":[f'iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 255 --cat {cat} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','level 255']
}
case1_step2={
    "step1":[f'iptables -I PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 255 --biba --inc  --cat {cat} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','level 255']
}
case1_step3={
    "step1":[f'iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 255 --cat {cat} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','level 255']
}
case1_step4={
    "step1":[f'iptables -D PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 255 --biba --inc  --cat {cat} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','level 255']
}



case2_step1={
    "step1":[f'iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 0 --cat {cat} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','level 0']
}
case2_step2={
    "step1":[f'iptables -I PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 0 --biba --inc  --cat {cat} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','level 0']
}
case2_step3={
    "step1":[f'iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 0 --cat {cat} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','level 0']
}
case2_step4={
    "step1":[f'iptables -D PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 0 --biba --inc  --cat {cat} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','level 0']
}



case3_step1={
    "step1":[f'iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 111 --cat {cat} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','level 111']
}
case3_step2={
    "step1":[f'iptables -I PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 111 --biba --inc  --cat {cat} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','level 111']
}
case3_step3={
    "step1":[f'iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 111 --cat {cat} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','level 111']
}
case3_step4={
    "step1":[f'iptables -D PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 111 --biba --inc  --cat {cat} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','level 111']
}


