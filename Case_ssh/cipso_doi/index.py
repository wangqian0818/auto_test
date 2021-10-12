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
cat='0x3,0x1,0x8,0x0'

#配置下发
#列表里面的顺序依次为：配置命令，查询命令，预期结果

cipso_doi={
    "curl":[f"curl http://{cipso_dip}:{dport} >/opt/cipso_curl_doi.txt", 'cat /opt/cipso_curl_doi.txt', "Welcome to nginx!"],
    "txt":['cipso_curl_doi.txt']
}

case_step={
    "step1":['iptables -t mangle -F']
}

case1_step1={
    "step1":[f'iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi 4294967295 --level 12 --cat {cat} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','doi 4294967295']
}
case1_step2={
    "step1":[f'iptables -I PREROUTING -t mangle -p tcp -m cipso --doi 4294967295 --level 12 --biba --inc  --cat {cat} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','doi 4294967295']
}
case1_step3={
    "step1":[f'iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi 4294967295 --level 12 --cat {cat} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','doi 4294967295']
}
case1_step4={
    "step1":[f'iptables -D PREROUTING -t mangle -p tcp -m cipso --doi 4294967295 --level 12 --biba --inc  --cat {cat} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','doi 4294967295']
}



case2_step1={
    "step1":[f'iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi 1 --level 12 --cat {cat} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','doi 1']
}
case2_step2={
    "step1":[f'iptables -I PREROUTING -t mangle -p tcp -m cipso --doi 1 --level 12 --biba --inc  --cat {cat} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','doi 1']
}
case2_step3={
    "step1":[f'iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi 1 --level 12 --cat {cat} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','doi 1']
}
case2_step4={
    "step1":[f'iptables -D PREROUTING -t mangle -p tcp -m cipso --doi 1 --level 12 --biba --inc  --cat {cat} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','doi 1']
}



case3_step1={
    "step1":[f'iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi 66 --level 12 --cat {cat} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','doi 66']
}
case3_step2={
    "step1":[f'iptables -I PREROUTING -t mangle -p tcp -m cipso --doi 66 --level 12 --biba --inc  --cat {cat} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','doi 66']
}
case3_step3={
    "step1":[f'iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi 66 --level 12 --cat {cat} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','doi 66']
}
case3_step4={
    "step1":[f'iptables -D PREROUTING -t mangle -p tcp -m cipso --doi 66 --level 12 --biba --inc  --cat {cat} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','doi 66']
}


