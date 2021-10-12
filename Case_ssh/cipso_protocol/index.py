#coding:utf-8
#此文件的参数配置均与用例强相关，与执行环境无关
#适用用例范围


from common import baseinfo

pcap_sip = baseinfo.clientOpeIp
pcap_dip = baseinfo.serverOpeIp
cipso_sip = baseinfo.clientIp
cipso_dip = baseinfo.serverIp
dport=80
# udp_dport=2222
cat1 = '0x15,0xc5,0x79,0x81'
cat2 = '0xa9,0x0,0x0,0x0'
# path = '/root/netlble_test_src'


#配置下发
#列表里面的顺序依次为：配置命令，查询命令，预期结果

cipso_tcp={
    "curl":[f"curl http://{cipso_dip}:{dport} >/opt/cipso_tcp.txt", 'cat /opt/cipso_tcp.txt', "Welcome to nginx!"],
    "txt":['cipso_tcp.txt']
}
# cipso_udp={
#     "udp-s": ['script /opt/cipso_udp_s.txt', f"{path}/udp_recv -p {udp_dport}", 'cat/opt/cipso_udp_s.txt', 'message: "hello world"'],
#     "udp-c": [f"{path}/udp_send -d {cipso_dip} -p {udp_dport} > /opt/cipso_udp.txt", 'cat /opt/cipso_udp.txt', f'Socket will send to port {udp_dport}'],
#     # "result": ['message: "hello world"']
# }
cipso_icmp={
    "ping":[f'ping -c 2 {cipso_dip} > /opt/cipso_icmp.txt', 'cat /opt/cipso_icmp.txt' ,f'64 bytes from {cipso_dip}: icmp_seq=1 ttl=64'],
    "txt":['cipso_icmp.txt']
}



case_step={
    "step1":['iptables -t mangle -F']
}
case_step1={
    "step1":['cipso_tcp.txt','cipso_udp.txt','cipso_icmp.txt']
}

case1_step1={
    "step1":[f'iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat {cat1} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','tcp']
}
case1_step2={
    "step1":[f'iptables -I PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 20 --blp --inc  --cat {cat1} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','tcp']
}
case1_step3={
    "step1":[f'iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat {cat1} -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','iptables -t mangle -nL','tcp']
}
case1_step4={
    "step1":[f'iptables -D PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 20 --blp --inc  --cat {cat1} -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','tcp']
}



case2_step1={
    "step1":[f'iptables -I POSTROUTING -t mangle -p icmp -j CIPSO --doi 16 --level 12 --cat {cat1} -d {cipso_dip} ','iptables -t mangle -nL','icmp']
}
case2_step2={
    "step1":[f'iptables -I PREROUTING -t mangle -p icmp -m cipso --doi 16 --level 20 --blp --inc  --cat {cat1} -s {cipso_sip} -j CIPSO --rm','iptables -t mangle -nL','icmp']
}
case2_step3={
    "step1":[f'iptables -D POSTROUTING -t mangle -p icmp -j CIPSO --doi 16 --level 12 --cat {cat1} -d {cipso_dip}','iptables -t mangle -nL','icmp']
}
case2_step4={
    "step1":[f'iptables -D PREROUTING -t mangle -p icmp -m cipso --doi 16 --level 20 --blp --inc  --cat {cat1} -s {cipso_sip} -j CIPSO --rm','iptables -t mangle -nL','icmp']
}


case3_step1={
    "step1":[f'iptables -I POSTROUTING -t mangle -p icmp -j CIPSO --doi 16 --level 12 --cat {cat2} -d {cipso_dip} ','iptables -t mangle -nL','icmp']
}
case3_step2={
    "step1":[f'iptables -I PREROUTING -t mangle -p icmp -m cipso --doi 16 --level 20 --blp --inc  --cat {cat2} -s {cipso_sip} -j CIPSO --rm','iptables -t mangle -nL','icmp']
}
case3_step3={
    "step1":[f'iptables -D POSTROUTING -t mangle -p icmp -j CIPSO --doi 16 --level 12 --cat {cat2} -d {cipso_dip}','iptables -t mangle -nL','icmp']
}
case3_step4={
    "step1":[f'iptables -D PREROUTING -t mangle -p icmp -m cipso --doi 16 --level 20 --blp --inc  --cat {cat2} -s {cipso_sip} -j CIPSO --rm','iptables -t mangle -nL','icmp']
}

# case4_step1={
#     "step1":[f'iptables -I POSTROUTING -t mangle -p udp -j CIPSO --doi 16 --level 12 --cat 0x3,0x0,0x0,0x0 -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','udp']
# }
# case4_step2={
#     "step1":[f'iptables -I PREROUTING -t mangle -p udp -m cipso --doi 16 --level 20 --blp --inc  --cat 0x3,0x0,0x0,0x0 -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','udp']
# }
# case4_step3={
#     "step1":[f'iptables -D POSTROUTING -t mangle -p udp -j CIPSO --doi 16 --level 12 --cat 0x3,0x0,0x0,0x0 -d {cipso_dip} --dport {dport}','iptables -t mangle -nL','udp']
# }
# case4_step4={
#     "step1":[f'iptables -D PREROUTING -t mangle -p udp -m cipso --doi 16 --level 20 --blp --inc  --cat 0x3,0x0,0x0,0x0 -s {cipso_sip} --dport {dport} -j CIPSO --rm','iptables -t mangle -nL','udp']
# }
# case4_step5={
#     "step1":['netstat -ultpn',str(dport)]
# }
