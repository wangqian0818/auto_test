from common import baseinfo
from firewall_flood_attack import index
import time
import json
datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
cardid0=baseinfo.gwCard0
attack_port = str(index.attack_port)
pcap_dip = baseinfo.serverOpeIp
pcap_sip = baseinfo.clientOpeIp

AddAclPolicy_ICMP = {
"AddAclPolicy":{
"MethodName":"AddAclPolicy",
 "MessageTime":datatime,
 "Content":[{
     "SeLabelDrop":"",
     "Action":"0",
     "QosMode":0,
     "SeLabelLevel":"",
     "SeLabelBitmap":"",
     "SeLabelType":"",
     "QosThreshold":"150,150",
     "Dip":pcap_dip,
     "Ifname":"",
     "QosBucket":1,
     "Listorder":"1",
     "Direction":"INPUT",
     "TTL":"",
     "SeLabelMatch":"",
     "Card":cardid0,
     "SeLabelMode":"",
     "Sport":"",
     "Dport":"",
     "SeLabelTag":"",
     "Sip":pcap_sip,
     "Protocol":"1",
     "SeLabelDoi":""}]
}
}

AddAclPolicy_UDP = {
"AddAclPolicy":{
"MethodName":"AddAclPolicy",
 "MessageTime":datatime,
 "Content":[{
     "SeLabelDrop":"",
     "Action":"0",
     "QosMode":0,
     "SeLabelLevel":"",
     "SeLabelBitmap":"",
     "SeLabelType":"",
     "QosThreshold":"300,300",
     "Dip":pcap_dip,
     "Ifname":"",
     "QosBucket":1,
     "Listorder":"1",
     "Direction":"INPUT",
     "TTL":"",
     "SeLabelMatch":"",
     "Card":cardid0,
     "SeLabelMode":"",
     "Sport":"",
     "Dport":attack_port,
     "SeLabelTag":"",
     "Sip":pcap_sip,
     "Protocol":"17",
     "SeLabelDoi":""}]
}
}

DelAclPolicy = {
"DelAclPolicy":{
"MethodName":"DelAclPolicy",
"MessageTime": datatime,
"Content":[{
    "Pid":"1",
    "Card":cardid0}]
}
}

