from common import baseinfo
from cipso_gw import index
import time
import json
datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
cardid0=baseinfo.gwCard0
pcap_dip = baseinfo.serverOpeIp
pcap_sip = baseinfo.clientOpeIp
dport = str(index.dport)
cat = index.cat


# AddAclPolicy_TCP = {
# "AddAclPolicy":{
# "MethodName":"AddAclPolicy",
#  "MessageTime":datatime,
#  "Content":[{
#      "SeLabelDrop":1,
#      "Action":"0",
#      "QosMode":"",
#      "SeLabelLevel":16,
#      "SeLabelBitmap":cat,
#      "SeLabelType":1,"QosThreshold":"",
#      "Dip":pcap_dip,
#      "Ifname":"",
#      "QosBucket":"",
#      "Listorder":"1",
#      "Direction":"INPUT",
#      "TTL":"",
#      "SeLabelMatch":0,
#      "Card":cardid0,
#      "SeLabelMode":"BLP",
#      "Sport":"",
#      "Dport":dport,
#      "SeLabelTag":2,
#      "Sip":pcap_sip,
#      "Protocol":"6",
#      "SeLabelDoi":16}]
# }
# }
#
#
# DelAclPolicy = {
# "DelAclPolicy":{
# "MethodName":"DelAclPolicy",
# "MessageTime": datatime,
# "Content":[{
#     "Pid":"1",
#     "Card":cardid0}]
# }
# }