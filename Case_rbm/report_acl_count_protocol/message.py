from report_acl_count_protocol import index
import time
from common import baseinfo
#from report_acl_count import index
datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
pcap_dip = baseinfo.serverOpeIp
pcap_sip = baseinfo.clientOpeIp
domain = baseinfo.rbmDomain
Ifname= baseinfo.pcapReadIface
cardid0 = index.card_id0
port_d = index.dport
port_s = index.sport


#开启acl命中统计开关
set_ReportAclCount_open = {
"EnableAclCount":{
"MethodName":"EnableAclCount",
 "Content":[{"Card":cardid0,"Action":"1"}],
"MessageTime":datatime,
}
}

#关闭acl命中统计开关
set_ReportAclCount_close = {
"EnableAclCount":{
"MethodName":"EnableAclCount",
 "Content":[{"Card":cardid0,"Action":"0"}],
"MessageTime":datatime,
}
}

#下发TCP协议的acl策略
AddAclPolicy_HitCount={
"AddAclPolicy":{
"MethodName":"AddAclPolicy",
"MessageTime":datatime,
 "Content":[{"SeLabelDrop":"","Action":"0","QosMode":"","SeLabelLevel":"","SeLabelBitmap":"","SeLabelType":"","QosThreshold":"","Dip":pcap_dip,"Ifname":Ifname,"QosBucket":"","Listorder":"1","Direction":"INPUT","TTL":"","SeLabelMatch":"",
             "Card":cardid0,"SeLabelMode":"","Sport":port_s,"Dport":port_d,"SeLabelTag":"","Sip":pcap_sip,"Protocol":"6","SeLabelDoi":""}]}
}

#移除acl策略
DelAclPolicy_HitCount={
"DelAclPolicy":{
"MethodName":"DelAclPolicy",
"MessageTime":datatime,
"Content":[{"Pid":"1","Card":cardid0}]}
}

#下发UDP协议的acl策略
AddAclPolicy_labelRejectPac={
"AddAclPolicy":{
"MethodName":"AddAclPolicy",
"MessageTime":datatime,
 "Content":[{"SeLabelDrop":"","Action":"0","QosMode":"","SeLabelLevel":"","SeLabelBitmap":"","SeLabelType":"","QosThreshold":"","Dip":pcap_dip,"Ifname":Ifname,"QosBucket":"","Listorder":"1","Direction":"INPUT","TTL":"","SeLabelMatch":"",
             "Card":cardid0,"SeLabelMode":"","Sport":port_s,"Dport":port_d,"SeLabelTag":"","Sip":pcap_sip,"Protocol":"17","SeLabelDoi":""}]}
}

#下发ICMP协议的acl策略
AddAclPolicy_labelPassPac={
"AddAclPolicy":{
"MethodName":"AddAclPolicy",
"MessageTime":datatime,
 "Content":[{"SeLabelDrop":"","Action":"0","QosMode":"","SeLabelLevel":"","SeLabelBitmap":"","SeLabelType":"","QosThreshold":"","Dip":pcap_dip,"Ifname":Ifname,"QosBucket":"","Listorder":"1","Direction":"INPUT","TTL":"","SeLabelMatch":"",
             "Card":cardid0,"SeLabelMode":"","Sport":"","Dport":"","SeLabelTag":"","Sip":pcap_sip,"Protocol":"1","SeLabelDoi":""}]}
}
