from report_acl_count import index
import time
from common import baseinfo
#from report_acl_count import index
datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
pcap_dip = baseinfo.serverOpeIp
pcap_sip = baseinfo.clientOpeIp
domain = baseinfo.rbmDomain
Ifname= baseinfo.pcapGwIface

cardid0 = index.card_id0
port_d = index.dport
port_s = index.sport
Level_ACL_RejectPac = index.SeLabelLevel_ACL_labelRejectPac
Level_common = index.SeLabelLevel_common
value = index.SeLabelBitmap
QosData = index.QosThreshold_QosData
QosRate = index.QosThreshold_QosRate

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

#下发acl策略HitCount
AddAclPolicy_HitCount={
"AddAclPolicy":{
"MethodName":"AddAclPolicy",
"MessageTime":datatime,
 "Content":[{"SeLabelDrop":"","Action":"0","QosMode":"","SeLabelLevel":"","SeLabelBitmap":"","SeLabelType":"","QosThreshold":"","Dip":pcap_dip,"Ifname":Ifname,"QosBucket":"","Listorder":"1","Direction":"INPUT","TTL":"","SeLabelMatch":"",
             "Card":cardid0,"SeLabelMode":"","Sport":port_s,"Dport":port_d,"SeLabelTag":"","Sip":pcap_sip,"Protocol":"6","SeLabelDoi":""}]
}
}

#移除acl策略
DelAclPolicy_HitCount={
"DelAclPolicy":{
"MethodName":"DelAclPolicy",
"MessageTime":datatime,
"Content":[{"Pid":"1","Card":cardid0}]}
}

#下发acl策略labelRejectPac
AddAclPolicy_labelRejectPac={
"AddAclPolicy":{
"MethodName":"AddAclPolicy",
"MessageTime":datatime,
"Content": [{"SeLabelDrop": 1, "Action": "0", "QosMode": "", "SeLabelLevel": Level_ACL_RejectPac, "SeLabelBitmap": value, "SeLabelType": 1, "QosThreshold": "", "Dip": pcap_dip, "Ifname": Ifname, "QosBucket": "",
             "Listorder": "1", "Direction": "INPUT", "TTL": "", "SeLabelMatch": 1, "Card": cardid0, "SeLabelMode": "BLP", "Sport": port_s, "Dport": port_d, "SeLabelTag": 2, "Sip": pcap_sip,
             "Protocol": "6", "SeLabelDoi": 16}]}
}

#下发acl策略labelPassPac
AddAclPolicy_labelPassPac={
"AddAclPolicy":{
"MethodName":"AddAclPolicy",
"MessageTime":datatime,
"Content":[{"SeLabelDrop":1,"Action":"0","QosMode":"","SeLabelLevel":Level_common,"SeLabelBitmap":value,"SeLabelType":1,"QosThreshold":"","Dip":pcap_dip,"Ifname":Ifname,
                "QosBucket":"","Listorder":"1","Direction":"INPUT","TTL":"","SeLabelMatch":1,"Card":cardid0,"SeLabelMode":"BLP","Sport":port_s,"Dport":port_d,
                "SeLabelTag":2,"Sip":pcap_sip,"Protocol":"6","SeLabelDoi":16}]}
}

#下发acl策略QosData
AddAclPolicy_QosData={
"AddAclPolicy":{
"MethodName":"AddAclPolicy",
"MessageTime":datatime,
"Content":[{"SeLabelDrop":"","Action":"0","QosMode":1,"SeLabelLevel":"","SeLabelBitmap":"","SeLabelType":"","QosThreshold":QosData,"Dip":pcap_dip,"Ifname":Ifname,
                "QosBucket":0,"Listorder":"1","Direction":"INPUT","TTL":"","SeLabelMatch":"","Card":cardid0,"SeLabelMode":"","Sport":port_s,"Dport":port_d,"SeLabelTag":"","Sip":pcap_sip,"Protocol":"6","SeLabelDoi":""}]}
}

#下发acl策略QosRate
AddAclPolicy_QosRate={
"AddAclPolicy":{
"MethodName":"AddAclPolicy",
"MessageTime":datatime,
 "Content":[{"SeLabelDrop":"","Action":"0","QosMode":0,"SeLabelLevel":"","SeLabelBitmap":"","SeLabelType":"","QosThreshold":QosRate,"Dip":pcap_dip,"Ifname":Ifname,
                "QosBucket":0,"Listorder":"1","Direction":"INPUT","TTL":"","SeLabelMatch":"","Card":cardid0,"SeLabelMode":"","Sport":port_s,"Dport":port_d,"SeLabelTag":"","Sip":pcap_sip,"Protocol":"6","SeLabelDoi":""}]}
}
