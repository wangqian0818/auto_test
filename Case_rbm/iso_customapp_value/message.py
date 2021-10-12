
from common import baseinfo
import time
from iso_customapp_value import index

value_1 = '"'+index.value1+'"'
value_2 = '"'+index.value2+'"'
value_3 = '"'+index.value3+'"'
value_4 = '"'+index.value4+'"'
value_5 = '"'+'0x32303020'+'"'
value_6 = '"'+'540028978'+'"'


datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
front_ifname = baseinfo.BG8010FrontOpeIfname
back_ifname = baseinfo.BG8010BackOpeIfnameOutside

front_cardid = baseinfo.BG8010FrontCardid
back_cardid = baseinfo.BG8010BackCardid

client_opeip = baseinfo.BG8010ClientOpeIp
windows_sip = baseinfo.windows_sip
http_server = baseinfo.http_server
# http_serverip = baseinfo.BG8010ServerOpeIp
http_server_port = baseinfo.http_server_port

Lport = baseinfo.app_proxy_port
iso_timeout = baseinfo.iso_timeout
para = index.app_ip

###massage�������С����С�˫��ǰ������Ķ���Ӧ�ò��ԣ�����һ��ɾ������del_app_upstream_front��del_app_upstream_back###
add_app_massage_value_equal_front = {
"AddCustomAppPolicy":{
"MethodName":"AddCustomAppPolicy",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Ifname":front_ifname,
    "Dip":http_server,
    "Sip":windows_sip,
    "Domain":"src",
    "Cards":front_cardid,
"Applist":[{
    "Sport":"1-65535",
    "Action":"deny",
    "Appid":104,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":http_server_port,
    "SeLabel":{},
    "End":"\\r\\n",
    "File":"off",
"Rules":[
    # {"Action":"allow","Cmpns":[{"offset":6,"value":"0x50545448","operation":"=","nnn":4}],"Direction":"downstream"},
    {"Action": "allow", "Cmpns":[{"offset":9,"value":value_5,"operation":"=","nnn":4}], "Direction": "upstream"},
    {"Action": "allow", "Cmpns":[{"offset":6,"value":value_1,"operation":"=","nnn":4}], "Direction": "downstream"}],
    "Lport":Lport,"L4protocol":"tcp"}]}]
}
}

add_app_massage_value_equal_back = {
"AddCustomAppPolicy":{
"MethodName":"AddCustomAppPolicy",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Ifname":back_ifname,
    "Dip":http_server,
    "Sip":windows_sip,
    "Domain":"dest",
    "Cards":back_cardid,
"Applist":[{
    "Sport":"1-65535",
    "Action":"deny",
    "Appid":104,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":http_server_port,
    "SeLabel":{},
    "File":"off",
    "End":"\\r\\n",
"Rules":[
    # {"Action":"allow","Cmpns":[{"offset":6,"value":"0x50545448","operation":"=","nnn":4}],"Direction":"downstream"},
    {"Action": "allow", "Cmpns":[{"offset":9,"value":value_5,"operation":"=","nnn":4}], "Direction": "upstream"},
    {"Action": "allow", "Cmpns":[{"offset":6,"value":value_1,"operation":"=","nnn":4}], "Direction": "downstream"}],
    "Lport":Lport,"L4protocol":"tcp"}]}]

}
}


add_app_massage_value_gt_front = {
"AddCustomAppPolicy":{
"MethodName":"AddCustomAppPolicy",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Ifname":front_ifname,
    "Dip":http_server,
    "Sip":windows_sip,
    "Domain":"src",
    "Cards":front_cardid,
"Applist":[{
    "Sport":"1-65535",
    "Action":"deny",
    "Appid":104,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":http_server_port,
    "SeLabel":{},
    "End":"\\r\\n",
    "File":"off",
"Rules":[
    # {"Action":"allow","Cmpns":[{"offset":6,"value":"0x50545447","operation":">","nnn":4}],"Direction":"downstream"},
    {"Action": "allow", "Cmpns":[{"offset":9,"value":value_5,"operation":"=","nnn": 4}], "Direction": "upstream"},
    {"Action": "allow", "Cmpns":[{"offset":6,"value":value_2,"operation":">","nnn":4}], "Direction": "downstream"}],
    "Lport":Lport,"L4protocol":"tcp"}]}]
}
}

add_app_massage_value_gt_back = {
"AddCustomAppPolicy":{
"MethodName":"AddCustomAppPolicy",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Ifname":back_ifname,
    "Dip":http_server,
    "Sip":windows_sip,
    "Domain":"dest",
    "Cards":back_cardid,
"Applist":[{
    "Sport":"1-65535",
    "Action":"deny",
    "Appid":104,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":http_server_port,
    "SeLabel":{},
    "End":"\\r\\n",
    "File":"off",
"Rules":[
    # {"Action":"allow","Cmpns":[{"offset":6,"value":"0x50545447","operation":">","nnn":4}],"Direction":"downstream"},
    {"Action": "allow", "Cmpns":[{"offset":9,"value":value_5,"operation":"=","nnn": 4}], "Direction": "upstream"},
    {"Action": "allow", "Cmpns":[{"offset":6,"value":value_2,"operation":">","nnn":4}], "Direction": "downstream"}],
    "Lport":Lport,"L4protocol":"tcp"}]}]
}
}

add_app_massage_value_lt_front = {
"AddCustomAppPolicy":{
"MethodName":"AddCustomAppPolicy",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Ifname":front_ifname,
    "Dip":http_server,
    "Sip":windows_sip,
    "Domain":"src",
    "Cards":front_cardid,
"Applist":[{
    "Sport":"1-65535",
    "Action":"deny",
    "Appid":104,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":http_server_port,
    "SeLabel":{},
    "End":"\\r\\n",
    "File":"off",
"Rules":[
    # {"Action":"allow","Cmpns":[{"offset":6,"value":"0x50545449","operation":"<","nnn":4}],"Direction":"downstream"}
    {"Action": "allow", "Cmpns": [{"offset": 9, "value": value_5, "operation": "=", "nnn": 4}],"Direction": "upstream"},
    {"Action": "allow", "Cmpns": [{"offset": 6, "value": value_3, "operation": "<", "nnn": 4}],"Direction": "downstream"}],
    "Lport":Lport,"L4protocol":"tcp"}]}]
}
}

add_app_massage_value_lt_back = {
"AddCustomAppPolicy":{
"MethodName":"AddCustomAppPolicy",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Ifname":back_ifname,
    "Dip":http_server,
    "Sip":windows_sip,
    "Domain":"dest",
    "Cards":back_cardid,
"Applist":[{
    "Sport":"1-65535",
    "Action":"deny",
    "Appid":104,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":http_server_port,
    "SeLabel":{},
    "End":"\\r\\n",
    "File":"off",
"Rules":[
    # {"Action":"allow","Cmpns":[{"offset":6,"value":"0x50545449","operation":"<","nnn":4}],"Direction":"downstream"}
    {"Action": "allow", "Cmpns": [{"offset": 9, "value": value_5, "operation": "=", "nnn": 4}],"Direction": "upstream"},
    {"Action": "allow", "Cmpns": [{"offset": 6, "value": value_3, "operation": "<", "nnn": 4}],"Direction": "downstream"}],
    "Lport":Lport,"L4protocol":"tcp"}]}]
}
}

add_app_value_end_front = {
"AddCustomAppPolicy":{
"MethodName":"AddCustomAppPolicy",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
     "Ifname":front_ifname,
     "Dip":http_server,
     "Sip":windows_sip,
     "Domain":"src",
     "Cards":front_cardid,
"Applist":[{
    "Sport":"1-65535",
    "Action":"deny",
    "Appid":104,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":http_server_port,
    "SeLabel":{},
    "End":"\\r\\n",
    "File":"off",
"Rules":[
    # {"Action":"allow","Cmpns":[{"offset":6,"end":"/","value":"0x50545448","operation":"=","nnn":4}],"Direction":"downstream"},
    {"Action": "allow", "Cmpns": [{"offset": 9, "value": value_5, "operation": "=", "nnn": 4}], "Direction": "upstream"},
    {"Action": "allow", "Cmpns":[{"offset":6,"end":"/","value":value_1,"operation":"=","nnn":4}], "Direction": "downstream"}],
    "Lport":Lport,"L4protocol":"tcp"}]}]
}
}

add_app_value_end_back = {
"AddCustomAppPolicy":{
"MethodName":"AddCustomAppPolicy",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Ifname":back_ifname,
    "Dip":http_server,
    "Sip":windows_sip,
    "Domain":"dest",
    "Cards":back_cardid,
"Applist":[{
    "Sport":"1-65535",
    "Action":"deny",
    "Appid":104,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":http_server_port,
    "SeLabel":{},
    "End":"\\r\\n",
    "File":"off",
"Rules":[
    # {"Action":"allow","Cmpns":[{"offset":6,"end":"/","value":"0x50545448","operation":"=","nnn":4}],"Direction":"downstream"},
    {"Action": "allow", "Cmpns": [{"offset": 9, "value": value_5, "operation": "=", "nnn": 4}], "Direction": "upstream"},
    {"Action": "allow", "Cmpns":[{"offset":6,"end":"/","value":value_1,"operation":"=","nnn":4}], "Direction": "downstream"}],
    "Lport": Lport, "L4protocol": "tcp"}]}]
}
}

add_app_value_byte_front = {
"AddCustomAppPolicy":{
"MethodName":"AddCustomAppPolicy",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Ifname":front_ifname,
    "Dip":http_server,
    "Sip":windows_sip,
    "Domain":"src",
    "Cards":front_cardid,
"Applist":[{
    "Sport":"1-65535",
    "Action":"deny",
    "Appid":104,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":http_server_port,
    "SeLabel":{},
    "End":"\\r\\n",
    "File":"off",
"Rules":[
    # {"Action":"allow","Cmpns":[{"offset":6,"value":"0x50545448","operation":"=","nnn":4}],"Direction":"downstream"},
    {"Action": "allow", "Cmpns": [{"offset": 9, "value": value_5, "operation": "=", "nnn": 4}], "Direction": "upstream"},
    {"Action": "allow", "Cmpns": [{"offset": 6, "value": value_1, "operation": "=", "nnn": 4}], "Direction": "downstream"}],
    "Lport": Lport, "L4protocol": "tcp"}]}]
}
}

add_app_value_byte_back = {
"AddCustomAppPolicy":{
"MethodName":"AddCustomAppPolicy",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Ifname":back_ifname,
    "Dip":http_server,
    "Sip":windows_sip,
    "Domain":"dest",
    "Cards":back_cardid,
"Applist":[{
    "Sport":"1-65535",
    "Action":"deny",
    "Appid":104,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":http_server_port,
    "SeLabel":{},
    "End":"\\r\\n",
    "File":"off",
"Rules":[
    # {"Action":"allow","Cmpns":[{"offset":6,"value":"0x50545448","operation":"=","nnn":4}],"Direction":"downstream"},
    {"Action": "allow", "Cmpns": [{"offset": 9, "value": value_5, "operation": "=", "nnn": 4}], "Direction": "upstream"},
    {"Action": "allow", "Cmpns": [{"offset": 6, "value": value_1, "operation": "=", "nnn": 4}], "Direction": "downstream"}],
    "Lport": Lport, "L4protocol": "tcp"}]}]
}
}


add_app_value_byte_end_front = {
"AddCustomAppPolicy":{
"MethodName":"AddCustomAppPolicy",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Ifname":front_ifname,
    "Dip":http_server,
    "Sip":windows_sip,
    "Domain":"src",
    "Cards":front_cardid,
"Applist":[{
    "Sport":"1-65535",
    "Action":"deny",
    "Appid":104,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":http_server_port,
    "SeLabel":{},
    "End":"\\r\\n",
    "File":"off",
"Rules":[
    # {"Action":"allow","Cmpns":[{"offset":6,"end":"/","value":"0x50545448","operation":"=","nnn":4}],"Direction":"downstream"},
    {"Action": "allow", "Cmpns": [{"offset": 9, "value": value_5, "operation": "=", "nnn": 4}], "Direction": "upstream"},
    {"Action": "allow", "Cmpns":[{"offset":6,"end":"/","value":value_1,"operation":"=","nnn":4}], "Direction": "downstream"}],
    "Lport":Lport,"L4protocol":"tcp"}]}]
}
}

add_app_value_byte_end_back = {
"AddCustomAppPolicy":{
"MethodName":"AddCustomAppPolicy",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Ifname":back_ifname,
    "Dip":http_server,
    "Sip":windows_sip,
    "Domain":"dest",
    "Cards":back_cardid,
"Applist":[{
    "Sport":"1-65535",
    "Action":"deny",
    "Appid":104,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":http_server_port,
    "SeLabel":{},
    "End":"\\r\\n",
    "File":"off",
"Rules":[
     # {"Action":"allow","Cmpns":[{"offset":6,"end":"/","value":"0x50545448","operation":"=","nnn":4}],"Direction":"downstream"},
    {"Action": "allow", "Cmpns": [{"offset": 9, "value": value_5, "operation": "=", "nnn": 4}], "Direction": "upstream"},
    {"Action": "allow", "Cmpns":[{"offset":6,"end":"/","value":value_1,"operation":"=","nnn":4}], "Direction": "downstream"}],
    "Lport":Lport,"L4protocol":"tcp"}]}]
}
}


add_app_value_decimalism_front = {
"AddCustomAppPolicy":{
"MethodName":"AddCustomAppPolicy",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Ifname":front_ifname,
    "Dip":http_server,
    "Sip":windows_sip,
    "Domain":"src",
    "Cards":front_cardid,
"Applist":[{
    "Sport":"1-65535",
    "Action":"deny",
    "Appid":104,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":http_server_port,
    "SeLabel":{},
    "End":"\\r\\n",
    "File":"off",
"Rules":[
    {"Action": "allow", "Cmpns": [{"offset": 9, "value": value_6, "operation": "=", "nnn": 4}], "Direction": "upstream"},
    {"Action": "allow", "Cmpns":[{"offset":6,"end":"/","value":value_4,"operation":"=","nnn":4}], "Direction": "downstream"}],
    "Lport":Lport,"L4protocol":"tcp"}]}]

}
}

add_app_value_decimalism_back = {
"AddCustomAppPolicy":{
"MethodName":"AddCustomAppPolicy",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Ifname":back_ifname,
    "Dip":http_server,
    "Sip":windows_sip,
    "Domain":"dest",
    "Cards":back_cardid,
"Applist":[{
    "Sport":"1-65535",
    "Action":"deny",
    "Appid":104,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":http_server_port,
    "SeLabel":{},
    "End":"\\r\\n",
    "File":"off",
"Rules":[
    {"Action": "allow", "Cmpns": [{"offset": 9, "value": value_6, "operation": "=", "nnn": 4}], "Direction": "upstream"},
    {"Action": "allow", "Cmpns":[{"offset":6,"end":"/","value":value_4,"operation":"=","nnn":4}], "Direction": "downstream"}],
    "Lport":Lport,"L4protocol":"tcp"}]}]
}
}


del_app_end_deny_front = {
"DelCustomAppPolicy":{
"MethodName": "DelCustomAppPolicy",
"MessageTime": datatime,
"Sender": "Centre0",
"Content": [{
    "Ifname": front_ifname,
    "Dip": http_server,
    "Sip": windows_sip,
    "Domain": "src",
    "Cards": front_cardid,
    "Applist": [{
    "Sport": "1-65535",
    "Action": "deny",
    "Appid": 104,
    "L3protocol": "ipv4",
    "Timeout": iso_timeout,
    "Dport": http_server_port,
    "End":"\\r\\n",
    "Lport": Lport,
    "L4protocol": "tcp"}]}]
}
}

del_app_end_deny_back = {
"DelCustomAppPolicy":{
"MethodName": "DelCustomAppPolicy",
"MessageTime": datatime,
"Sender": "Centre0",
"Content": [{
    "Ifname": back_ifname,
    "Dip": http_server,
    "Sip": windows_sip,
    "Domain": "dest",
    "Cards": back_cardid,
    "Applist": [{
    "Sport": "1-65535",
    "Action": "deny",
    "Appid": 104,
    "L3protocol": "ipv4",
    "Timeout": iso_timeout,
    "Dport": http_server_port,
    "End":"\\r\\n",
    "Lport": Lport,
    "L4protocol": "tcp"}]}]
}
}