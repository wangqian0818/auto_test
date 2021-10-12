
from common import baseinfo
import time
from iso_customapp_order import index


datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
front_ifname = baseinfo.BG8010FrontOpeIfname
back_ifname = baseinfo.BG8010BackOpeIfnameOutside

front_cardid = baseinfo.BG8010FrontCardid
back_cardid = baseinfo.BG8010BackCardid

client_opeip = baseinfo.BG8010ClientOpeIp
windows_sip = baseinfo.windows_sip
# http_serverip = baseinfo.BG8010ServerOpeIp
http_server = baseinfo.http_server
http_server_port = baseinfo.http_server_port
Lport = baseinfo.app_proxy_port
iso_timeout = baseinfo.iso_timeout
para = index.app_ip

###massage�������С����С�˫��ǰ������Ķ���Ӧ�ò��ԣ�����һ��ɾ������del_app_upstream_front��del_app_upstream_back###
add_app_order_capital_front = {
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
    {"Action": "allow", "Cmds": [{"offset": 0, "cmd": "HTTP"}], "Direction": "upstream"},
    {"Action": "allow", "Cmds": [{"offset": 0, "cmd": "GET"}], "Direction": "downstream"}],
    "Lport":Lport,"L4protocol":"tcp"}]}]
}
}



add_app_order_capital_back = {
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
    {"Action": "allow", "Cmds": [{"offset": 0, "cmd": "HTTP"}], "Direction": "upstream"},
    {"Action": "allow", "Cmds": [{"offset": 0, "cmd": "GET"}], "Direction": "downstream"}],
    "Lport":Lport,"L4protocol":"tcp"}]}]
}
}

add_app_order_lowercase_front = {
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
    {"Action": "allow", "Cmds": [{"offset": 0, "cmd": "http"}], "Direction": "upstream"},
    {"Action": "allow", "Cmds": [{"offset": 0, "cmd": "get"}], "Direction": "downstream"}],
    "Lport":Lport,"L4protocol":"tcp"}]}]}

}



add_app_order_lowercase_back = {
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
    {"Action": "allow", "Cmds": [{"offset": 0, "cmd": "http"}], "Direction": "upstream"},
    {"Action": "allow", "Cmds": [{"offset": 0, "cmd": "get"}], "Direction": "downstream"}],
    "Lport":Lport,"L4protocol":"tcp"}]}]
}
}

add_app_order_other_character_front = {
"AddCustomAppPolicy":{
"MethodName": "AddCustomAppPolicy",
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
    "SeLabel": {},
    "End":"\\r\\n",
    "File": "off",
"Rules": [
    {"Action": "allow", "Cmds":[{"offset":0,"cmd":"http"}], "Direction": "upstream"},
    {"Action": "allow", "Cmds": [{"offset": 20, "cmd": ":"}], "Direction": "downstream"}],
    "Lport": Lport,"L4protocol": "tcp"}]}]
}
}

add_app_order_other_character_back = {
"AddCustomAppPolicy":{
"MethodName": "AddCustomAppPolicy",
"MessageTime": datatime,
"Sender": "Centre0",
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
    {"Action": "allow", "Cmds":[{"offset":0,"cmd":"http"}], "Direction": "upstream"},
    {"Action": "allow", "Cmds": [{"offset": 20, "cmd": ":"}], "Direction": "downstream"}],
    "Lport":Lport,"L4protocol":"tcp"}]}]
}
}

add_app_order_group_front = {
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
    {"Action": "allow", "Cmds":[{"offset":0,"cmd":"http"}], "Direction": "upstream"},
    {"Action": "allow", "Cmds":[{"offset":16,"para":para,"delimiter":":","end":"\\r\\n","cmd":"Host"}], "Direction": "downstream"}],
    "Lport":Lport,"L4protocol":"tcp"}]}]
}
}

add_app_order_group_back = {
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
    {"Action": "allow", "Cmds":[{"offset":0,"cmd":"http"}], "Direction": "upstream"},
    {"Action": "allow", "Cmds":[{"offset":16,"para":para,"delimiter":":","end":"\\r\\n","cmd":"Host"}], "Direction": "downstream"}],
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

