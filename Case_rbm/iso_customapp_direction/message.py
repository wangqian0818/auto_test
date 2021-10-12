
from common import baseinfo
import time
from iso_customapp_direction import index


datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
front_ifname = baseinfo.BG8010FrontOpeIfname
back_ifname = baseinfo.BG8010BackOpeIfnameOutside

front_cardid = baseinfo.BG8010FrontCardid
back_cardid = baseinfo.BG8010BackCardid

windows_sip = baseinfo.windows_sip
http_server = baseinfo.http_server
# http_serverip = baseinfo.BG8010ServerOpeIp
http_server_port = baseinfo.http_server_port
Lport = baseinfo.app_proxy_port
iso_timeout = baseinfo.iso_timeout

###massage�������С����С�˫��ǰ������Ķ���Ӧ�ò��ԣ�����һ��ɾ������del_app_upstream_front��del_app_upstream_back###
add_app_upstream_front = {
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
     "Action":"allow",
     "Appid":101,
     "L3protocol":"ipv4",
     "Timeout":iso_timeout,
     "Dport":http_server_port,
     "SeLabel":{},
     "File":"off",
"Rules":[{
     "Action":"deny",
     "Cmds":[{"offset":0,"cmd":"http"}],"Direction":"upstream"}],"Lport":Lport,"L4protocol":"tcp"}]
 }]
}
}


add_app_upstream_back = {
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
    "Action":"allow",
    "Appid":101,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":http_server_port,
    "SeLabel":{},
    "File":"off",
"Rules":[{
    "Action":"deny",
    "Cmds":[{"offset":0,"cmd":"http"}],"Direction":"upstream"}],"Lport":Lport,"L4protocol":"tcp"}]
}]
}
}


add_app_downstream_front = {
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
    "Action":"allow",
    "Appid":101,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":http_server_port,
    "SeLabel":{},
    "File":"off",
"Rules":[{
    "Action":"deny",
    "Cmds":[{"offset":0,"cmd":"get"}],"Direction":"downstream"}],"Lport":Lport,"L4protocol":"tcp"}]}]
}
}

add_app_downstream_back = {
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
    "Action":"allow",
    "Appid":101,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":http_server_port,
    "SeLabel":{},
    "File":"off",
"Rules":[{
    "Action":"deny",
    "Cmds":[{"offset":0,"cmd":"get"}],"Direction":"downstream"}],"Lport":Lport,"L4protocol":"tcp"}]}]
}
}




add_app_twoway_front = {
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
    "Appid":103,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":http_server_port,
     "SeLabel":{},
    "File":"off",
"Rules":[{
     "Action":"allow",
     "Cmds":[{"offset":0,"roffset":9,"rcode":"200","cmd":"get"}],"Direction":"twoway"}],"Lport":Lport,"L4protocol":"tcp"}]}]
}
}

add_app_twoway_back = {
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
    "Appid":103,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":http_server_port,
    "SeLabel":{},
    "File":"off",
"Rules":[{
    "Action":"allow",
    "Cmds":[{"offset":0,"roffset":9,"rcode":"200","cmd":"get"}],"Direction":"twoway"}],"Lport":Lport,"L4protocol":"tcp"}]}]
}
}



del_app_action_front = {
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
    "Appid": 103,
    "L3protocol": "ipv4",
    "Timeout": iso_timeout,
    "Dport": http_server_port,
    "Lport": Lport,
    "L4protocol": "tcp"}]}]
}
}

del_app_action_back = {
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
    "Appid": 103,
    "L3protocol": "ipv4",
    "Timeout": iso_timeout,
    "Dport": http_server_port,
    "Lport": Lport,
    "L4protocol": "tcp"}]}]
}
}

del_app_upstream_front = {
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
    "Action": "allow",
    "Appid": 101,
    "L3protocol": "ipv4",
    "Timeout": iso_timeout,
    "Dport": http_server_port,
    "Lport": Lport,
    "L4protocol": "tcp"}]
}]
}
}

del_app_upstream_back ={
"DelCustomAppPolicy":{
"MethodName":"DelCustomAppPolicy",
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
    "Action":"allow",
    "Appid":101,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":http_server_port,
    "Lport":Lport,
    "L4protocol":"tcp"}]
}]
}
}




