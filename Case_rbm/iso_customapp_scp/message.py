
from common import baseinfo
import time
from iso_customapp_scp import index


datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
front_ifname = baseinfo.BG8010FrontOpeIfname
back_ifname = baseinfo.BG8010BackOpeIfnameOutside

front_cardid = baseinfo.BG8010FrontCardid
back_cardid = baseinfo.BG8010BackCardid

clientIp = baseinfo.BG8010ClientOpeIp
# http_serverip = baseinfo.http_server
serverIp = baseinfo.BG8010ServerOpeIp
ssh_dport = index.scp_dport
ssh_proxy_port = baseinfo.ssh_proxy_port
iso_timeout = baseinfo.iso_timeout


add_app_scp_upload_front = {
"AddCustomAppPolicy":{
"MethodName":"AddCustomAppPolicy",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Ifname":front_ifname,
    "Dip":serverIp,
    "Sip":clientIp,
    "Domain":"src",
    "Cards":front_cardid,
"Applist":[{
    "Sport":"1-65535",
    "Action":"allow",
    "Appid":102,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":ssh_dport,
    "SeLabel":{},
    "File":"off",
"Rules":[{
    "Action":"allow",
    "Cmds":[{"offset":0,"cmd":"SSH"}],"Direction":"downstream"}],"Lport":ssh_proxy_port,"L4protocol":"tcp"}]}]
}
}

add_app_scp_upload_back = {
"AddCustomAppPolicy":{
"MethodName":"AddCustomAppPolicy",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Ifname":back_ifname,
    "Dip":serverIp,
    "Sip":clientIp,
    "Domain":"dest",
    "Cards":back_cardid,
"Applist":[{
    "Sport":"1-65535",
    "Action":"allow",
    "Appid":102,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":ssh_dport,
    "SeLabel":{},
    "File":"off",
"Rules":[{
    "Action":"allow",
    "Cmds":[{"offset":0,"cmd":"SSH"}],"Direction":"downstream"}],"Lport":ssh_proxy_port,"L4protocol":"tcp"}]}]
}
}




add_app_scp_download_front = {
"AddCustomAppPolicy":{
"MethodName":"AddCustomAppPolicy",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Ifname":front_ifname,
    "Dip":serverIp,
    "Sip":clientIp,
    "Domain":"src",
    "Cards":front_cardid,
"Applist":[{
    "Sport":"1-65535",
    "Action":"allow",
    "Appid":102,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":ssh_dport,
    "SeLabel":{},
    "File":"off",
"Rules":[{
    "Action":"allow",
    "Cmds":[{"offset":0,"cmd":"SSH"}],"Direction":"downstream"}],"Lport":ssh_proxy_port,"L4protocol":"tcp"}]}]
}
}

add_app_scp_download_back = {
"AddCustomAppPolicy":{
"MethodName":"AddCustomAppPolicy",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Ifname":back_ifname,
    "Dip":serverIp,
    "Sip":clientIp,
    "Domain":"dest",
    "Cards":back_cardid,
"Applist":[{
    "Sport":"1-65535",
    "Action":"allow",
    "Appid":102,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":ssh_dport,
    "SeLabel":{},
    "File":"off",
"Rules":[{
    "Action":"allow",
    "Cmds":[{"offset":0,"cmd":"SSH"}],"Direction":"downstream"}],"Lport":ssh_proxy_port,"L4protocol":"tcp"}]}]
}
}




del_app_scp_front = {
"DelCustomAppPolicy":{
"MethodName": "DelCustomAppPolicy",
"MessageTime": datatime,
"Sender": "Centre0",
"Content": [{
    "Ifname": front_ifname,
    "Dip": serverIp,
    "Sip": clientIp,
    "Domain": "src",
    "Cards": front_cardid,
    "Applist": [{
    "Sport": "1-65535",
    "Action": "allow",
    "Appid": 102,
    "L3protocol": "ipv4",
    "Timeout": iso_timeout,
    "Dport":ssh_dport ,
    "Lport": ssh_proxy_port,
    "L4protocol": "tcp"}]
}]
}
}

del_app_scp_back ={
"DelCustomAppPolicy":{
"MethodName":"DelCustomAppPolicy",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Ifname":back_ifname,
    "Dip":serverIp,
    "Sip":clientIp,
    "Domain":"dest",
    "Cards":back_cardid,
    "Applist":[{
    "Sport":"1-65535",
    "Action":"allow",
    "Appid":102,
    "L3protocol":"ipv4",
    "Timeout":iso_timeout,
    "Dport":ssh_dport,
    "Lport":ssh_proxy_port,
    "L4protocol":"tcp"}]
}]
}
}









