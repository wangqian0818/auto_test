
from common import baseinfo
import time


datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
front_ifname = baseinfo.BG8010FrontOpeIfname
back_ifname = baseinfo.BG8010BackOpeIfnameOutside
windows_sip = baseinfo.windows_sip
front_cardid = baseinfo.BG8010FrontCardid
back_cardid = baseinfo.BG8010BackCardid
http_server = baseinfo.http_server
http_server_port = baseinfo.http_server_port
iso_timeout = baseinfo.iso_timeout
http_proxy_port = baseinfo.http_proxy_port
serverIp = baseinfo.BG8010ServerOpeIp
clientIp = baseinfo.BG8010ClientOpeIp
ssh_proxy_port = baseinfo.ssh_proxy_port



addtcp_front = {
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
"Appid":4,
"L3protocol":"ipv4",
"Timeout":iso_timeout,
"Dport":http_server_port,
"SeLabel":{},
"File":"off",
"Lport":http_proxy_port,
"L4protocol":"tcp"}]
}]}
}

addtcp_back = {
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
"Appid":4,
"L3protocol":"ipv4",
"Timeout":iso_timeout,
"Dport":http_server_port,
"SeLabel":{},
"File":"off",
"Lport":http_proxy_port,
"L4protocol":"tcp"}]
}]}
}

addtcp_ssh_front = {
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
"Appid":30,
"L3protocol":"ipv4",
"Timeout":iso_timeout,
"Dport":22,
"SeLabel":{},
"File":"off",
"Lport":ssh_proxy_port,
"L4protocol":"tcp"}]
}]}
}

addtcp_ssh_back = {
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
"Appid":30,
"L3protocol":"ipv4",
"Timeout":iso_timeout,
"Dport":22,
"SeLabel":{},
"File":"off",
"Lport":ssh_proxy_port,
"L4protocol":"tcp"}]
}]}
}

deltcp_front = {
"DelCustomAppPolicy":{
"MethodName":"DelCustomAppPolicy",
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
"Appid":4,
"L3protocol":"ipv4",
"Timeout":iso_timeout,
"Dport":http_server_port,
"Lport":http_proxy_port,
"L4protocol":"tcp"}]
}]}
}

deltcp_back = {
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
"Appid":4,
"L3protocol":"ipv4",
"Timeout":iso_timeout,
"Dport":http_server_port,
"Lport":http_proxy_port,
"L4protocol":"tcp"}]
}]}
}

deltcp_ssh_front = {
"DelCustomAppPolicy":{
"MethodName":"DelCustomAppPolicy",
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
"Appid":30,
"L3protocol":"ipv4",
"Timeout":iso_timeout,
"Dport":22,
"Lport":ssh_proxy_port,
"L4protocol":"tcp"}]}
]}
}

deltcp_ssh_back = {
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
"Appid":30,
"L3protocol":"ipv4",
"Timeout":iso_timeout,
"Dport":22,
"Lport":ssh_proxy_port,
"L4protocol":"tcp"}]
}]}
}
