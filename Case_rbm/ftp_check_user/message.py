import time
from common import baseinfo
from ftp_check_user import index

datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
proxy_ip = baseinfo.gwInternetIp
ftp_ip = baseinfo.ftp_ip
username = index.username
case2_allow_user = index.case2_allow_user
ftp_proxy_port = baseinfo.ftp_proxy_port

addftp = {
'AddAgent':{
"MethodName":"AddAgent",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"InProtocol":"ftp",
"Type":2,
"InPort":ftp_proxy_port,
"domain":"all",
"SyncId":87,
"OutAddr":[{"OutPort":21,"OutIp":ftp_ip}],
"InIp":proxy_ip
}]
}}
delftp = {
'DelAgent':{
"MethodName":"DelAgent",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"InProtocol":"ftp",
"Type":2,
"InPort":ftp_proxy_port,
"domain":"all",
"SyncId":87,
"OutAddr":[{"OutPort":21,"OutIp":ftp_ip}],
"InIp":proxy_ip
}]}
}
ftpcheck1 = {'SetFtpCheck':{
"MethodName":"SetFtpCheck",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"Type":"user","DataCheck":username}
]}
}
ftpcheck2 = {'SetFtpCheck':{
"MethodName":"SetFtpCheck",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"Type":"user","DataCheck":f'{username};{case2_allow_user}'}
]}
}

delftpcheck = {'DropFtpCheck':{
"MethodName":"DropFtpCheck",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[]
}}
