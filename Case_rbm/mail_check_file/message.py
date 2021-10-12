import time
from common import baseinfo
from mail_check_file import index

datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
proxy_ip = baseinfo.gwInternetIp
smtp_ip = baseinfo.smtp_ip
pop3_ip = baseinfo.pop3_ip
mail_proxy_port = baseinfo.mail_proxy_port
pop3_server_port = baseinfo.pop3_server_port
case1_filename = index.case1_filename
case2_filename = index.case2_filename
case2_deny_file = index.case2_deny_file

addsmtp = {
'AddAgent':{
"MethodName":"AddAgent",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"InProtocol":"smtp",
"Type":2,
"InPort":mail_proxy_port,
"domain":"all",
"SyncId":85,
"OutAddr":[{"OutPort":25,"OutIp":smtp_ip}],
"InIp":proxy_ip
}]
}}
addpop3 = {
'AddAgent':{
"MethodName":"AddAgent",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"InProtocol":"pop3",
"Type":2,
"InPort":pop3_server_port,
"domain":"all",
"SyncId":86,
"OutAddr":[{"OutPort":110,"OutIp":pop3_ip}],
"InIp":proxy_ip
}]
}}
delsmtp = {'DelAgent':{
"MethodName":"DelAgent",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"InProtocol":"smtp",
"Type":2,
"InPort":mail_proxy_port,
"domain":"all",
"SyncId":85,
"OutAddr":[{"OutPort":25,"OutIp":smtp_ip}],
"InIp":proxy_ip
}]
}}
delpop3 = {
'DelAgent':{
"MethodName":"DelAgent",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"InProtocol":"pop3",
"Type":2,
"InPort":pop3_server_port,
"domain":"all",
"SyncId":86,
"OutAddr":[{"OutPort":110,"OutIp":pop3_ip}],
"InIp":proxy_ip
}]
}}
mailcheck1 = {
'SetMailCheck':{
"MethodName":"SetMailCheck",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"Type":"attachment",
"DataCheck":{"name":f'{case1_filename}'}}]
}}
mailcheck2 = {
'SetMailCheck':{
"MethodName":"SetMailCheck",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"Type":"attachment",
"DataCheck":{"name":f'{case2_filename};{case2_deny_file}'}}]
}}

delmailcheck = {
'DropMailCheck':{
"MethodName":"DropMailCheck",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[]}
}