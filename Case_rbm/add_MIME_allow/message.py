import time
from common import baseinfo
from add_MIME_allow import index

datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
proxy_ip = baseinfo.gwServerIp
proxy_port = index.proxy_port
server_ip = baseinfo.http_server
server_port = baseinfo.http_server_port
check1_uri = index.check1_uri
application_uri = index.application_uri
audio_uri = index.audio_uri
image_uri = index.image_uri
text_uri = index.text_uri
video_uri = index.video_uri

addhttp = {
'AddAgent':{
"MethodName":"AddAgent",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"InProtocol":"http",
"Type":2,
"InPort":proxy_port,
"domain":"all",
"SyncId":27,
"OutAddr":[{
"OutPort":server_port,
"OutIp":server_ip}],
"InIp":proxy_ip}]
}}
delhttp = {
'DelAgent':{
"MethodName":"DelAgent",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"InProtocol":"http",
"Type":2,
"InPort":proxy_port,
"domain":"all",
"SyncId":27,
"OutAddr":[{
"OutPort":server_port,
"OutIp":server_ip}],
"InIp":proxy_ip}]
}}
httpcheck1 = {
'SetHttpCheck':{
"MethodName":"SetHttpCheck",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"Type":"mime",
"DataCheck":[{"Action":0,
"Data":check1_uri}
]}]}
}
httpcheck2 = {
'SetHttpCheck':{
"MethodName":"SetHttpCheck",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"Type":"mime",
"DataCheck":[{"Action":0,
"Data":f"{application_uri};{audio_uri};{image_uri};{text_uri};{video_uri}"}
]}]}
}
