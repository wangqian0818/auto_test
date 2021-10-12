
from common import baseinfo
import time
from modsecurity_switch import index


datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
dip = baseinfo.serverOpeIp
port = index.modsecurity_port
###massage�������С����С�˫��ǰ������Ķ���Ӧ�ò��ԣ�����һ��ɾ������del_app_upstream_front��del_app_upstream_back###
modsecurity_AddAgent = {
"AddAgent":{
"MethodName":"AddAgent",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "InProtocol": "http",
    "Type": 1,
    "InPort": port,
    "OutAddr": [{"OutPort": port, "OutIp": dip}],
    "InIp": dip}]
}
}

modsecurity_DelAgent = {
"DelAgent":{
"MethodName":"DelAgent",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "InProtocol":"http",
    "Type":1,
    "InPort":port,
    "OutAddr":[{"OutPort":port,"OutIp":dip}],
    "InIp":dip}]
}
}

modsecurity_SetAppProtectEnable_open = {
"SetAppProtectEnable":{
"MethodName":"SetAppProtectEnable",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Enable":1}]
}
}

modsecurity_SetAppProtectEnable_close = {
"SetAppProtectEnable":{
"MethodName":"SetAppProtectEnable",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Enable":0}]
}
}