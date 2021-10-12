
from common import baseinfo
import time
from verifymod_switch import index


datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
verifymod_ip = baseinfo.gwClientIp
verifymod_port = index.verifymod_port
verifymod_port1 = index.verifymod_port1

###massage�������С����С�˫��ǰ������Ķ���Ӧ�ò��ԣ�����һ��ɾ������del_app_upstream_front��del_app_upstream_back###
verifymod_switch_start = {
"ManageAuthServer":{
"MethodName":"ManageAuthServer",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "AuthServerIp":verifymod_ip,
    "AuthServerPort":verifymod_port,
    "Enable":1}]
}
}

verifymod_switch_stop = {
"ManageAuthServer":{
"MethodName":"ManageAuthServer",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "AuthServerIp":"",
    "Enable":0}]
}
}

verifymod_switch_restart = {
"ManageAuthServer":{
"MethodName":"ManageAuthServer",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "AuthServerIp":verifymod_ip,
    "AuthServerPort":verifymod_port1,
    "Enable":2}]
}
}





