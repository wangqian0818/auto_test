import time

from common import baseinfo


datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

vlanA = str(baseinfo.vlanA)
vlanB = str(baseinfo.vlanB)
vlanIfname = baseinfo.gwVlanIfname
vlanIfname2 = baseinfo.gwVlanIfname2
vlanCard = baseinfo.gwVlanCard

setvlan = {
'SetVlan':{
"MethodName":"SetVlan",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"Cards":vlanCard,
"VlanList":[
{"Vid":f"{vlanA},{vlanB}","Ifnames":vlanIfname},
{"Vid":f"{vlanA},{vlanB}","Ifnames":vlanIfname2}]}]}
}

delvlan = {
'SetVlan':{
"MethodName":"SetVlan",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"Cards":vlanCard,
"VlanList":[
{"Vid":"","Ifnames":vlanIfname},
{"Vid":"","Ifnames":vlanIfname2}]}]}
}

