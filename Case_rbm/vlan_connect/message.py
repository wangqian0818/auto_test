import time

from common import baseinfo


datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

vlanA = str(baseinfo.vlanA)
vlanB = str(baseinfo.vlanB)
vlanIfname = baseinfo.gwVlanIfname
vlanCard = baseinfo.gwVlanCard

setvlan = {
'SetVlan':{
"MethodName":"SetVlan",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"Cards":vlanCard,
"VlanList":[{"Vid":f"{vlanA},{vlanB}","Ifnames":vlanIfname}]
}]}
}

delvlan = {
'SetVlan':{
"MethodName":"SetVlan",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"Cards":vlanCard,
"VlanList":[{"Vid":"","Ifnames":vlanIfname}]}]}
}

