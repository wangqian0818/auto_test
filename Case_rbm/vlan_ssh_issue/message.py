import time

from common import baseinfo


datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

vlanA = str(baseinfo.vlanA)
vlanB = str(baseinfo.vlanB)
vlanIfname = baseinfo.gwVlanIfname
# gwOtherIfname = baseinfo.gwOtherIfname
vlanCard = baseinfo.gwVlanCard

setvlan_right = {
'SetVlan':{
"MethodName":"SetVlan",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"Cards":vlanCard,
"VlanList":[{"Vid":f"{vlanA},{vlanB},2,4094,1,4093","Ifnames":vlanIfname}]
}]}
}

setvlan_error = {
'SetVlan':{
"MethodName":"SetVlan",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"Cards":vlanCard,
"VlanList":[{"Vid":"4095,4096","Ifnames":vlanIfname}]
}]}
}

setvlan_part = {
'SetVlan':{
"MethodName":"SetVlan",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"Cards":vlanCard,
"VlanList":[{"Vid":f"{vlanA},{vlanB},4097,9999","Ifnames":vlanIfname}]
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
