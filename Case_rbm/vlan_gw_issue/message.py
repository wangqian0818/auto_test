import time

from common import baseinfo


datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

vlanA = str(baseinfo.vlanA)
vlanB = str(baseinfo.vlanB)
vlanIfname = baseinfo.gwVlanIfname
gwOther1Ifname = baseinfo.gwOther1Ifname
gwOther2Ifname = baseinfo.gwOther2Ifname
gwOther3Ifname = baseinfo.gwVlanIfname2
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

setNetVlan_right = {
'SetVlan':{
"MethodName":"SetVlan",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"Cards":vlanCard,
"VlanList":[{
"Vid":"88","Ifnames":gwOther1Ifname},
{"Vid":"88","Ifnames":gwOther2Ifname},
{"Vid":"88","Ifnames":gwOther3Ifname},
{"Vid":"88","Ifnames":vlanIfname}]}]}
}

setNetVlan_error = {
'SetVlan':{
"MethodName":"SetVlan",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"Cards":vlanCard,
"VlanList":[{
"Vid":"8888","Ifnames":gwOther1Ifname},
{"Vid":"8888","Ifnames":gwOther2Ifname},
{"Vid":"8888","Ifnames":gwOther3Ifname},
{"Vid":"8888","Ifnames":vlanIfname}]}]}
}

setMoreNetVlan_right = {
'SetVlan':{
"MethodName":"SetVlan",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"Cards":vlanCard,
"VlanList":[{
"Vid":"88,99,66","Ifnames":gwOther1Ifname},
{"Vid":"11,22,33","Ifnames":gwOther2Ifname},
{"Vid":"44,55,66","Ifnames":gwOther3Ifname},
{"Vid":"77,555,1111","Ifnames":vlanIfname}]}]}
}
setMoreNetVlan_error = {
'SetVlan':{
"MethodName":"SetVlan",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"Cards":vlanCard,
"VlanList":[{
"Vid":"ol,-5,9999","Ifnames":gwOther1Ifname},
{"Vid":"52h,-=)","Ifnames":gwOther2Ifname},
{"Vid":"4095,4096","Ifnames":gwOther3Ifname},
{"Vid":"4097,8888","Ifnames":vlanIfname}]}]}
}

delvlan = {
'SetVlan':{
"MethodName":"SetVlan",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
"Cards":vlanCard,
"VlanList":[{
"Vid":"","Ifnames":gwOther1Ifname},
{"Vid":"","Ifnames":gwOther2Ifname},
{"Vid":"","Ifnames":gwOther3Ifname},
{"Vid":"","Ifnames":vlanIfname}]}]}
}