#coding:utf-8
from common import baseinfo

vlanCardid = str(baseinfo.gwVlanCardid)
vlanA = str(baseinfo.vlanA)
vlanB = str(baseinfo.vlanB)



#配置下发
#列表里面的顺序依次为：查询命令，预期结果
case1_step1={
"step1":[f"export cardid={vlanCardid}&&switch-jsac --set --module 12 --switch on",f"export cardid={vlanCardid}&&switch-jsac --get | grep 12","on"],
"step2":[f"export cardid={vlanCardid}&&switch-jsac --set --module 15 --switch on",f"export cardid={vlanCardid}&&switch-jsac --get | grep 15","on"]
}

case1_step2={
"step1":[f"export cardid={vlanCardid}&&vlan-jsac --get",vlanA],
"step2":[f"export cardid={vlanCardid}&&vlan-jsac --get",vlanB]
}

case1_step11={
"step1":[f"export cardid={vlanCardid}&&switch-jsac --set --module 12 --switch off",f"export cardid={vlanCardid}&&switch-jsac --get | grep 12","off"],
"step2":[f"export cardid={vlanCardid}&&switch-jsac --set --module 15 --switch off",f"export cardid={vlanCardid}&&switch-jsac --get | grep 15","off"]
}