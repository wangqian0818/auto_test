#coding:utf-8
from common import baseinfo

vlanCardid = str(baseinfo.gwVlanCardid)
vlanA = str(baseinfo.vlanA)
vlanB = str(baseinfo.vlanB)

#配置下发
#列表里面的顺序依次为：查询命令，预期结果
case1_step1={
"step1":[f"export cardid={vlanCardid}&&vlan-jsac --get",vlanA],
"step2":[f"export cardid={vlanCardid}&&vlan-jsac --get",vlanB],
"step3":[f"export cardid={vlanCardid}&&vlan-jsac --get",'2'],
"step4":[f"export cardid={vlanCardid}&&vlan-jsac --get",'4094'],
"step5":[f"export cardid={vlanCardid}&&vlan-jsac --get",'1'],
"step6":[f"export cardid={vlanCardid}&&vlan-jsac --get",'4093']
}
case1_step2={
"step1":[f"export cardid={vlanCardid}&&vlan-jsac --get",'4095'],
"step2":[f"export cardid={vlanCardid}&&vlan-jsac --get",'4096']
}

case1_step3={
"step1":[f"export cardid={vlanCardid}&&vlan-jsac --get",'4097'],
"step2":[f"export cardid={vlanCardid}&&vlan-jsac --get",'9999']
}

case2_step1={
"step1":[f"export cardid={vlanCardid}&&vlan-jsac --get",'88'],
"step2":[f"export cardid={vlanCardid}&&vlan-jsac --get",'1'],
"step3":[f"export cardid={vlanCardid}&&vlan-jsac --get",'2'],
"step4":[f"export cardid={vlanCardid}&&vlan-jsac --get",'3'],
"step5":[f"export cardid={vlanCardid}&&vlan-jsac --get",'4'],
"step6":[f"export cardid={vlanCardid}&&vlan-jsac --get |wc -l",'5']
}
case2_step2={
"step1":[f"export cardid={vlanCardid}&&vlan-jsac --get",'8888']
}

case3_step1={
"step1":[f"export cardid={vlanCardid}&&vlan-jsac --get",'11'],
"step2":[f"export cardid={vlanCardid}&&vlan-jsac --get",'22'],
"step3":[f"export cardid={vlanCardid}&&vlan-jsac --get",'33'],
"step4":[f"export cardid={vlanCardid}&&vlan-jsac --get",'44'],
"step5":[f"export cardid={vlanCardid}&&vlan-jsac --get",'55'],
"step6":[f"export cardid={vlanCardid}&&vlan-jsac --get",'66'],
"step7":[f"export cardid={vlanCardid}&&vlan-jsac --get",'77'],
"step8":[f"export cardid={vlanCardid}&&vlan-jsac --get",'88'],
"step9":[f"export cardid={vlanCardid}&&vlan-jsac --get",'99'],
"step10":[f"export cardid={vlanCardid}&&vlan-jsac --get",'555'],
"step11":[f"export cardid={vlanCardid}&&vlan-jsac --get",'1111'],
"step12":[f"export cardid={vlanCardid}&&vlan-jsac --get |wc -l",'13']
}
case3_step2={
"step1":[f"export cardid={vlanCardid}&&vlan-jsac --get",'8888']
}

vlan_clear={
"step1":[f"export cardid={vlanCardid}&&vlan-jsac --get",'no vlan']
}