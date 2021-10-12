#coding:utf-8
from common import baseinfo

vlanCardid = str(baseinfo.gwVlanCardid)
vlanA = str(baseinfo.vlanA)
vlanB = str(baseinfo.vlanB)

#配置下发
#列表里面的顺序依次为：查询命令，预期结果
case1_step1={
"step1":[f"export cardid={vlanCardid}&&vlan-jsac --set --netif 1 --vid 5",f"export cardid={vlanCardid}&&vlan-jsac --get","5"],
"step2":[f"export cardid={vlanCardid}&&vlan-jsac --set --netif 1 --vid 4093",f"export cardid={vlanCardid}&&vlan-jsac --get","4093"]
}
case1_step2={
"step1":[f"export cardid={vlanCardid}&&vlan-jsac --set --netif 1 --vid 4095",'Error'],
"step2":[f"export cardid={vlanCardid}&&vlan-jsac --set --netif 1 --vid 23o",'Error'],
"step3":[f"export cardid={vlanCardid}&&vlan-jsac --set --netif 1 --vid 25,52",'Error'],
"step4":[f"export cardid={vlanCardid}&&vlan-jsac --set --netif 1 --vid dl0",'Error'],
"step5":[f"export cardid={vlanCardid}&&vlan-jsac --set --netif 1 --vid 23-56",'Error'],
"step6":[f"export cardid={vlanCardid}&&vlan-jsac --set --netif 6 --vid 23-56",'Error']
}
vlan_clear={
"step1":[f"export cardid={vlanCardid}&&vlan-jsac --clear",f"export cardid={vlanCardid}&&vlan-jsac --get",'no vlan']
}
case2_step1={
"step1":[f"export cardid={vlanCardid}&&vlan-jsac --set --netif 1 --vid 888",f"export cardid={vlanCardid}&&vlan-jsac --get","888"],
"step2":[f"export cardid={vlanCardid}&&vlan-jsac --set --netif 2 --vid 888",f"export cardid={vlanCardid}&&vlan-jsac --get","2"],
"step3":[f"export cardid={vlanCardid}&&vlan-jsac --set --netif 0 --vid 888",f"export cardid={vlanCardid}&&vlan-jsac --get |wc -l","5"]
}
case3_step1={
"step1":[f"export cardid={vlanCardid}&&vlan-jsac --set --netif 1 --vid 888",f"export cardid={vlanCardid}&&vlan-jsac --get","888"],
"step2":[f"export cardid={vlanCardid}&&vlan-jsac --set --netif 1 --vid 999",f"export cardid={vlanCardid}&&vlan-jsac --get","999"],
"step3":[f"export cardid={vlanCardid}&&vlan-jsac --set --netif 2 --vid 888",f"export cardid={vlanCardid}&&vlan-jsac --get","2"],
"step4":[f"export cardid={vlanCardid}&&vlan-jsac --set --netif 3 --vid 888",f"export cardid={vlanCardid}&&vlan-jsac --get","3"],
"step5":[f"export cardid={vlanCardid}&&vlan-jsac --set --netif 0 --vid 888",f"export cardid={vlanCardid}&&vlan-jsac --get |wc -l","6"]
}
