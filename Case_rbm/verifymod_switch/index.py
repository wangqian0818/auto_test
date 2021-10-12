#coding:utf-8
from common import baseinfo


verifymod_port = 443
verifymod_port1 = 5566
verifymod_ip = baseinfo.gwClientIp



#配置检查
#列表里面的顺序依次为：查询命令，预期结果
case1_step1={
"step1":["ps -ef | grep verifymod", '/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf']
}

case1_step2={
    "step1":["netstat -ultpn", f'{verifymod_ip}:{verifymod_port}']
}

case2_step1={
    "step1":["netstat -ultpn", f'{verifymod_ip}:{verifymod_port1}']
}