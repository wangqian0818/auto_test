# coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp

# ftp相关参数设置
port = baseinfo.ftp_proxy_port
username = 'test'
password = '1q2w3e'
deny_user = 'lwq'

case1_deny_user = 'lwq'
case2_deny_user = 'cpz'
case2_allow_user = 'lwq'

ftp_ip = proxy_ip + ':' + str(port)

# 配置下发
# 列表里面的顺序依次为：查询命令，预期结果
case1_step1 = {
    "step1": ["cat /etc/jsac/customapp.stream", ftp_ip]
}
case1_step11 = {
    "step1": ["netstat -anp |grep tcp", ftp_ip]
}
case1_step2 = {
    "step1": ["cat /etc/jsac/filter.json", "allow-user"],
    "step2": ["cat /etc/jsac/filter.json", username]
}

case2_step2 = {
    "step1": ["cat /etc/jsac/filter.json", "allow-user"],
    "step2": ["cat /etc/jsac/filter.json", username],
    "step3": ["cat /etc/jsac/filter.json", case2_allow_user]
}

delcheck = {
    "step1": ["cat /etc/jsac/filter.json", "ftp"]
}