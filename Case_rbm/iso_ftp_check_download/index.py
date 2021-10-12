#coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
upremotePath = baseinfo.ftp_upremotePath
uplocalPath = baseinfo.ftp_uplocalPath
downremotePath = baseinfo.ftp_downremotePath
downlocalPath = baseinfo.ftp_downlocalPath

#ftp相关参数设置
port = baseinfo.ftp_proxy_port
username = 'test'
password = '1q2w3e'
deny_user = 'lwq'

filename = '456.'
case1_downfile = 'txt'
case1_deny_downfile = 'pdf'
case1_file = filename + case1_downfile
case1_deny_file = filename + case1_deny_downfile
case1_downremotePath = downremotePath + case1_file
case1_downlocalPath = downlocalPath + case1_file
case1_deny_downremotePath = downremotePath + case1_deny_file
case1_deny_downlocalPath = downlocalPath + case1_deny_file

case2_downfile = 'txt'
case2_allow_downfile = 'xls'
case2_deny_downfile = 'pdf'
case2_file = filename + case2_downfile
case2_allow_file = filename + case2_allow_downfile
case2_deny_file = filename + case2_deny_downfile
case2_downremotePath = downremotePath + case2_file
case2_downlocalPath = downlocalPath + case2_file
case2_allow_downremotePath = downremotePath + case2_allow_file
case2_allow_downlocalPath = downlocalPath + case2_allow_file
case2_deny_downremotePath = downremotePath + case2_deny_file
case2_deny_downlocalPath = downlocalPath + case2_deny_file

ftp_ip = proxy_ip + ':' + str(port)
#配置下发
#列表里面的顺序依次为：查询命令，预期结果
case1_step1={
"step2":["cat /etc/jsac/customapp.stream",ftp_ip]
}
case1_step11={
"step1":["netstat -anp |grep tcp",ftp_ip]
}
case1_step2={
"step1":["cat /etc/jsac/filter.json","allow-download"],
"step2":["cat /etc/jsac/filter.json",case1_downfile]
}

case2_step2={
"step1":["cat /etc/jsac/filter.json","allow-download"],
"step2":["cat /etc/jsac/filter.json",case2_downfile],
"step3":["cat /etc/jsac/filter.json",case2_allow_downfile]
}

delcheck = {
    "step1": ["cat /etc/jsac/filter.json", "ftp"]
}