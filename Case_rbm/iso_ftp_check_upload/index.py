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

filename = '1.'
case1_upload = 'txt'
case1_deny_upload = 'pdf'
case1_file = filename + case1_upload
case1_deny_file = filename + case1_deny_upload
case1_upremotePath = upremotePath + case1_file
case1_uplocalPath = uplocalPath + case1_file
case1_deny_upremotePath = upremotePath + case1_deny_file
case1_deny_uplocalPath = uplocalPath + case1_deny_file

case2_upload = 'txt'
case2_allow_upload = 'xls'
case2_deny_upload = 'pdf'
case2_file = filename + case2_upload
case2_allow_file = filename + case2_allow_upload
case2_deny_file = filename + case2_deny_upload
case2_upremotePath = upremotePath + case2_file
case2_uplocalPath = uplocalPath + case2_file
case2_allow_upremotePath = upremotePath + case2_allow_file
case2_allow_uplocalPath = uplocalPath + case2_allow_file
case2_deny_upremotePath = upremotePath + case2_deny_file
case2_deny_uplocalPath = uplocalPath + case2_deny_file

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
"step1":["cat /etc/jsac/filter.json","allow-upload"],
"step2":["cat /etc/jsac/filter.json",case1_upload]
}

case2_step2={
"step1":["cat /etc/jsac/filter.json","allow-upload"],
"step2":["cat /etc/jsac/filter.json",case2_upload],
"step3":["cat /etc/jsac/filter.json",case2_allow_upload]
}

delcheck = {
    "step1": ["cat /etc/jsac/filter.json", "ftp"]
}