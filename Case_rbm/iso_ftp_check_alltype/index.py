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

upload_filename = '1.'
case1_upload = 'txt'
case1_deny_upload = 'pdf'
case1_upload_file = upload_filename + case1_upload
case1_upload_deny_file = upload_filename + case1_deny_upload
case1_upremotePath = upremotePath + case1_upload_file
case1_uplocalPath = uplocalPath + case1_upload_file
case1_deny_upremotePath = upremotePath + case1_upload_deny_file
case1_deny_uplocalPath = uplocalPath + case1_upload_deny_file

down_filename = '456.'
case1_downfile = 'txt'
case1_deny_downfile = 'pdf'
case1_down_file = down_filename + case1_downfile
case1_down_deny_file = down_filename + case1_deny_downfile
case1_downremotePath = downremotePath + case1_down_file
case1_downlocalPath = downlocalPath + case1_down_file
case1_deny_downremotePath = downremotePath + case1_down_deny_file
case1_deny_downlocalPath = downlocalPath + case1_down_deny_file

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
"step1":["cat /etc/jsac/filter.json","allow-user"],
"step2":["cat /etc/jsac/filter.json",username],
"step3":["cat /etc/jsac/filter.json","allow-upload"],
"step4":["cat /etc/jsac/filter.json",case1_upload],
"step5":["cat /etc/jsac/filter.json","allow-download"],
"step6":["cat /etc/jsac/filter.json",case1_downfile],
"step7":["cat /etc/jsac/filter.json","allow-cmd"]
}
case1_step22={
"step1":["cat /etc/jsac/filter.json","RETR"]
}

delcheck = {
    "step1": ["cat /etc/jsac/filter.json", "ftp"]
}
