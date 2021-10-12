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

upload_filename = '1.'
upload = 'txt'
upload_file = upload_filename + upload
upremotePath = upremotePath + upload_file
uplocalPath = uplocalPath + upload_file



down_filename = '456.'
downfile = 'txt'
down_file = down_filename + downfile
downremotePath = downremotePath + down_file
downlocalPath = downlocalPath + down_file

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
"step1":["cat /etc/jsac/filter.json","allow-cmd"]
}
case1_step22={
"step1":["cat /etc/jsac/filter.json","RETR"],
"step2":["cat /etc/jsac/filter.json","STOR"],
"step3":["cat /etc/jsac/filter.json","DELE"]
}

case2_step2={
"step1":["cat /etc/jsac/filter.json","RETR"],
"step2":["cat /etc/jsac/filter.json","DELE"],
"step3":["cat /etc/jsac/filter.json","allow-cmd"]
}
case2_step22={
"step1":["cat /etc/jsac/filter.json","STOR"]
}

delcheck = {
    "step1": ["cat /etc/jsac/filter.json", "ftp"]
}