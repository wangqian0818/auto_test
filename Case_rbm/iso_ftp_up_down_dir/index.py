#coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
ftp_proxy_port = baseinfo.ftp_proxy_port


#ftp相关参数设置
ftp_user = 'test'
ftp_pass = '1q2w3e'

ftp_ip = proxy_ip + ':' + str(ftp_proxy_port)


#配置检查
#列表里面的顺序依次为：查询命令，预期结果
case2_step1={
"step1":["cat /etc/jsac/customapp.stream",ftp_ip]
}
case2_step11={
"step1":["netstat -anp |grep tcp",ftp_ip]
}

case1_step1={
"step1":["cat /etc/jsac/customapp.stream",ftp_ip]
}
case1_step11={
"step1":["netstat -anp |grep tcp",ftp_ip]
}

