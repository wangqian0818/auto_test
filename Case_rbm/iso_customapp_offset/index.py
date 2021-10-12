#coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
app_proxy_port = baseinfo.app_proxy_port
# dport = 8889
app_ip = proxy_ip + ':' + str(app_proxy_port)
a=r'"\r\n"'
app_offset = '<cmd cmd="get" offset="190" end='+a +'>'
back_serverIP_serverPort = str(baseinfo.http_server)+':'+str(baseinfo.http_server_port)



#配置检查
#列表里面的顺序依次为：查询命令，预期结果
case0_step1={
"step1":["cat /etc/jsac/customapp.stream",back_serverIP_serverPort],
}

case1_step1={
"step1":["cat /etc/jsac/custom_app.xml",app_offset],
}
case1_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}
