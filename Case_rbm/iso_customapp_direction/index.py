#coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
app_proxy_port = baseinfo.app_proxy_port
# dport = 8889
app_ip = proxy_ip + ':' + str(app_proxy_port)


twoway_cmd = 'cmd cmd="get" offset="0"'
twoway_code = 'resp code="200" offset="9"'
upstream = 'cmd cmd="http" offset="0"'
downstream = 'cmd cmd="get" offset="0"'
back_serverIP_serverPort = str(baseinfo.http_server)+':'+str(baseinfo.http_server_port)

#配置检查
#列表里面的顺序依次为：查询命令，预期结果
case0_step1={
"step1":["cat /etc/jsac/customapp.stream",back_serverIP_serverPort],
}

case1_step1={
"step1":["cat /etc/jsac/custom_app.xml",upstream],
}
case1_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}


case2_step1={
"step1":["cat /etc/jsac/custom_app.xml",downstream],
}
case2_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}


case3_step1={
"step1":["cat /etc/jsac/custom_app.xml",twoway_cmd],
"step2":["cat /etc/jsac/custom_app.xml",twoway_code],
}
case3_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}