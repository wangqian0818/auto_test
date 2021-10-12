#coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
app_proxy_port = baseinfo.app_proxy_port
# dport = 8889
app_ip = proxy_ip + ':' + str(app_proxy_port)
app_order_capital = '<cmd cmd="GET" offset="0">'
app_order_lowercase = '<cmd cmd="get" offset="0">'
app_order_other_character = '<cmd cmd=":" offset="20">'

a=r'"\r\n"'
end=r'"\r\n">'
app_order_group = f'<cmd cmd="Host" para="{app_ip}" offset="16" delimiter=":" end={end}'
back_serverIP_serverPort = str(baseinfo.http_server)+':'+str(baseinfo.http_server_port)




#配置检查
#列表里面的顺序依次为：查询命令，预期结果
case0_step1={
"step1":["cat /etc/jsac/customapp.stream",back_serverIP_serverPort],
}

case1_step1={
"step1":["cat /etc/jsac/custom_app.xml",app_order_capital],
}
case1_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}
case1_step3={
"step1":["cmdword 'GET'"],
}

case2_step1={
"step1":["cat /etc/jsac/custom_app.xml",app_order_lowercase],
}
case2_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}
case2_step3={
"step1":["cmdword 'get'"],
}

case3_step1={
"step1":["cat /etc/jsac/custom_app.xml",app_order_other_character],
}
case3_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}
case3_step3={
"step1":["cmdword ':'"],
}

case4_step1={
"step1":["cat /etc/jsac/custom_app.xml",app_order_group],
}
case4_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}
case4_step3={
"step1":["cmdword 'Host'"],
}