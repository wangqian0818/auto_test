#coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
app_proxy_port = baseinfo.app_proxy_port
# dport = 8889
app_ip = proxy_ip + ':' + str(app_proxy_port)
app_default_action_allow = '<action>allow</action>'
app_action_allow = 'action="allow"'
app_action_deny = 'action="deny"'
app_ruler_allow = 'ruler action="allow"'
app_ruler_deny = 'ruler action="deny"'
app_pport=f'pport="{app_proxy_port}"'
back_serverIP_serverPort = str(baseinfo.http_server)+':'+str(baseinfo.http_server_port)
#配置检查
#列表里面的顺序依次为：查询命令，预期结果
case0_step1={
"step1":["cat /etc/jsac/customapp.stream",back_serverIP_serverPort],
}

case1_step1={
"step1":["cat /etc/jsac/custom_app.xml",app_default_action_allow],
}
case1_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}
case1_step3={
"step1":["cat /etc/jsac/custom_app.xml",app_pport],
}

case3_step1={
"step1":["cat /etc/jsac/custom_app.xml",app_action_allow],
}
case3_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}
case3_step3={
"step1":["cat /etc/jsac/custom_app.xml",app_pport],
}


case4_step1={
"step1":["cat /etc/jsac/custom_app.xml",app_action_deny],
}
case4_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}
case4_step3={
"step1":["Default Deny"],
}
case4_step4={
"step1":["cat /etc/jsac/custom_app.xml",app_pport],
}


case6_step1={
"step1":["cat /etc/jsac/custom_app.xml",app_ruler_allow],
}
case6_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}
case6_step3={
"step1":["cat /etc/jsac/custom_app.xml",app_pport],
}



case7_step1={
"step1":["cat /etc/jsac/custom_app.xml",app_ruler_deny],
}
case7_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}
case7_step3={
"step1":["|Deny] cmdword 'get'"],
}
case7_step4={
"step1":["cat /etc/jsac/custom_app.xml",app_pport],
}

