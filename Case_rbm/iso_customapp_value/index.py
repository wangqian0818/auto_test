#coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
app_proxy_port = baseinfo.app_proxy_port
# dport = 8889
app_ip = proxy_ip + ':' + str(app_proxy_port)
value1 = '0x48545450'
value2 = '0x47545450'
value3 = '0x49545450'
value4 = '1347703880'
# app_massage_value_equal = f'<cmpn value="{value1}" operation="=" offset="6">'
# app_massage_value_gt = f'<cmpn value="{value2}" operation="&gt;" offset="6">'
# app_massage_value_lt = f'<cmpn value="{value3}" operation="&lt;" offset="6">'
# app_value_end = f'<cmpn value="{value1}" operation="=" offset="6" end="/">'
# app_value_byte = f'<cmpn value="{value1}" operation="=" offset="6" nnn="4">'
# app_value_byte_end = f'<cmpn value="{value1}" operation="=" offset="6" nnn="4" end="/">'
# app_value_decimalism = f'<cmpn value="{value4}" operation="=" offset="6" nnn="4" end="/">'
back_serverIP_serverPort = str(baseinfo.http_server)+':'+str(baseinfo.http_server_port)



#配置检查
#列表里面的顺序依次为：查询命令，预期结果
case0_step1={
"step1":["cat /etc/jsac/customapp.stream",back_serverIP_serverPort],
}

case1_step1={
"step1":["cat /etc/jsac/custom_app.xml",value1],
}
case1_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}
case1_step3={
"step1":[f"value '{value1}'"],
}

case2_step1={
"step1":["cat /etc/jsac/custom_app.xml",value2],
}
case2_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}
case2_step3={
"step1":[f"value '{value2}'"],
}

case3_step1={
"step1":["cat /etc/jsac/custom_app.xml",value3],
}
case3_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}
case3_step3={
"step1":[f"value '{value3}'"],
}

case4_step1={
"step1":["cat /etc/jsac/custom_app.xml",value1],
}
case4_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}
case4_step3={
"step1":[f"value '{value1}'"],
}

case5_step1={
"step1":["cat /etc/jsac/custom_app.xml",value1],
}
case5_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}
case5_step3={
"step1":[f"value '{value1}'"],
}

case6_step1={
"step1":["cat /etc/jsac/custom_app.xml",value1],
}
case6_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}
case6_step3={
"step1":[f"value '{value1}'"],
}

case7_step1={
"step1":["cat /etc/jsac/custom_app.xml",value4],
}
case7_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}
case7_step3={
"step1":[f"value '{value1}'"],
}
