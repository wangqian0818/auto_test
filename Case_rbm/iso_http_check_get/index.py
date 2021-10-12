#coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
http_proxy_port = baseinfo.http_proxy_port
http_url = 'http://' + proxy_ip + ':' + str(http_proxy_port)

#http相关参数设置
check1_data1 = '123'
case1_data = {'data': check1_data1}

check2_data1 = 'test'
check2_data2 = 'juson'
case2_data1 = {'data':check2_data1}
case2_data2 = {'data':check2_data2}

#当有过滤内容时，get内容必须是键值对
data = {'data':'abc'}
http_ip = proxy_ip + ':' + str(http_proxy_port)
#配置下发
#列表里面的顺序依次为：查询命令，预期结果
case1_step1={
"step1":["cat /etc/jsac/http.stream",http_ip]
}
case1_step11={
"step1":["netstat -anp |grep tcp",http_ip]
}
case1_step2={
"step1":["cat /etc/jsac/http.json","c_get_args"],
"step2":["cat /etc/jsac/http.json",check1_data1],
"step3":[r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local",check1_data1]
}


case2_step2={
"step1":["cat /etc/jsac/http.json","c_get_args"],
"step2":["cat /etc/jsac/http.json",check2_data1],
"step3":["cat /etc/jsac/http.json",check2_data2],
"step4":[r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local",check2_data1],
"step5":[r"cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local",check2_data2]
}

delcheck = {
    "step1": ["cat /etc/jsac/http.json", "http"]
}