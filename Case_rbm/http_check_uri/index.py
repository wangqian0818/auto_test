#coding:utf-8
from common import baseinfo

url = baseinfo.http_url
proxy_ip = baseinfo.gwInternetIp
proxy_port = baseinfo.http_proxy_port

#http相关参数设置
check1_uri = '123'
case1_uri = url + '/' + check1_uri

check2_uri1 = 'test'
check2_uri2 = 'juson'
case2_uri1 = url + '/' + check2_uri1
case2_uri2 = url + '/' + check2_uri2

#当有过滤内容时，get内容必须是键值对
data = {'data':'abc'}

http_ip = proxy_ip + ':' + str(proxy_port)
#配置下发
#列表里面的顺序依次为：查询命令，预期结果
case1_step1={
"step1":["netstat -anp |grep tcp",http_ip]
}
case1_step2={
"step1":["cat /etc/jsac/http.json","c_http_uri"],
"step2":["cat /etc/jsac/http.json",check1_uri]
}
case1_step3={
"step1":["cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local",check1_uri]
}


case2_step1={
"step1":["netstat -anp |grep tcp",http_ip]
}
case2_step2={
"step1":["cat /etc/jsac/http.json","c_http_uri"],
"step2":["cat /etc/jsac/http.json",check2_uri1],
"step3":["cat /etc/jsac/http.json",check2_uri2]
}
case2_step3={
"step1":["cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local",check2_uri1],
"step2":["cat /usr/local/nginx/lua/http.lua | grep =\{ | grep -v local",check2_uri2]
}

delcheck = {
    "step1": ["cat /etc/jsac/http.json", "http"]
}