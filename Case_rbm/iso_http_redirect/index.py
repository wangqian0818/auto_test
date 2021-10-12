#coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
http_proxy_port = baseinfo.http_proxy_port


http_ip = proxy_ip + ':' + str(http_proxy_port)
http_url = 'http://' + proxy_ip + ':' + str(http_proxy_port)


#配置检查
#列表里面的顺序依次为：查询命令，预期结果
case1_step1={
"step1":["cat /etc/jsac/http.stream",http_ip]
}
case1_step11={
"step1":["netstat -anp |grep tcp",http_ip]
}
