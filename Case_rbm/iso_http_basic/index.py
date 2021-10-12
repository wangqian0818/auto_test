#coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
http_proxy_port = baseinfo.http_proxy_port
http_server_port_file = baseinfo.http_server_port_file


remote_downfile = '10M.txt'

http_ip = proxy_ip + ':' + str(http_proxy_port)
http_file_ip = proxy_ip + ':' + str(http_server_port_file)
http_url = 'http://' + proxy_ip + ':' + str(http_proxy_port)
downfile_url = 'http://' + proxy_ip + ':' + str(http_proxy_port) + '/' + remote_downfile
downlocalPath = baseinfo.http_downlocalPath + remote_downfile
up_url = 'http://' + proxy_ip + ':' + str(http_server_port_file)
upfile_url = up_url + '/file'
upfilename = '10M.txt'
uplocalPath = baseinfo.http_uplocalPath + upfilename
upMIME_type = 'text/plain'


#配置检查
#列表里面的顺序依次为：查询命令，预期结果
case1_step1={
"step1":["cat /etc/jsac/http.stream",http_ip]
}
case1_step11={
"step1":["netstat -anp |grep tcp",http_ip]
}

case2_step1={
"step1":["cat /etc/jsac/http.stream",http_ip]
}
case2_step11={
"step1":["netstat -anp |grep tcp",http_ip]
}

case3_step1={
"step1":["cat /etc/jsac/http.stream",http_file_ip]
}
case3_step11={
"step1":["netstat -anp |grep tcp",http_file_ip]
}