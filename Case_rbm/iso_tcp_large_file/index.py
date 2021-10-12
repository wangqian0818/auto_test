#coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
http_proxy_port = baseinfo.http_proxy_port
ssh_proxy_port = baseinfo.ssh_proxy_port

http_ip = proxy_ip + ':' + str(http_proxy_port)
ssh_ip = proxy_ip + ':' + str(ssh_proxy_port)

# remote_downfile = '10G.txt'
remote_downfile = '100M.txt'    # 10G 太大了，上传下载失败，换成100M
downfile_url = 'http://' + proxy_ip + ':' + str(http_proxy_port) + '/' + remote_downfile
downlocalPath = baseinfo.http_downlocalPath + remote_downfile


#配置检查
#列表里面的顺序依次为：查询命令，预期结果
case1_step1={
"step1":["cat /etc/jsac/customapp.stream",http_ip]
}
case1_step11={
"step1":["netstat -anp |grep tcp",http_ip]
}

case2_step1={
"step1":["cat /etc/jsac/customapp.stream",ssh_ip]
}
case2_step11={
"step1":["netstat -anp |grep tcp",ssh_ip]
}

case3_step1={
"step1":["cat /etc/jsac/customapp.stream",ssh_ip]
}
case3_step11={
"step1":["netstat -anp |grep tcp",ssh_ip]
}