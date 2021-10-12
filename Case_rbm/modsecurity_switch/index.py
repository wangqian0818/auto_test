#coding:utf-8
from common import baseinfo

modsecurity_port = 2221
dip = baseinfo.serverOpeIp

#配置检查
#列表里面的顺序依次为：查询命令，预期结果
case1_step1={
"step1":["cat /usr/local/nginx/conf/nginx.conf", f'server {dip}:{modsecurity_port}']
}

case1_step2={
"step1":["cat /usr/local/nginx/conf/nginx.conf", 'modsecurity on','modsecurity off']
}