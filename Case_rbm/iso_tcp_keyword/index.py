# coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
smtp_proxy_port = baseinfo.mail_proxy_port
pop3_proxy_port = baseinfo.pop3_server_port
ftp_proxy_port = baseinfo.ftp_proxy_port
mail_attach = baseinfo.mail_attach
downremotePath = baseinfo.ftp_downremotePath
downlocalPath = baseinfo.ftp_downlocalPath
http_proxy_port = baseinfo.http_proxy_port
ssh_proxy_port = baseinfo.ssh_proxy_port
BG8010FrontOpeNum = baseinfo.BG8010FrontOpeNum

# smtp相关参数设置
mail_sender = 'liwanqiu66@163.com'  # 发件人
mail_receivers = ['m53667987@163.com', 'liwanqiu66@163.com']  # 收件人
mail_cc = ['liwanqiu66@163.com', 'm53667987@163.com']  # 抄送人
mail_bcc = ['liwanqiu66@163.com', 'm53667987@163.com']  # 暗送人
mail_host = proxy_ip  # 设置服务器,发件人的服务器代理
mail_port = smtp_proxy_port  # 设置服务器端口
mail_user = "liwanqiu66@163.com"  # 邮件登录地址
mail_pass = "lwq5945"  # 授权码
deny_mail = 'jusontest@163.com'
deny_pwd = 'UMXDELUQAPUWQFNU'

# pop3相关参数设置
# 获取邮箱密码和对应邮箱POP3服务器,邮件地址跟收件人相同
pop3_email = "m53667987@163.com"
pop3_pwd = "DKIFMDALXMWLXCOW"
title = '关于iso_tcp_keyword'
context = '测试内容-content'
file = '1.xls'
attach_path = mail_attach + file

# ftp相关参数设置
ftp_user = 'test'
ftp_pass = '1q2w3e'
filename = '456.'
case2_downfile = 'txt'
case2_file = filename + case2_downfile
case2_downremotePath = downremotePath + case2_file
case2_downlocalPath = downlocalPath + case2_file

smtp_keyword = '卓讯'
pop3_keyword = '科技'
smtp_keyword_base64 = '5Y2T6K6v'
pop3_keyword_base64 = '56eR5oqA'
smtp_keyfile = 'cat /etc/jsac/key_word/kw' + BG8010FrontOpeNum + '_' + str(mail_port)
pop3_keyfile = 'cat /etc/jsac/key_word/kw' + BG8010FrontOpeNum + '_' + str(pop3_proxy_port)
ftp_keyword = 'RETR'
ftp_keyfile = 'cat /etc/jsac/key_word/kw' + BG8010FrontOpeNum + '_' + str(ftp_proxy_port)

mail_ip = proxy_ip + ':' + str(mail_port)
pop3_ip = proxy_ip + ':' + str(pop3_proxy_port)
ftp_ip = proxy_ip + ':' + str(ftp_proxy_port)
http_ip = proxy_ip + ':' + str(http_proxy_port)
http_url = 'http://' + proxy_ip + ':' + str(http_proxy_port)
ssh_ip = proxy_ip + ':' + str(ssh_proxy_port)

# 配置检查
# 列表里面的顺序依次为：查询命令，预期结果
case1_step1 = {
    "step1": ["cat /etc/jsac/customapp.stream", mail_ip],
    "step2": ["cat /etc/jsac/customapp.stream", pop3_ip],
    'step3': [smtp_keyfile, smtp_keyword_base64],
    'step4': [pop3_keyfile, pop3_keyword_base64]
}
case1_step11 = {
    "step1": ["netstat -anp |grep tcp", mail_ip],
    "step2": ["netstat -anp |grep tcp", pop3_ip]
}

case2_step1 = {
    "step1": ["cat /etc/jsac/customapp.stream", ftp_ip],
    'step2': [ftp_keyfile, ftp_keyword]
}
case2_step11 = {
    "step1": ["netstat -anp |grep tcp", ftp_ip]
}

case3_step1 = {
    "step1": ["cat /etc/jsac/customapp.stream", http_ip]
}
case3_step11 = {
    "step1": ["netstat -anp |grep tcp", http_ip]
}
