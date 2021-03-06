#coding:utf-8
from common import baseinfo

proxy_ip = baseinfo.BG8010FrontOpeIp
mail_attach = baseinfo.mail_attach

#smtp相关参数设置
mail_sender = baseinfo.mail_sender  # 发件人
mail_receivers = baseinfo.mail_receivers  # 收件人
mail_cc = baseinfo.mail_cc  # 抄送人
mail_bcc = baseinfo.mail_bcc  # 暗送人
mail_host = proxy_ip  # 设置服务器,发件人的服务器代理
mail_port = baseinfo.mail_proxy_port  # 设置服务器端口
mail_user = baseinfo.mail_user  # 邮件登录地址
mail_pass = baseinfo.mail_pass  # 授权码
deny_mail = 'jusontest@163.com'
deny_pwd = 'UMXDELUQAPUWQFNU'

#pop3相关参数设置
# 获取邮箱密码和对应邮箱POP3服务器,邮件地址跟收件人相同
pop3_email = baseinfo.pop3_email
pop3_pwd = baseinfo.pop3_pwd    # 授权码
pop3_server_host = proxy_ip
pop3_server_port = baseinfo.pop3_server_port

context = '测试测试测试'
file = '1.xls'
attach_path = mail_attach + file
case1_title1 = 'test'
case1_title2 = '我不是黑名单主题（隔离的数据结构检查）'
case2_title1 = 'test'
case2_title2 = 'abc'
case2_title3 = '我不是黑名单主题!!（隔离的数据结构检查）'

mail_ip = proxy_ip + ':' + str(mail_port)
pop3_ip = proxy_ip + ':' + str(pop3_server_port)
#配置检查
#列表里面的顺序依次为：查询命令，预期结果
case1_step1={
"step1":["cat /etc/jsac/customapp.stream",mail_ip],
"step2":["cat /etc/jsac/customapp.stream",pop3_ip]
}
case1_step11={
"step1":["netstat -anp |grep tcp",mail_ip],
"step2":["netstat -anp |grep tcp",pop3_ip]
}
case1_step2={
"step1":["cat /etc/jsac/filter.json","deny-topic"],
"step2":["cat /etc/jsac/filter.json",case1_title1]
}


case2_step2={
"step1":["cat /etc/jsac/filter.json","deny-topic"],
"step2":["cat /etc/jsac/filter.json",case2_title1],
"step3":["cat /etc/jsac/filter.json",case2_title2]
}

delcheck = {
    "step1": ["cat /etc/jsac/filter.json", "mail"]
}