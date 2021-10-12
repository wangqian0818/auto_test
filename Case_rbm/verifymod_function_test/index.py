#coding:utf-8
from common import baseinfo


verifymod_port = 443
verifymod_ip = baseinfo.gwClientIp
verifymod_sip = baseinfo.clientOpeIp
dip = baseinfo.serverOpeIp
dport = 80
cert_md5 = 'c970dfa3234ed84ccac2e819a1276026'
right_url = 'https://www.testCA.cn'
error_url = 'https://www.test.cn'
right_cert = '/opt/test2certandkey.pem'
error_cert = '/opt/gwdifferentCA.pem'
right_cert_passd = '123456'
err_cert_passwd = '666666'

#配置检查
#列表里面的顺序依次为：查询命令，预期结果
case1_step1={
"step1":["ps -ef | grep verifymod", '/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf']
}
case1_step2={
    "step1":["netstat -ultpn", f'{verifymod_ip}:{verifymod_port}']
}
case1_step3={
    "step1":['ls /usr/local/ipauth/file/CAdb/', cert_md5]
}
case1_step4={
    "step1":[f'curl --cert {right_cert}:{right_cert_passd} {right_url}:{verifymod_port}','verify success']
}
case1_step5={
    "step1":['tail -1 /var/log/jsac.verifymod.log', f'jsacaudit {verifymod_sip} success']
}
case1_step6={
    "step1":['ipauth-jsac --auth --show','ipauth-jsac --clear',verifymod_sip,'Clear all rules successfully']
}


case2_step1={
    "step1":[f'curl --cert {error_cert}:{right_cert_passd} {right_url}:{verifymod_port}','verify success']
}

case2_step2={
    "step1":[f'curl --cert {right_cert}:{err_cert_passwd} {right_url}:{verifymod_port}','verify success']
}

case2_step3={
    "step1":[f'curl --cert {right_cert}:{right_cert_passd} {error_url}:{verifymod_port}','verify success' ]
}
case2_step4={
    "step1":['tail -1 /var/log/jsac.verifymod.log' , f'jsacaudit {verifymod_sip} fail']
}


case3_step1={
    "step1":['export cardid=0&&switch-jsac --set --switch on --module 13', 'export cardid=0&&switch-jsac --get', '13   IP_AUTH_MODULE     1    in     on']
}
case3_step2={
    "step1":[f"curl http://{dip}:{dport} >/opt/verifymod_curl.txt", 'cat /opt/verifymod_curl.txt', "Welcome to nginx!"],
    "step2":['verifymod_curl.txt']
}
case3_step3={
    "step1":['export cardid=0&&switch-jsac --set --switch off --module 13', 'export cardid=0&&switch-jsac --get', '13   IP_AUTH_MODULE     1    in     off']
}
