#coding:utf-8
from common import baseinfo


verifymod_port = 443
verifymod_ip = baseinfo.gwClientIp
verifymod_sip = baseinfo.clientOpeIp
dip = baseinfo.serverOpeIp
dport = 80
expired_cert_md5 = '356702019c53f58e3e2e6b6697a2299c'
expired_clientcert = '/opt/dateoutcertandkey.pem'
cert_md5 = 'c970dfa3234ed84ccac2e819a1276026'
right_url = 'https://www.testCA.cn'
right_cert = '/opt/test2certandkey.pem'
right_cert_passd = '123456'


#配置检查
#列表里面的顺序依次为：查询命令，预期结果
case1_step1={
"step1":["ps -ef | grep verifymod", '/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf']
}
case1_step2={
    "step1":["netstat -ultpn", f'{verifymod_ip}:{verifymod_port}']
}
case1_step3={
    "step1":['ls /usr/local/ipauth/file/CAdb/', expired_cert_md5 ]
}
case1_step4={
    "step1":[f'curl --cert {right_cert}:{right_cert_passd} {right_url}:{verifymod_port}','verify success']
}
case1_step5={
    "step1":['tail -1 /var/log/jsac.verifymod.log', f'jsacaudit {verifymod_sip} fail']
}
case1_step6={
    "step1":['ipauth-jsac --auth --show',verifymod_sip]
}


case2_step1={
    "step1":[f'curl --cert {expired_clientcert}:{right_cert_passd} {right_url}:{verifymod_port}','verify success']
}
case2_step2={
    "step1":['ls /usr/local/ipauth/file/CAdb/', cert_md5 ]
}