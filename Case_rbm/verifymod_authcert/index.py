#coding:utf-8
from common import baseinfo


verifymod_port = 443
verifymod_ip = baseinfo.gwClientIp
verifymod_sip = baseinfo.clientOpeIp
cert_md5 = 'c970dfa3234ed84ccac2e819a1276026'
test_cert2_md5 = 'b1cca5dae1537b565f9781e6c47e9e90'
test_cert3_md5 = '356702019c53f58e3e2e6b6697a2299c'
right_cert = '/opt/test2certandkey.pem'
right_cert3 = '/opt/test3certandkey.pem'
right_cert_passd = '123456'
right_url = 'https://www.testCA.cn'

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


case2_step1={
    "step1":['ls /usr/local/ipauth/file/CAdb/', test_cert2_md5]
}
case2_step2={
    "step1":['ls /usr/local/ipauth/file/CAdb/', test_cert3_md5]
}



case3_step1={
    "step1":[f'curl --cert {right_cert}:{right_cert_passd} {right_url}:{verifymod_port}','verify success'],
    "step2":[f'curl --cert {right_cert3}:{right_cert_passd} {right_url}:{verifymod_port}','verify success']
}
case3_step2={
    "step1":['tail -1 /var/log/jsac.verifymod.log', f'jsacaudit {verifymod_sip} success']
}
case3_step3={
    "step1":['ipauth-jsac --auth --show',verifymod_sip]
}