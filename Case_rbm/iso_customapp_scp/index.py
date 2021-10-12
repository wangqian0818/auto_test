#coding:utf-8
from common import baseinfo

scp_dport = 22
txt = '100M.txt'
app_ip = baseinfo.BG8010FrontOpeIp + ':' + str(baseinfo.ssh_proxy_port)
ssh = 'SSH'
app_pport=f'pport="{baseinfo.ssh_proxy_port}"'
back_serverIP_serverPort=str(baseinfo.BG8010ServerOpeIp)+':'+str(scp_dport)




#配置检查
#列表里面的顺序依次为：查询命令，预期结果
txt_file = {
  "step1":[txt],
}

case0_step1={
"step1":["cat /etc/jsac/customapp.stream",back_serverIP_serverPort],
}

case1_step1={
"step1":["cat /etc/jsac/custom_app.xml",ssh],
}
case1_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}

case1_step3={
"step1":["Allow] cmdword 'SSH'"],
}

case1_step4={
"step1":["cat /etc/jsac/custom_app.xml",app_pport],
}


case2_step1={
"step1":["cat /etc/jsac/custom_app.xml",ssh],
}
case2_step2={
"step1":["netstat -anp |grep tcp",app_ip],
}

case2_step3={
"step1":["Allow] cmdword 'SSH'"],
}

case2_step4={
"step1":["cat /etc/jsac/custom_app.xml",app_pport],
}


