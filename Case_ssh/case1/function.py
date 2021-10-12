#encoding='utf-8'
try:
	import os,sys,pytest,allure
except Exception as err:
	print('导入CPython内置函数库失败!错误信息如下:')
	print(err)
	sys.exit(0)#避免程序继续运行造成的异常崩溃,友好退出程序

base_path=os.path.dirname(os.path.abspath(__file__))#获取当前项目文件夹
base_path=base_path.replace('\\','/')
sys.path.insert(0,base_path)#将当前目录添加到系统环境变量,方便下面导入版本配置等文件
try:
	from fun import *
except Exception as err:
	print('导入基础函数库失败!请检查相关文件是否存在.\n文件位于: '+str(base_path)+'/common/ 目录下.\n分别为:pcap.py  rabbitmq.py  ssh.py\n错误信息如下:')
	print(err)
	sys.exit(0)#避免程序继续运行造成的异常崩溃,友好退出程序
else:
	del sys.path[0]#及时删除导入的环境变量,避免重复导入造成的异常错误

#创建ssh链接之前，要检查是不是在mac变量中定义了，例如定义ssh_1实例
#要先判断if "1" in mac:
