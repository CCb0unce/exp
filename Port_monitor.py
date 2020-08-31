
# coding:utf-8 
#python3


import os
import json
import ast
import time
from apscheduler.schedulers.blocking import BlockingScheduler
import logging
import requests
import datetime

#调用masscan，存扫描文件到当前文件
def portscan():
	cmd ='./bin/masscan -p1-65535 -iL ip.txt --max-rate 1000 --banners -oJ result.json'
	YorN = os.system(cmd)
	return YorN

#处理masscan存入json的数据
def resultdeal():
	info = {}
	flag = 0
	with open('result.json','r+') as f:
		for line in f.readlines():
			#处理末尾的 ‘，’
			if line.startswith("{"):
				#portInfo = ast.literal_eval(line.strip()[:-1])
 
				#portInfo = json.loads(line.strip()[:-1])
				portInfo = json.loads(line.strip())
				ip = portInfo["ip"]
				port =portInfo["ports"][0]["port"]
				#print(ip,port)
				portALLInfo = portInfo["ports"]
				#print(ip,port,portALLInfo)
				if ip not in info:
					info[ip] = {}
				if "ports_masscan" not in info[ip]:
					info[ip]["ports_masscan"] = {}

				info[ip]["ports_masscan"][port] = portALLInfo
				#定义预期互联网开放端口
				if port not in [8443,80,443,4000,4001]:
					flag = 1
					#现在写入txt文件中，后续升级写入数据库，支持历史数据查询
					with open('warning.json','a') as file:
						file.write(line.strip()+'\n')
			
			else : 
				continue

#	print(info+'\n')
	return flag

#如果扫描结果中有非预期端口，机器人推送消息告警
def dingwarning():
	url1 = 'https://oapi.xxxxxxxx.com/robot/send?access_token=xxxxxxxxxxxxx'
	data = {"msgtype": "text", "text": {"content": "发现非预期端口对互联网开放，warning.json核实@xxxxxxx"}, "at": {"atMobiles": ["xxxxxxxx"]}}
	#print("有端口暴露")
	headers = {"Content-Type":"application/json"}
	result = requests.post(url=url1,data=json.dumps(data),headers=headers)
	#print(result.text)

def main():
	with open('warning.json','a') as file1:
		file1.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+'\n')
	flag1 = portscan()
	#masscan扫描完成再处理json
	if flag1 == 0:
		flag2 = resultdeal()
	    #有非预期端口再xx告警
		if flag2 ==1:
			dingwarning()
		with open('warning.json','a') as file2:
			file2.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+'\n'+'\n')
		

	else :
		print("masscan扫描出了问题，排查错误吧，赶紧的")

if __name__ == "__main__":
	#隔段时间安排一次扫描
	scheduler = BlockingScheduler()
#	scheduler.add_job(main,'interval',seconds=10)
	scheduler.add_job(main,'interval',minutes=60,next_run_time=datetime.datetime.now())
	scheduler.start()
