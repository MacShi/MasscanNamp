#!/usr/bin/python3

import nmap
import os
from queue import Queue
import json
from multiprocessing import Pool

def run_masscan():
    masscan_path = '/home/ubuntu/masscan/bin/masscan'
    masscan_rate = 2000
    ip_file = 'ip_file.txt'
    result = 'result.json'
    command = 'sudo {} -iL {} -p 1-65535 -oJ {} --rate {}'.format(masscan_path,ip_file,result,masscan_rate)
    msg = 'executing==> {}'.format(command)
    print(msg)
    try:
        ret = os.system(command)
        if ret == 0:
            return True
        else:
            return False
    except Exception as e:
        print("[run_masscan Error] {}".format(str(e)))
        return False

def nmap_scan_port(ip_port:dict,result_queue:Queue)->Queue:
    try:
        nm = nmap.PortScanner()
        ip = ip_port['ip']
        port = ip_port['port']
        ret = nm.scan(ip,port,arguments='-Pn -sS')
        print(ret)
        print('\n')
        service = ret['scan'][ip]['tcp'][int(port)]['name']
        msg = '{}:{}:{}'.format(ip, port, service)
        if None!=service:
            result_queue.put('{},{},{}'.format(ip, port, service))
        else:
            result_queue.put('{},{},{}'.format(ip, port, '-'))
        print(msg)
        return result_queue
    except  Exception as e:
        print(str(e))

def extract_masscan_json(result:str)->Queue:
    task_queue = Queue()
    with open(result,'r') as ff:
        for line in ff.readlines():
            line = line.strip()
            if line !='[' and line!=',' and line !=']':
                if "," == line[-1]:
                    tmp = json.loads(line[:-1])
                else:
                    tmp = json.loads(line)
                # task_queue.put('{}:{}'.format(tmp['ip'],tmp['ports'][0]['port']))
                task_queue.put(dict({'ip':tmp['ip'],'port':str(tmp['ports'][0]['port'])}))
        ff.close()
        task_queue.put("aaa")
    return task_queue

def run_nmap(process_num:int,task_queue:Queue,result_queue:Queue)->Queue:
    pool = Pool(process_num)
    while not task_queue.empty():
        ip_port = task_queue.get()
        pool.apply_async(nmap_scan_port(ip_port,result_queue))
    pool.close()
    pool.join()

    return result_queue
def save_service_info(result_queue:Queue):
    while not result_queue.empty():
        server_info = str(result_queue.get())+'\n'
        with open('service_info.txt','a',encoding="utf-8") as ff:
            ff.write(str(server_info))
            ff.close()


if __name__ == '__main__':
    result_queue = Queue()
    run_masscan()
    task_queue = extract_masscan_json('result.json')
    run_nmap(5,task_queue,result_queue)
    save_service_info(result_queue)
    # nmap_scan_port({'ip':'127.0.0.1','port':'2100'})
    # run_masscan()
    # task_queue = extract_masscan_json('result.json')
    # while not task_queue.empty():
    #     print(task_queue.get())
    # run_masscan()


