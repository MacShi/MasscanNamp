## masscan探测端口是否开启，nmap确定端口运行的服务
程序中使用的masscan、nmap命令

masscan使用命令
```
masscan -iL ip_file.txt -p 1-65535 -oJ result.json --rate 2000
```
nmap使用命令
```
nmap -oX -p port -Pn -sS 192.168.203.41
```