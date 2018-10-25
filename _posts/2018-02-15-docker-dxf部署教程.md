---
layout:     post
title:      docker-dxf部署教程
subtitle:   dxf
date:       2018-02-15
author:     meigea
header-img: img/post-bg-9.png
catalog: true
tags:
    - dxf
---

# 安装 `CENTOS 5.8` 

## 工具位置
**[官网: 这个有八合一和二合一的dvd安装](http://vault.centos.org/5.8/isos/x86_64/)**

## 步骤
- 用 `UltraISO` 软碟通先把 `iso` 压一个到硬盘(写入硬盘)。
- 将需要的全部镜像放入根目录
- 安装后一直下一步下一步即可

## GRUB 分区
- 引导项非常要注意; [参考](https://www.linuxidc.com/Linux/2016-07/133521.htm)
- 安装完重新引导的时候注意引导位置(若出错参考上面的链接)
- boot, keneal, boot(h0, 0); `fdisk -l`
- `grub -install --root-directory=/ /dev/sda`

### GRUB 指令
**在grub界面指定kernel和initramfs所在路径启动，可以操作的命令有：**

- grub>kernel 内核文件 //设置内核文件的路径
- grub>initrd 镜像文件名 //设置镜像路径
- grub>boot //启动指定操作系统
- grub>help //获取帮助
- grub>reboot //重启系统
- grub>md5-crypt //生成口令的MD5密文
- grub>setup (hdx[,y]) //安装GURB到MBR/指定分区的引导扇区中
- grub>hide 分区 //隐藏分区grub>cat 文件名 //显示文件内容
- grub>find 文件名 //查找文件
- grub>rootnoveify (hdx,y) //设置根设备所对应的分区,但不检查加载点
- grub>chainloader 文件名 //加载指定的文件 在此指定linux内核和initramfs文件路径
- 

# 部署注意事项_网络和基本环境

## 调整网络
- 交换机部署 编辑`eth0` 为电脑端的网口
- `/etc/init.d/network restart`

- 交换机变换网关; 和`windows`设置相同
- 相关命令和说明
```
# 修改网络_编辑第一个默认网卡
vi /etc/sysconfig/network-scripts/eth0 

## ssh 连接缓慢; 修改
vi /etc/ssh/ssh_conf
> GSSAPIAuthentication no
```

## 技术细节
- 一键端部署
- 替换 `game` 目录下的多个文件; 例如 `game_c（后期的等级补丁）, Script.pvf, cfg目录中的ip`
- 客户端启动的 `game.ini`
- 客户端主机中的 `C:\Windows\System32\drivers\etc\hosts` 添加 `start.dnf.pw 192.168.137.111`


# Docker 部署须知
# docker 下载镜像源
- `dockker pull centos:5`
- `docker run -itd --net=host --name=dof centos:5`
- `docker exec -it dof bash `

# 镜像修改和开发
-  **5.11 的源已经错了; 需要修改镜像源。**

- **mysql 服务无法启动缺少 `liblinux.so.2`**
- mysql服务启动失败 Starting MySQL. ERROR! The server quit without updating PID file 

```
# yum 更新
cp CentOS-base.repo /etc/yum.repo.d/;
yum clean all;
echo 'http://vault.centos.org/5.11/os/x86_64/' > /var/cache/yum/libselinux/mirrorlist.txt;
yum makecache;
yum -y update;
echo "版本号 : " `cat /etc/redhat-release`
## 报错缺少 lib.so2

## 3.20更新; 跳过下面的yum ；安装这个命令 main_install.sh

yum install glibc.i686
## 编辑 mysql 用户为 root; 默认的权限不够
vi /opt/lammp/etc/my.conf 

```

## 运行`/root/run`过程中的错误和解决 

```
## yum provides libstdc++.so.6;
yum install  libstdc++-4.4.7-4.el6.i686;
// 如果出现错误, 就执行下面的试试; 我的这个一步通过。
### yum  update  libstdc++-4.4.7-3.el6.x86_64

## yum provides libz.so.1;
yum install zlib-1.2.3-7.el5.i386
```

## 修改cfg
**所有的 第一行的IP/有的版本写的 $(Public IP) `192.168.200.131` 修改为自己的IP**


```
cd /home/neople
sed -i "s/Public IP/${IP}/g" `find . -type f -name "*.cfg"`
```

## 总结需要安装的插件对应lib.so126

```
libstdc++-4.1.2-55.el5.i386
yum install -y glibc.i686;
yum install -y libstdc++-4.4.7-4.el6.i686;
yum install -y zlib-1.2.3-7.el5.i386;
// 快速安装(不推荐)。
## yum install --skip-broken  -y *.i386;
```

## 安装 GEOIP 前置安装包

```
yum -y install gcc gcc-c++ make zlib-devel libc.so.6 libstdc++ glibc.i686

cd /home/Ge《Tab》;
./configure
make &&  make check &&make install ;

```

## Docker-镜像

```
# 一个干净的配置好基础包的 centos:5.11 镜像；也是 dof 运行的前置镜像
docker pull actanble/dof-dev:0.1-beta2

# 成品; 直接pull 
docker pull actanble/centos5.10-dof:0.2-beta
docker run -itd --net=host actanble/centos5.10-dof:0.2-beta /bin/bash /root/run 
```

## 创建8G的虚拟内存

```
/bin/dd if=/dev/zero of=/var/swap.1 bs=1M count=8000
mkswap /var/swap.1
swapon /var/swap.1
sed -i '$a /var/swap.1 swap swap default 0 0' /etc/fstab

```



## 附件
**修改 `/etc/yum.repos.d/` 目录下的  `CentOS-base.repo`**

```

[base]  
name=CentOS-$releasever - Base  
baseurl=http://vault.centos.org/5.11/os/x86_64/  
gpgcheck=1  
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-5  
  
  
#released updates   
[updates]  
name=CentOS-$releasever - Updates   
baseurl=http://vault.centos.org/5.11/updates/x86_64/  
gpgcheck=1  
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-5  
  
  
#additional packages that may be useful  
[extras]  
name=CentOS-$releasever - Extras  
baseurl=http://vault.centos.org/5.11/extras/x86_64/  
gpgcheck=1  
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-5  
  
  
  
  
#additional packages that extend functionality of existing packages  
[centosplus]  
name=CentOS-$releasever - Plus   
baseurl=http://vault.centos.org/5.11/centosplus/x86_64/  
gpgcheck=1  
enabled=0  
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-5  
  
  
  
  
#contrib - packages by Centos Users  
[contrib]  
name=CentOS-$releasever - Contrib  
baseurl=http://vault.centos.org/5.11/contrib/x86_64/  
gpgcheck=1  
enabled=0  
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-5
```

## 基础命令

```
# 查看文件大小
du -h --max-depth=1 /home
# 查看运行端口
netstat -nlpt
```

## 相关运行截图




## yum 需要安装的前置包 
```
## main_install.sh

#!/bin/bash
yum clean all;
cp /root/CentOS-Base.repo /etc/yum.repos.d/;
echo 'http://vault.centos.org/5.11/os/x86_64/' > /var/cache/yum/libselinux/mirroo
rlist.txt;
yum makecache;
yum -y update;
yum -y install gcc gcc-c++ make zlib-devel libc.so.6 libstdc++ glibc.i686 vim-enhanced net-tools unzip 
cd / 
docker cp dof.tar.gz dof:/
tar -zxvf dof.tar.gz ;
chmod 755 /opt/lampp/etc/my.cnf;
# set -i "s/noboby/root/g" /opt/lampp/etc/my.cnf;
/root/run;
```

## DockerFile

```
# FROM centos:5
FROM muratayusuke/centos5.8
MAINTAINER actanble actanble@gmail.com

# RUN yum clean all && yum makecache;
COPY CentOS-Base.repo /etc/yum.repos.d/
RUN sed -in "s/5.11/5.10/g" CentOS-Base.repo
# RUN echo 'http://vault.centos.org/5.11/os/x86_64/' > /var/cache/yum/libselinux/mirrorlist.txt;
# RUN yum makecache;
RUN yum -y update;
RUN yum -y install gcc gcc-c++ make zlib-devel libc.so.6 libstdc++ glibc.i686;
COPY dof.tar.gz /
WORKDIR /
RUN tar zxvf dof.tar.gz ;
RUN rm -f dof.tar.gz ;
RUN cd /home/GeoIP-1.4.8/ ;
RUN ./configure
RUN make && make check && make install ;
RUN find /home/neople/ -type f -name "*.tbl" | xargs sed -i "s/101.200.211.94/192.168.0.110/g" ;
RUN find /home/neople/ -type f -name "*.cfg" | xargs sed -i "s/101.200.211.94/192.168.0.110/g" ;
# RUN for cfg_file in `find /home/neople/ -type f -name "*.cfg"`; do {sed -i "s/101.200.211.94/192.168.0.110/g" $cfg_file} || {echo $cfg_file is not can be replaced!}; done;
RUN make &&  make check && make install ;
RUN chmod 755 /opt/lampp/etc/my.cnf ;
RUN /bin/nash /root/run ;
EXPOSE 80 3306 8000 10013 30303 30403 10315 \
30603 7245 20303 40401 30803 20403 31100
CMD ["/bin/bash", "/root/run"]


```