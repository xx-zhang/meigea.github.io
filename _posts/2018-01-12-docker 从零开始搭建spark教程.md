---
layout:     post
title:      docker 从零开始搭建spark教程
subtitle:   docker
date:       2018-01-12
author:     meigea
header-img: img/post-bg-5.png
catalog: true
tags:
    - docker
    - spark
    - mysql
---


# Ubuntu/Centos 下安装 `docker-ce`

## Ubuntu14-16
参考 <https://docs.docker.com/engine/installation/linux/docker-ce/centos/#upgrade-docker-ce-1>
```
# step 1: 安装必要的一些系统工具
sudo apt-get update
sudo apt-get -y install apt-transport-https ca-certificates curl software-properties-common
# step 2: 安装GPG证书
curl -fsSL http://mirrors.aliyun.com/docker-ce/linux/ubuntu/gpg | sudo apt-key add -
# Step 3: 写入软件源信息
sudo add-apt-repository "deb [arch=amd64] http://mirrors.aliyun.com/docker-ce/linux/ubuntu $(lsb_release -cs) stable"
# Step 4: 更新并安装 Docker-CE
sudo apt-get -y update
sudo apt-get -y install docker-ce

# 安装指定版本的Docker-CE:
# Step 1: 查找Docker-CE的版本:
# apt-cache madison docker-ce
#   docker-ce | 17.03.1~ce-0~ubuntu-xenial | http://mirrors.aliyun.com/docker-ce/linux/ubuntu xenial/stable amd64 Packages
#   docker-ce | 17.03.0~ce-0~ubuntu-xenial | http://mirrors.aliyun.com/docker-ce/linux/ubuntu xenial/stable amd64 Packages
# Step 2: 安装指定版本的Docker-CE: (VERSION 例如上面的 17.03.1~ce-0~ubuntu-xenial)
# sudo apt-get -y install docker-ce=[VERSION]
```

## CentOS

```
# step 1: 安装必要的一些系统工具
sudo yum install -y yum-utils device-mapper-persistent-data lvm2
# Step 2: 添加软件源信息
sudo yum-config-manager --add-repo http://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
# Step 3: 更新并安装 Docker-CE
sudo yum makecache fast
sudo yum -y install docker-ce
# Step 4: 开启Docker服务
sudo service docker start

# 注意：
# 官方软件源默认启用了最新的软件，您可以通过编辑软件源的方式获取各个版本的软件包。例如官方并没有将测试版本的软件源置为可用，你可以通过以下方式开启。同理可以开启各种测试版本等。
# vim /etc/yum.repos.d/docker-ee.repo
#   将 [docker-ce-test] 下方的 enabled=0 修改为 enabled=1
#
# 安装指定版本的Docker-CE:
# Step 1: 查找Docker-CE的版本:
# yum list docker-ce.x86_64 --showduplicates | sort -r
#   Loading mirror speeds from cached hostfile
#   Loaded plugins: branch, fastestmirror, langpacks
#   docker-ce.x86_64            17.03.1.ce-1.el7.centos            docker-ce-stable
#   docker-ce.x86_64            17.03.1.ce-1.el7.centos            @docker-ce-stable
#   docker-ce.x86_64            17.03.0.ce-1.el7.centos            docker-ce-stable
#   Available Packages
# Step2 : 安装指定版本的Docker-CE: (VERSION 例如上面的 17.03.0.ce.1-1.el7.centos)
# sudo yum -y install docker-ce-[VERSION]
```

## 阿里云Docker加速器
```
curl -sSL http://acs-public-mirror.oss-cn-hangzhou.aliyuncs.com/docker-engine/internet | sh -
## bash -
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json <<-'EOF'
{
  "registry-mirrors": ["https://1n1i3zwf.mirror.aliyuncs.com"]
}
EOF
## sudo systemctl daemon-reload
## sudo systemctl restart docker
sudo /etc/init.d/docker restart 
```

## 相关说明|
`docker`命令详细教程 <http://www.simapple.com/docker-tutorial> 这是一个系列的教程； 讲解比较详细。部分翻译不准，多看几个`DockerFile` 就可以了

## docker_spark 使用

> docker search spark 第一个就是

参考 <https://hub.docker.com/r/sequenceiq/spark/>
```
docker pull sequenceiq/spark:1.6.0
docker run -d -h sandbox sequenceiq/spark:1.6.0 -d

## 接着运行容器
/usr/local/spark/bin/spark-shell \
--master yarn-client \
--driver-memory 1g \
--executor-memory 1g \
--executor-cores 1


/usr/local/spark/bin/spark-submit \
--class org.apache.spark.examples.SparkPi \
--files $SPARK_HOME/conf/metrics.properties \
--master yarn-cluster \
--driver-memory 1g \
--executor-memory 1g \
--executor-cores 1 \
$SPARK_HOME/lib/spark-examples-1.6.0-hadoop2.6.0.jar
```

## 后记
自己配置了一个 `django` 环境并且上传。
<https://hub.docker.com/r/actanble/djangoblog/>
更好的可以参考下面这个连接。
<https://github.com/actble/Docker-Django-Python3-Nginx>

Dockerfile 
```
From ubuntu:16.04

MAINTAINER Jacob chenjr0719@gmail.com

RUN apt-get update && apt-get install -y \
    git \
    vim \
    python3 \
    python3-pip \
    nginx \
    sqlite3 \
    supervisor && rm -rf /var/lib/apt/lists/*

### DockerFIle2 ++ 配置

## Ubutnu 安装 mysql;要输入密码; 112233..
RUN apt-get update && \
apt-get -y install mysql-server \
apt-get -y install mysql-client \
apt-get -y install libmysqlclient-dev \
# 这里重新启动Mysql加载后面lib包; 因为上面的顺序错了。
# CREATE DATABASE `website` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci; 
## GRANT ALL PRIVILEGES ON *.* TO 'monty'@'%' IDENTIFIED BY 'some_pass' WITH GRANT OPTION;
RUN /etc/init.d/mysql restart 

# 安装Django 实际上后面的 `start.sh` 中已经安装了;
RUN pip3 install uwsgi django

### END DockerFile2 ++ 配置
# setup all the configfiles
RUN echo "daemon off;" >> /etc/nginx/nginx.conf
COPY nginx-site.conf /etc/nginx/sites-available/default
COPY supervisor.conf /etc/supervisor/conf.d/

COPY uwsgi.ini /home/django/
COPY uwsgi_params /home/django/
# COPY 本地的文件到容器的/home/django中完成配置 

COPY start.sh /home/django/

EXPOSE 80
CMD ["/bin/bash", "/home/django/start.sh"]

```

## Mysql 相关
```
docker pull mysql 
// 开放一个随机端口
docker run -itd -P mysql bash
docker exec -it <c_id> bash 
>mysql  >>>>>
update user set authentication_string = password('112233..') where user = 'root';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY '112233..' WITH GRANT OPTION;
exit
// 收工
```