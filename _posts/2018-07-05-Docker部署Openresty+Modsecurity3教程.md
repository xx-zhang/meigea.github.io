---
layout:     post
title:      Docker部署Openresty+Modsecurity3教程
subtitle:   Docker Openresty Modsecurity
date:       2018-07-05
author:     BY
header-img: img/post-bg-0.png
catalog: true
tags:
    - Dokcer
    - WAF
---

# 描述
> Centos7 系统 sshd + openresty1.13 + modsec-v3 + crs3.0+supervisor

# 执行
`docker run -itd --name=waf -p 30022:6922 -p 30080:6980 registry.cn-beijing.aliyuncs.com/actanble/openresty-modsec-crs3-ssh-p69 supervisord -n`

# 扩展
- 如果自己要扩展 就把 `-v /opt/nginx/:/etc/nginx -v /var/log/waf-log/:/var/log/` 添加扩展
- 注意使用映射前`/opt/nginx/`一定要有文件。

# 查看部署日志
- `docker logs <container_name>`

## 安装 Nginx(OpenResty) + Modsec3.02 版本
## 2018-8-21 记录
### 安装失败; 回到3.0版本
- 参考这个 Dockerfile 修改其中的Nginx为openresty


也可以用 -V 先连接
```

## 基础安装包
from registry.cn-beijing.aliyuncs.com/actanble/centos7

RUN yum -y update

#docker run -itd --name=waf --net=host -v /etc/localtime:/etc/localtime -v /etc/yum.repos.d/:/etc/yum.repos.d/ \
#        registry.cn-beijing.aliyuncs.com/actanble/centos7 /usr/sbin/init


RUN mkdir -p /usr/local/src/nginx_waf
WORKDIR /usr/local/src/nginx_waf
RUN cd /usr/local/src/nginx_waf
RUN yum -y install wget curl git gcc-c++ make gcc
RUN wget https://archive.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-7
RUN mv RPM-GPG-KEY-EPEL-7 /etc/pki/rpm-gpg
## nginx 编译需要
COPY /usr/lib/rpm/redhat /usr/lib/rpm
## 时区需要
COPY /etc/localtime /etc/
## yum 源更改
COPY /etc/yum.repos.d/ /etc/
# COPY /etc/*  /
## 前置工具包
RUN yum install autoconf automake bzip2 \
         flex httpd-devel libaio-devel \
         libass-devel libjpeg-turbo-devel libpng12-devel \
         libtheora-devel libtool libva-devel libvdpau-devel \
         libvorbis-devel libxml2-devel libxslt-devel \
         perl texi2html unzip zip openssl \
         openssl-devel geoip geoip-devel nginx gcc-c++

## 解决一些编译安装常见错误的辅助包
RUN yum -y install gd-devel GeoIP GeoIP-devel GeoIP-data libxml2 libxml2-dev zlib-devel
## 编译安装 ModSecurity
RUN cd nginx_waf && git clone https://github.com/SpiderLabs/ModSecurity \
&&  cd ModSecurity  \
&&  git checkout -b v3/master origin/v3/master   \
&&  sh build.sh  \
&&  git submodule init  \
&&  git submodule update  \
&&  ./configure  \
&&  make && make install  \

## 记录下环境变量: Nginx 版本
ENV NGINX_VERSION 1.12.2

RUN cd /usr/local/src   \
&& git clone https://github.com/SpiderLabs/ModSecurity-nginx.git   \
&& wget http://nginx.org/download/nginx-{NGINX_VERSION}.tar.gz
&& tar zxvf nginx-{NGINX_VERSION}.tar.gz && ./configure   \
   --prefix=/usr/share/nginx   \
   --sbin-path=/usr/sbin/nginx  \
   --modules-path=/usr/lib64/nginx/modules  \
   --conf-path=/etc/nginx/nginx.conf  \
   --error-log-path=/var/log/nginx/error.log  \
   --http-log-path=/var/log/nginx/access.log  \
   --http-client-body-temp-path=/var/lib/nginx/tmp/client_body  \
   --http-proxy-temp-path=/var/lib/nginx/tmp/proxy  \
   --http-fastcgi-temp-path=/var/lib/nginx/tmp/fastcgi  \
   --http-uwsgi-temp-path=/var/lib/nginx/tmp/uwsgi  \
   --http-scgi-temp-path=/var/lib/nginx/tmp/scgi  \
   --pid-path=/run/nginx.pid  \
   --lock-path=/run/lock/subsys/nginx  \
   --user=nginx  \
   --group=nginx  \
   --with-file-aio  \
   --with-ipv6  \
   --with-http_auth_request_module  \
   --with-http_ssl_module  \
   --with-http_v2_module  \
   --with-http_realip_module  \
   --with-http_addition_module  \
   --with-http_xslt_module=dynamic  \
   --with-http_image_filter_module=dynamic  \
   --with-http_geoip_module=dynamic  \
   --with-http_sub_module  \
   --with-http_dav_module  \
   --with-http_flv_module  \
   --with-http_mp4_module  \
   --with-http_gunzip_module  \
   --with-http_gzip_static_module  \
   --with-http_random_index_module  \
   --with-http_secure_link_module  \
   --with-http_degradation_module  \
   --with-http_slice_module  \
   --with-http_stub_status_module  \
   --with-http_perl_module=dynamic  \
   --with-mail=dynamic  \
   --with-mail_ssl_module  \
   --with-pcre --with-pcre-jit  \
   --with-stream=dynamic  \
   --with-stream_ssl_module  \
   --with-google_perftools_module  \
   --with-debug  \
   --with-cc-opt="-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -m64 -mtune=generic "  \
   --with-ld-opt="-Wl,-z,relro -specs=/usr/lib/rpm/redhat/redhat-hardened-ld -Wl,-E"  \
   --add-dynamic-module=../ModSecurity-nginx

RUN wget https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended
RUN mv modsecurity.conf-recommended  /etc/nginx/modsecurity.conf
RUN find /etc/nginx/ -type f -name "modsecurity.conf" | xargs sed -i "s/SecRuleEngine DetectionOnly/SecRuleEngine On/g" ;
```


### 将开源的检测规则放在我们的 nginx 里面

```
RUN cd nginx_waf && git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git \
&& cd owasp-modsecurity-crs/ \
&& cp -R owasp-modsecurity-crs/rules/ /etc/nginx/  \
&& cp crs-setup.conf.example /etc/nginx/crs-setup.conf
### waf配置文件加载配置。
RUN echo "\n\n#加载规则配置文件\nInclude crs-setup.conf\n#加载所有规则\nInclude rules/*.conf\n#禁用某个规则方法\n#SecRuleRemoveById 911250\n" >> /etc/nginx/modsecurity.conf
```

### 将本地的 nginx.conf 放进去; 添加

```
COPY nginx.conf /etc/nginx/

COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["entrypoint.sh"]
CMD ["/usr/sbin/nginx"]
```

## 出现的问题

 1, 缺少 `redhat的ld-opt` 
- 下载`yum -y install redhat-rpm-config`

 2, `error: perl module ExtUtils::Embed is required` 扩展包异常。
- `yum install perl perl-devel perl-ExtUtils-Embed`

 3, 缺少`google`分析工具 `google-perftools`
- `git clone https://github.com/gperftools/gperftools && cd gperftools && sh autogen.sh && ./configure && make && make install`

 4, nginx 启动缺少 `libprofiler.so`
- `ldd /usr/sbin/nginx`, `find / -type f -name "libprofiler.so*"`
- `ln -sv /usr/local/lib/libprofiler.so.0.4.17 /lib64/libprofiler.so.0`

 4.1, nginx 找到自己的mod模块
- `find / -type f -name "ngx_http_modsecurity_module.so*"`

 5, nginx 启动失败; `mod模块问题：ctl:requestBodyProcessor=URLENCODED`
- [URLENCODE失败](https://github.com/SpiderLabs/owasp-modsecurity-crs/issues/1120)
- [mod更新内容](https://coreruleset.org/)

 6, 替换 crs3.03-3.10版本都会出现问题; 901里面的便编码；dos里面的语法。
- 修改910350编码为json, 注释dos核心规则
- 912110 附近两条修改为
- 914100 太多了。


## 设置相关
- 请求中太多内容 [请求中有图片二进制](https://github.com/SpiderLabs/ModSecurity-nginx/issues/115)
```
SecResponseBodyLimit 1
SecResponseBodyMimeType text/plain text/html
```

### SSH 服务
- `yum install openssh-server -y`
- `vi /etc/ssh/ssh_config` 修改端口 
- `ssh-keygen -t dsa -f /etc/ssh/ssh_host_ed25519_key`
- `ssh-keygen -t rsa -b 2048 -f /etc/ssh/ssh_host_rsa_key`
- `ssh-keygen -t dsa -f /etc/ssh/ssh_host_dsa_key`


## 部署结束

- `-p 6922, -p 6980`
- `docker run -itd --name=waf -p 30022:6922 -p 30080:6980 registry.cn-beijing.aliyuncs.com/actanble/openresty-modsec-crs3-ssh-p69 supervisord -n`



