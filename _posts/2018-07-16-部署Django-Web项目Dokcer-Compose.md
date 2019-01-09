---
layout:     post
title:      部署Django-Web项目Dokcer-Compose
subtitle:   WAF入门
date:       2018-07-16
author:     BY
header-img: img/post-bg-debug.png
catalog: true
tags:
    - Django
    - Docker
---

## docker-compose.yml
```
version: "2.2"

services:
   web:
      container_name: web-server
      restart: always
      build: ./wkdir_web
      expose:
        - "8077"
      volumes:
        - ./wkdir_web:/usr/src/app
      command: /usr/local/bin/gunicorn website.wsgi:application -w 2 -b :8077
      networks:
          customize_net:
            ipv4_address: 192.168.32.223

   nginx:
      container_name: nginx
      restart: always
      build: ./nginx-container/
      ports:
        - "80:80"
      volumes:
        - .:/home/wkdir/2018-12-11/
      links:
        - web:web
      networks:
          customize_net:
            ipv4_address: 192.168.32.99

   mysql:
      container_name: mysql-server
      image: 'sameersbn/mysql:5.7.22-1'
      volumes:
        - /srv/docker/data/mysqldata:/var/lib/mysql
      restart: always
      expose:
        - "3306"
      environment:
       - DB_USER=admin007
       - DB_PASS=myadmin@816
       - DB_NAME=qydldb
       - DB_REMOTE_ROOT_NAME=root
       - DB_REMOTE_ROOT_PASS=test@1q2w2e4R

      networks:
        customize_net:
          ipv4_address: 192.168.32.101

networks:
  customize_net:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 192.168.32.0/24

```