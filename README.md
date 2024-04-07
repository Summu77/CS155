# CS155-project2

> As a personal course lab assignment, the code mainly refers to [jpslvtr/cs155-proj2](https://github.com/jpslvtr/cs155-proj2/tree/main)
>
> In addition I have provided a lab report for reference and understanding, but please understand that there may be some unidentified problems.

![image-20240407200333832](/assets/image-20240407200333832.png)



## Introduction

> Copied from " CS155: Computer and Network Security  / Project 2: Web Attacks and Defenses  / introduction "
>
> [CS155 Computer and Network Security](https://cs155.stanford.edu/)

In this project, you will construct several attacks against a web application (Part 1), and then update the application to defend against those attacks (Part 2). You will specifically be attacking Bitbar, a Node.js web app that lets users manage Bitbars, a new ultra-safe cryptocurrency. Each user is given 100 Bitbars when they register for the site. They can transfer Bitbars to other users using the web interface, as well as create and view other user profiles.  

You have been given the source code for the Bitbar application. Real attackers generally do not have access to the source of a target website, but the source may make finding the vulnerabilities a bit easier. Bitbar is powered by a collection of Node packages, including the Express.js web application framework, a SQLite database, and EJS for HTML templating. The list of resources in the next section includes links for more information on these packages as well as other information that you can use as a reference.  

## Part 1 Attacks

There are seven attack tasks in all:

1. Exploit Alpha: Cookie Theft  
2. Exploit Bravo: Cross-Site Request Forgery  
3. Exploit Charlie: Session Hijacking with Cookies  
4. Exploit Delta: Cooking the Books with Cookies  
5. Exploit Echo: SQL Injection  
6. Exploit Foxtrot: Profile Worm  
7. Exploit Gamma: Password Extraction via Timing Attack  

## Part 2 Defenses

For the defense of the seven tasks, I have divided them into the following four directions:
1. defense against XSS attack (Task 1 and Task 6)
2. defense against CSPF attack (Task 2, Task 3 and Task 4)
3. defense against SQL injection attack (Task 5)
4. defending against channel measurement attacks (Task 7)

The defense techniques used in this are:

1. content security checks, dangerous characters for escaping, filtering, banning, etc. (XSS)
2. CSP content security policy (XSS)
3. CSRF token technology (CSPF)
4. Session HMAC authentication technology (CSPF)
5. SQL parameterized queries (SQL injection)
6. Random Corresponding Time Strategy (Timing Attacks)

## Setup Instructions  

> [小乖乖的妙妙屋 (qing-lky.github.io)](https://qing-lky.github.io/)
>
> The experiments were conducted on VMware using the Linux distribution Ubuntu 22.04 Server.
>
> Please download docker before experimenting.

1. cs155 Spring 2022

```
curl -O https://cs155.github.io/Spring2022/hw_and_proj/proj2/proj2.pdf
curl -O https://cs155.github.io/Spring2022/hw_and_proj/proj2/proj2.zip
```

2. docker

```
unzip proj2.zip -d proj2/
cd proj2
bash build_image.sh
bash start_server.sh
```

Tips:

- Ubuntu :[VMware 安装 Ubuntu（2023 当然要看热乎的教程了）_vmware安装ubuntu-CSDN博客](https://blog.csdn.net/m0_51913750/article/details/131604868)

- Docker:[一分钟 ubuntu22.04 linux 安装 docker_哔哩哔哩_bilibili](https://www.bilibili.com/video/BV1LN4y1x7xn/?spm_id_from=333.788.recommend_more_video.-1&vd_source=ae67b970bd4a0665fa92195df95aa1f3)
