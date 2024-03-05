---
title: "Basicos para Pentesters (Basicos)"
excerpt: "Una lista de Commandos y de informacion acerca de Linux para personas que empiezan en el mundo del Hacking."
header:
  teaser: "/assets/images/basicLinux.png"
categories:
  - Linux
---

<style>
  .teaser-img {
    width: 900px; /* Ancho de la imagen */
    height: auto; /* Altura ajustada automáticamente */
    max-height: 300px; /* Altura máxima deseada */
    /* Puedes agregar más estilos si es necesario */
  }
</style>

<!-- Puedes usar HTML para la imagen y agregar una clase -->
<img src="{{ page.header.teaser }}" alt="Teaser image" class="teaser-img">

## Comandos para el manejo de ficheros
### cat, more, head, tac

```bash
cat archivo.txt    ## Mostrar contenido completo de un archivo.
more archivo.txt   ## Mostrar contenido de un archivo de forma paginada.
head archivo.txt   ## Mostrar las primeras líneas de un archivo.
tac archivo.txt    ## Mostrar contenido en orden inverso.
```

### cd
```bash
cd directorio    ## Cambiar al directorio especificado.
```
### compress
```bash
compress archivo    ## Comprimir archivo en formato .Z.
```
### cp
```bash
cp archivo.txt /directorio/destino    ## Copiar un archivo a otro directorio.
cp -R /directorio/origen /directorio/destino    ## Copiar directorio completo.
```
### chmod
```bash
chmod [ugo]+[rwx] nombre_archivo    ## Cambiar permisos de un archivo.
```
### chown
```bash
chown usuario.grupo nombre_archivo    ## Cambiar propietario y grupo de un archivo.
```
### df
```bash
df -h    ## Mostrar espacio libre en disco (formato legible por humanos).
```
### du
```bash
du -sh    ## Mostrar espacio en disco utilizado.
```
### du -sh * | sort -h
```bash
du -sh * | sort -h    ## Mostrar y ordenar por tamaño los directorios.
```
### ncdu
```bash
ncdu /directorio    ## Diagnosticar el uso de disco (NCurses Disk Usage).
```
### fdformat
```bash
fdformat dispositivo    ## Formatear un diskette.
```
### fdisk
```bash
fdisk dispositivo    ## Particionar unidades.
```
### file
```bash
file archivo    ## Determinar el tipo de archivo.
```
### find
```bash
find directorio -name nombre_archivo    ## Buscar archivo en un directorio (recursivamente).
```
### fsck
```bash
fsck dispositivo    ## Chequear el sistema de archivos.
```
### grep
```bash
grep "texto" archivo.txt    ## Buscar texto en un archivo.
```
### gzip
```bash
gzip archivo    ## Comprimir archivo en formato GZip.
```
### ln
```bash
ln -sf origen destino    ## Crear enlace simbólico.
```
### ls
```bash
ls /directorio    ## Listar contenido de un directorio.
ls -l --full-time    ## Mostrar formato de fecha completo.
ls -X    ## Ordenar por extensión.
ls -t    ## Ordenar por fecha.
ls -S    ## Ordenar por tamaño.
```
### mkdir
```bash
mkdir directorio    ## Crear un directorio.
```
### mkfs
```bash
mkfs dispositivo    ## Crear nuevo sistema de archivos.
```
### mkswap
```bash
mkswap dispositivo    ## Crear espacio de intercambio.
```
### tar
```bash
tar -xvzf archivo.tar.gz    ## Descomprimir archivo *.tar.gz.
tar -xvvf archivo.tar    ## Descomprimir archivo *.tar.
tar -cvvf archivo.tar directorio    ## Comprimir directorio en archivo *.tar.
```
### touch
```bash
touch archivo    ## Modificar fecha de un archivo.
```
### type
```bash
type nombre_archivo    ## Mostrar la ubicación de un archivo en el "path".
```
### umount
```bash
umount dispositivo    ## Desmontar una unidad montada.
```
### byobu
```bash
byobu    ## Compartir consola de forma remota.
```
### dd
```bash
dd if=/dev/zero of=test.img bs=1MB count=4096    ## Crear un archivo de ceros (4GB).
```
### scp
```bash
scp -P PUERTO archivo usuario@servidor:ruta    ## Copiar archivos por red con SSH.
```
## Cambiar permisos recursivamente solo a directorios
```bash
find . -type d -exec chmod 0755 {} \;
```
## Cambiar permisos recursivamente solo a archivos
```bash
find . -type f -exec chmod 0644 {} \;
```
## Comprimir y descomprimir
```bash
tar -xvzf archivo.tar.gz    ## Descomprimir archivo *.tar.gz.
tar -xvvf archivo.tar    ## Descomprimir archivo *.tar.
tar -cvvf archivo.tar directorio    ## Comprimir directorio en archivo *.tar.
gzip -d archivo.gz    ## Descomprimir archivo *.gz.
gzip archivo    ## Comprimir ficheros empaquetados.
```
## Comandos para el manejo de procesos
### dmesg
```bash
dmesg    ## Listar hardware reconocido.
```
### fdisk /mbr
```bash
fdisk /mbr    ## Eliminar Lilo.
```
### free
```bash
free    ## Mostrar memoria libre y utilizada.
```
### halt
```bash
halt    ## Apagar la máquina.
```
### kill
```bash
kill PID    ## Matar un proceso por su número de identificación.
```
### ldd
```bash
ldd /ruta/programa    ## Mostrar librerías necesarias para ejecutar un programa.
```
### lsmod
```bash
lsmod    ## Ver módulos cargados en el kernel.
```
### modprobe
```bash
modprobe -a    ## Instalar módulos.
modprobe -r    ## Eliminar módulos.
modprobe -l    ## Listar módulos.
```
### ps
```bash
ps fax    ## Mostrar todos los procesos en ejecución.
```
### pstree
```bash
pstree    ## Mostrar procesos en forma de árbol.
```
### reboot
```bash
reboot    ## Reiniciar el sistema.
```
### shutdown
```bash
shutdown    ## Cerrar el sistema.
```
### top
```bash
top    ## Monitorear procesos y estado del sistema.
```
### uname
```bash
uname -a    ## Mostrar información del sistema.
```
### /sbin/ldconfig -p
```bash
/sbin/ldconfig -p    ## Librerías instaladas.
```
### source /root/.bashrc
```bash
source /root/.bashrc    ## Ejecutar de nuevo el .bashrc modificado.
```
## Comandos para el manejo de usuarios
### adduser
```bash
adduser nombre_usuario    ## Crear una cuenta de usuario.
```
### chsh
```bash
chsh nombre_usuario    ## Cambiar la shell de un usuario.
```
### groups
```bash
groups    ## Mostrar el listado de grupos de usuarios del sistema.
```
### id
```bash
id nombre_usuario    ## Mostrar la información de usuario y grupo de un usuario.
```
### logout
```bash
logout    ## Salir del sistema y permitir el ingreso a otro usuario (Ctrl + D).
```
### passwd
```bash
passwd nombre_usuario    ## Cambiar el password de un usuario.
```
### su
```bash
su nombre_usuario    ## Dar privilegios de root a un usuario.
```
### talk
```bash
talk nombre_usuario    ## Permitir chatear con otros usuarios.
```
### users
```bash
users    ## Lista los usuarios conectados al sistema.
```
### who
```bash
who    ## Muestra información de los usuarios conectados al sistema.
who -b    ## Saber el último reboot.
who -r    ## Saber el RunLevel actual.
```
### whoami
```bash
whoami    ## Muestra información propia.
```
## Comandos de red
### finger
```bash
finger nombre_usuario    ## Información sobre un usuario.
```
### host
```bash
host "destino"    ## Muestra la IP de "destino".
```
### ifconfig
```bash
ifconfig    ## Ver las placas de red.
```
### mail
```bash
mail    ## Sencillo programa de correo.
```
### netstat
```bash
netstat    ## Testeo de red.
```
### nmap
```bash
nmap "ip de destino"    ## Analizar IPs o rangos.
```
### nslookup
```bash
nslookup dominio [dns-server]    ## Query Internet name servers interactively.
```
### ping
```bash
ping "destino"    ## Enviar paquetes y esperar una respuesta.
```
### talk
```bash
talk nombre_usuario    ## Establecer una charla con otro usuario.
```
### traceroute
```bash
traceroute dominio.extension    ## Print the route packets take to network host.
```
### wall
```bash
wall "mensaje"    ## Mensaje a todos los usuarios.
```
### pktstat
```bash
pktstat -i eth0    ## Muestra el estado de procesos relacionados con la interfaz de red eth0.
```
### iptraf
```bash
iptraf    ## Información de tráfico de red.
```
### iftop
```bash
iftop    ## Top del tráfico de red.
```
### dig
```bash
dig DOMINIO    ## Información de DNS del dominio.
```
### dig DOMINIO INPUT
```bash
dig DOMINIO INPUT    ## Información de DNS del dominio sobre el input deseado (INPUT = CNAME, TXT, NS, A[default]).
```
## Otros comandos
### banner
```bash
banner "texto"    ## Saca letrero en pantalla con el texto proporcionado.
```
### cal
```bash
cal    ## Muestra el calendario.
```
### clear
```bash
clear    ## Limpia la pantalla.
```
### date
```bash
date    ## Muestra el día y la hora.
```
### ddate
```bash
ddate    ## Similar a 'date' pero de forma diferente.
```
### info
```bash
info    ## Muestra la ayuda de un comando.
```
### man
```bash
man nombre_comando    ## Muestra las páginas del manual de un comando.
```
### mesg
```bash
mesg    ## Bloqueo de mensajes de write.
```
### startx
```bash
startx    ## Para iniciar XWindow.
```
### write
```bash
write nombre_usuario    ## Manda un mensaje a la pantalla de un usuario.
```
### byobu
```bash
byobu    ## Manejador de terminales (similar a GNU Screen o tmux).
```
F2 -> nueva pestaña
F3 -> moverse por las pestañas.

### screen
```bash
screen    ## Gestión remota. Permite desconectar y volver a reconectar sin parar el proceso que hemos lanzado.
```
### Crear el descriptor de archivo:
		`exec 3<> file`
### Uso de descriptor
		`whoami >&3`  # Manda al descriptor de archivo 
		`exec 7>&5`  # Copia de deesciprotr de archivo
		`exec 5&>5-` # Copiar descriptor 5 en 6 y borrar el 5
### Eliminar descriptor de archivos
		`exec 3>&-`
## Capability
con Getcap podemos listar la Capabiity del sistema:
	```bash
  getcap -r / 2>/dev/null
  ```
Nos permiten manipular nuestro identificador de usuario(UID).

- https://gtfobins.github.io/#+capabilities

## Busquedas

Archivos

	`find / -name passwd 2>/dev/null`
	`find / -name passwd 2>/dev/null | xargs ls -l`

### Por SUID

	`find / -perm -4000 2>/dev/null`

### Por grupo

	`find / -group trexngero -type d 2>/dev/null` # Directorio
	`find / -group trexngero -type f 2>/dev/null` # Archivos 

### Por permiso

	`find / -user root -writable 2>/dev/null` # W
	`find / -user root -executable -type f 2>/dev/null` # X
	`find / -user root -readtable 2>/dev/null` # W

### Por nombres 

	`find / dex\* 2>/dev/null`

### Por tamaño 

	`find / -user root 'size 5000Kb' 2>/dev/null` # W

## LSATTR y CHATTR
Para que no se pueda borrar por root:

		`lsattr`
		
Asignar Flag
	
		`chattr +i -V file`
		
Quitar FLag 

		`chattr -i -V file`

## Permisos SGUID y SUID
### SGUID

El permiso SGID está relacionado con los grupos, tiene dos funciones:

- Si se establece en un **archivo**, permite que cualquier usuario ejecute el archivo como si fuese miembro del grupo al que pertenece el archivo.
- Si se establece en un **directorio**, a cualquier archivo creado en el directorio se le asignará como grupo perteneciente, el grupo del directorio.

Para los directorios, la lógica del SGID y el motivo de su existencia es por si trabajamos en grupo, para que todos podamos acceder a los archivos de las demás personas. Si SGID no existiera, cada persona cada vez que crease un archivo, tendría que cambiarlo del grupo suyo al grupo común del proyecto. Asimismo, evitamos tener que asignarle permisos a «Otros».

#### Asignar permiso
Dos formas: 
		
	`chmod g+s file`
	
	`chmod 2755 file`
#### Busca binarios SIUD
	`find / -type -perm -2000 2>/dev/null`


### SIUD

El permiso SUID permite que un archivo se ejecute como si del propietario se tratase, independientemente del usuario que lo ejecute, el archivo se ejecutará como el propietario.
Al asignar permisos SUID, la salida del comando whoami, a pasado de ser sikumy a ser root. Esto porque como podemos ver, el propietario del binario de whoami, es root.

#### Asignar permiso
Dos formas: 
		
	`chmod u+s file`
	
	`chmod 4755 file`
#### Busca binarios SIUD
	`find / -type f -pernm -4000 2>/dev/null`

## Permisos Sticky Bit
El bit sticky se representa mediante una t en la máscara de permisos, apareciendo en la posición del permiso de búsqueda de los otros. Se aplica a directorios de uso público, es decir, aquellos que tienen todos los permisos activados y por tanto, todo el mundo puede crear y borrar ficheros; esto puede ser un poco peligroso porque un usuario puede borrar los ficheros de otros y para evitarlo se activa el bit sticky. Con este permiso se consigue que cada usuario solo pueda borrar los ficheros que son de su propiedad. Un directorio al que se le suele activar el bit sticky es /tmp.

		`chmod +t dir`  

## Comandos Debian
### apt-get
```bash
apt-get update    ## Actualiza la base de datos de los paquetes .deb.
apt-get upgrade    ## Actualiza los paquetes a su última versión.
apt-get install "paquete"    ## Instala el paquete especificado.
apt-get remove "paquete"    ## Desinstala el paquete especificado.
apt-get check    ## Actualiza la caché de paquetes.
apt-get clean    ## Borra los paquetes .deb descargados.
apt-get dist-upgrade    ## Hace un upgrade del sistema operativo.
apt-get source "paquete"    ## Descarga fuentes del paquete especificado.
apt-cache showpkg "paquete"    ## Muestra todas las versiones disponibles del paquete.
modconf    ## Pequeño programa para sacar o poner módulos del kernel.
update-rc.d "opcion" "programa o script" "opcion"    ## Remueve o agrega el script o programa a los niveles de corrida especificados.
```
## Comandos Red Hat
### rpm
```bash
rpm -q "programa"    ## Para saber si "programa" está instalado.
rpm -qs "programa"    ## Estado de todos los archivos de "programa".
rpm -qd "programa"    ## Documentación de "programa" instalada.
rpm -qc "programa"    ## Archivos de configuración de "programa".
rpm -qa "programa"    ## Muestra todos los rpm de "programa".
rpm -qa | grep "programa"    ## Busca el nombre de paquete del "programa".
rpm -i "programa"    ## Instala "programa".
rpm -u "programa"    ## Actualiza "programa".
rpm -e "programa"    ## Elimina "programa".
rpm -ivh "programa"    ## Instala "programa" en pasos y muestra el progreso de la instalación.
```
## Comandos para el manejo de paquetes, servicios e instalaciones
### tar
```bash
tar - "opcion" "paquete"    ## Comprime o descomprime el "paquete" de formato tar.gz, .tgz o tar.bz2.
```
### rpm
```bash
rpm - "opcion" "paquete"    ## Instala o desinstala el "paquete" dependiendo de la opción.
```
### dpkg
```bash
dpkg - "opcion" "paquete"    ## Instala o desinstala el "paquete" dependiendo de la opción (solo Debian).
dpkg -i    ## Instalar paquete.
dpkg --info    ## Información del paquete.
dpkg -c    ## Muestra la lista de ficheros contenidos.
dpkg --contents    ## Lista todos los ficheros contenidos con sus directorios.
dpkg -f    ## Muestra información de versión del paquete.
dpkg --unpack    ## Desempaqueta.
dpkg --purge    ## Borra un paquete incluidos los ficheros de configuración.
dpkg -r    ## Borra un paquete pero no borra los ficheros de configuración.
dpkg -L    ## Lista el paquete si está instalado.
dpkg -l    ## Lista los paquetes instalados.
update-rc.d "opcion" "programa o script" "opcion"    ## Remueve o agrega el script o programa a los niveles de corrida que se le asignen.
```
## Entorno gráfico xwindow
### startx
```bash
startx    ## Iniciar X.
```
### startx -- :2 , :3 , :4 , etc.
```bash
startx -- :2 , :3 , :4 , etc.    ## Abrir nuevas sesiones.
```
### /etc/X11/XF86Config
```bash
/etc/X11/XF86Config    ## Configuración de XF86.
```
### /etc/X11/Xserver
```bash
/etc/X11/Xserver    ## Configuración de servidor X.
```
### XF86Setup
```bash
XF86Setup    ## Configurar X (entorno gráfico).
```
### ctrl-alt-backspace
```bash
ctrl-alt-backspace    ## Salir de las X.
```
### /etc/X11/window-managers
```bash
/etc/X11/window-managers    ## Fichero donde está el programa que arranca las X.
```
## Manejo de las Unidades de Diskettes y CD-ROM

### Montar Diskette
```bash
mount -t msdos /dev/floppy /mnt    ## /dev/floppy = /dev/fd0
```
### Montar CD-ROM
```bash
mount -t iso9660 /dev/cdrom /mnt    ## /dev/cdrom = /dev/hdb
```
### Listar Unidad Montada
```bash
ls /mnt
```
### Desmontar Todo
```bash
umount /mnt
```
### Formatear Floppy
```bash
superformat /dev/fd0 hd (msdos)    ## (Es necesario tener instalado fdutils)
superformat /dev/fd0 sect=21 cyl=83    ## mkfs.ext2 /dev/fd0 (crea sistema de archivos ext2)
```
## Convertir Paquetes de RedHat a Debian
```bash
alien -d fichero.rpm    ## Convierte fichero rpm a deb.
alien -d fichero.tgz    ## Convierte fichero tgz a deb.
alien -i fichero.rpm    ## Convierte fichero rpm a deb y lo instala.
alien -i fichero.tgz    ## Convierte fichero tgz a deb y lo instala.
```
## Manejo de la Impresora
```bash
/dev/lp1    ## Dispositivo.
ls > /dev/lp1    ## Probarlo.
```
## Imprimir
```bash
lpr    ## Ver colas de impresión.
lpc status    ## Estado de impresoras.
lprm    ## Eliminar colas en impresión.
```
## Comandos de IRC para IrcII
```bash
/server    ## Conectar con un servidor.
(/server irc.arrakis.es)    ## Conectar con un canal.
(/channel #linux)    ## Datos de servidor o nickname.
/list    ## Listar canales IRC.
/names    ## Nicknames de todos los usuarios.
/msg <nick> <msg>    ## Mensaje privado a nick.
/who <canal>    ## Quién está conectado y sus datos.
/whois <nick>    ## Verdadera identificación de alguien.
/quit    ## Desconectar.
```
## MYSQL

### Exportación
```sql
mysqldump -u user -p db_name > file_name.sql    ## (Preguntará por la 'clave')
```
### Importación
```sql
mysql -u USER -p DB_NAME -h HOST < SQL_FILE_NAME    ## (Preguntará por la 'clave')
```
## Top
```bash
mytop -u USUARIO -p CLAVE -d BBDD -sNUM    ## (NUM = número de segundos para el refresco)
```
## Moverse a un Directorio
```bash
cd /path/subpath ...
```
## Listar un Directorio
```bash
ll
ls -al
ls -lha
```
## Borrar Ficheros o Directorios
```bash
rm nombre_fichero
rm -R nombre_directorio
```
## Copiar/Duplicar Fichero con Nuevo Nombre
```bash
cp nombre_fichero nombre fichero_nuevo
```
## Mover/Renombrar
```bash
mv nombre1 nombre2    ## Cambia el nombre del directorio si "nombre2" no existe, si no, mueve nombre1 dentro de nombre2.
```
## Modificar Propietario de un Fichero o un Directorio
```bash
chown usuario.grupo fichero
```
## Modificar Permisos de un Fichero o un Directorio
Los permisos se agrupan de tres en tres:
```
usuario grupo otros
rwx        rwx     rwx

1 ó r - lectura
2 ó w - escritura
4 ó x - ejecución
```
Se pueden cambiar de dos formas:

a)
```bash
chmod 771 fichero    ## Todos los permisos para usuario y grupo y lectura para otros.
1 - r - lectura
2 - w - escritura
4 - x - ejecucion
```
b)
```bash
chmod u+x fichero    ## Añade(+) permiso al usuario(u) de ejecución(x)
chmod g-w fichero    ## Quita(-) permiso al grupo(g) de escritura(w)
```
## Editar un Fichero
WARNING!!!! (hacer solo en local y con el usuario)
{: .notice--danger}
```bash
joe nombre_fichero    ## Abre el editor
Ctrl + _    ## Deshacer
Ctrl + K y después X    ## Guarda y cierra
Ctrl + K y después H    ## Despliega la ayuda y en él puedes ver distintas acciones "^" significa "ctrl"
```
## Verificar Memoria RAM, Tipo, Bancos, Tamaño...
dmidecode --type 17    ## Muestra información sobre las tarjetas de memoria y dónde están pinchadas.
```bash
lsb_release -a    ## Permite saber la distribución y versión de SO instalado.
cat /etc/redhat-release    ## Muestra información sobre el sistema.
lshw    ## Requiere ser instalado en Debian (## apt-get install lshw). Muestra información detallada del sistema.
grep MemTotal /proc/meminfo    ## Muestra la memoria RAM total del sistema.
grep SwapTotal /proc/meminfo    ## Muestra la cantidad de espacio swap del sistema (memoria de intercambio).
```
## Herramientas para Administración del Sistema
```bash
lsb_release -a    ## Permite saber la distribución y versión de SO instalado.
cat /etc/redhat-release    ## Muestra información sobre el sistema.
ls /etc/init.d/    ## Lista los servicios disponibles.
```
## Reiniciar Servidores Web
```bash
/etc/init.d/apache2 restart    ## Reinicia Apache.
service apache2 restart    ## Reinicia Apache (alternativa).
/etc/init.d/mysql restart    ## Reinicia MySQL.
service mysql restart    ## Reinicia MySQL (alternativa).
/etc/init.d/nginx restart    ## Reinicia Nginx.
service nginx restart    ## Reinicia Nginx (alternativa).
/etc/init.d/php-fpm restart    ## Reinicia PHP-FPM.
```
## Control de Memoria en Uso
```bash
swapon -s    ## Verifica el espacio de intercambio (swap).
free -m    ## Muestra información sobre el uso de la memoria.
php -r "echo ini_get('memory_limit').PHP_EOL;"    ## Verifica el límite de memoria en PHP.
htop    ## Herramienta interactiva para el monitoreo del sistema.
```
## Control de Versiones de Servicios Web en Servidores
```bash
lsb_release -a    ## Muestra información sobre la distribución y versión del SO.
cat /etc/redhat-release    ## Muestra información sobre el sistema.
apache2 -v    ## Muestra la versión de Apache.
httpd -v    ## Muestra la versión de Apache (en CentOS/cPanel).
php -v    ## Muestra la versión de PHP.
mysql -u root -p    ## Inicia sesión en MySQL como root y solicita la clave.
mysql> select version();    ## Muestra la versión de MySQL.
ps -Af | grep mysql | grep -v "grep" | wc -l    ## Cuenta el número de procesos de MySQL.
```
