---
layout: post
title: Twomillion - Hack The Box
date: 2023-11-03
categories: [htb, easy]
tags: [web, credential, cve]
image:
  path: htb-writeup-twomillion/twomillion_logo.png
  alt: twomillion
---

![logo](htb-writeup-twomillion/logo.png){: .right w="200" h="200" }
Esta máquina es catalogada como fácil, me trajo algo de nostalgia, ya que cuando empecé con esto del Hacking y a jugar 
en Hack The Box, para poder registrarnos a la plataforma teniamos que realizar estos mismo pasos y obtener el código 
de invitación, es decir para hackiar tenias que hackiar :v ( Que Buenos Recuerdos !! ).
Bueno como dije el código de invitación es para poder registrarnos a la plataforma, dentro vamos a encontrar un apartado 
donde podemos interactuar con una API, con ella cambiaremos nuestro rol al de admin para ver cierta ruta, con eso vamos a 
tener RCE, en local para migrar al usuario admin encontramos un archivo con credenciales, y escalaremos privilegios 
con un CVE adecuado.

## Reconocimiento

### Directorios de trabajo

```bash
mkdir twomillion
cd twomillion
mkdir nmap content exploit
```
{: .nolineno}

### nmap

```bash
sudo nmap -p- --open -sS --min-rate 5000 -Pn -n -sCV 10.10.11.221 -oN version-port
```
{: .nolineno}

### version-port

```bash
Nmap scan report for 10.10.11.221
Host is up (0.095s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3eea454bc5d16d6fe2d4d13b0a3da94f (ECDSA)
|_  256 64cc75de4ae6a5b473eb3f1bcfb4e394 (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
{: .nolineno}

- 22: ssh
	+ De momento no voy a tocar este puerto, no cuento con credenciales y la versión de OpenSSH no parece tener una vulnera
bilidad conocida "De momento, claro"
- 80: http
	+ El servicio http está relacionado con la web.

## 80: http

### http

Al parecer hace un redirect a http://2million.htb/ pero mi equipo no sabe resolver a esa dirección, para eso, tengo 
que retocar el archivo /etc/host

### /etc/hosts

```bash
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters
# Others

10.10.11.221    2million.htb
```
{: .nolineno}

Ahora hagamos algo de reconocimiento web para identificar tecnologías, gestores de contenido y otras cosas con herramientas bás
icas como ( whatweb , wappalyzer )

```bash
whatweb 10.10.11.221
```
{: .nolineno}

### whatweb

![](htb-writeup-twomillion/whatweb1.png)

Listo ahora veamos cómo se luce la página desde firefox


### firefox

![](htb-writeup-twomillion/web1.png)

Con el plugin Wappalyzer podemos darnos idea de las cosas que funcionan tras el servidor web

### wappalyzer

![](htb-writeup-twomillion/wappalyzer1.png

Bueno por ahora nada valioso, solo que usa PHP como lenguaje de programación, y que la página se ve como era hace un 
par de años.
Después de un par de minutos viendo las pestaña en la web, hay una interesante que dice (join)

![](htb-writeup-twomillion/join1.png)

y esto no lleva a un apartado donde nos pide un código de invitación

![](htb-writeup-twomillion/join2.png)

Lo que hago en este punto es echar un vistazo al código fuente, y en las últimas líneas veo algo interesante, en javascript

![](htb-writeup-twomillion/join3.png)

Hay una ruta `/js/inviteapi.min.js` que me lleva a un codigo ofuscado

![](htb-writeup-twomillion/join4.png)

Encontré esta página [https://beautifier.io/](https://beautifier.io/) que me va ayudar a desofuscar el javascript

![](htb-writeup-twomillion/join5.png)

Como resultado tenemos esto, y ya puedo leer algo curioso

![](htb-writeup-twomillion/join6.png)

- Método "POST"
- path `/api/v1/invite/how/to/generate`
	+ cómo generar código de invitación

Desde la terminal, podemos hacer eso

```bash
curl -s -X POST http://2million.htb/api/v1/invite/how/to/generate | jq
```
{: .nolineno}

![](htb-writeup-twomillion/curl1.png)

Hay un texto que nos habla de ROT13 , decodificando el mensaje llegamos a la conclusión de que no era `/api/v1/invite/how/to/generate` si no `/api/v1/invite/generate`

![](htb-writeup-twomillion/curl2.png)

Con esto si nos da algo en base 64, y con una linea puedo decodificarlo

```bash
echo QUcyUVctOFBaVUgtV1JSTEstT0tVQzY= | base64 -d ;echo
```
{: .nolineno}

![](htb-writeup-twomillion/curl3.png)

Listo con el código podemos ponerlo en la web, y eso nos lleva a un apartado para poder registrarnos, una vez nos logiemos 
vamos a ver lo siguiente 

![](htb-writeup-twomillion/htb1.png)

La mayoria de los botones me llevan al `/home` hasta que veo `Access` que me lleva a `/access` y eso tiene que ver con la descarga de la VPN para poder conectarnos y tener visibilidad con las máquinas "claro en el entorno real de Hack The Box",
en este punto estuve tocando un rato este apartado pero solo se descargaba el archivo .ovpn, lo curioso es que este 
apartado estaba algo oculto, como dije los otros botones solo me llevan al `/home` y este y el único que me lleva a otra cosa

![](htb-writeup-twomillion/htb2.png)

Bueno es hora de ayudarnos con `BurpSuite`, jugando un rato en el `Repiter` de BurpSuite
Capturo el trafico y como comentaba , solo se puede ver como se descarga el archivo .ovpn

## BurpSuite
![](htb-writeup-twomillion/burp1.png)

Toqueteando un poco las rutas, obtenia esto

![](htb-writeup-twomillion/burp2.png)

probaba con 

- /api/v1/user/vpn/regenerate
- /api/v1/user/vpn/
- /api/v1/user/vpn
- /api/v1/user/
- /api/v1/user
- /api/v1/

y con `/api/v1` tengo algo llamativo

![](htb-writeup-twomillion/burp3.png)

En resumen pordemos interactuar con la API

### Método GET
- /api/v1
	+ lista las rutas
- /api/v1/invite/how/to/generate
- /api/v1/invite/generate
	+ estas dos rutas la tocamos cuando buscamos el código de invitación
- /api/v1/invite/verify
	+ verifica el código de invitación
- /api/v1/user/auth
	+ mira si el usuario está autenticado
- /api/v1/user/vpn/generate
- /api/v1/user/vpn/regenerate
- /api/v1/user/vpn/download
	+ estas están relacionadas con la vpn cosa que no tiene interes por ahora

### Método POST
- /api/v1/user/register
	+ registra un nuevo usuario
- /api/v1/user/login
	+ logea a un usuario existente

### Método GET Admin
- /api/v1/admin/auth
	+ valida si el usuario es admin

### Método POST Admin
- /api/v1/admin/vpn/generate
	+ genera una vpn para cualquier usuario (solo admin puede ver)

### Método PUT Admin
- /api/v1/admin/settings/update
	+ actualiza la configuraciones de usuario


Bueno despues de eso, me interesa cambiar mi rol a uno de admin, para poder entrar a donde solo el admin puede, desde `/api/v1/
admin/settings/update` sin ser admin puedo manipular los atributos de un usario que exista, el API no va ir diciendo que paráme
tros requiere para que la petición sea correcta llegando a lo siguiente

![](htb-writeup-twomillion/burp4.png)
![](htb-writeup-twomillion/burp5.png)
![](htb-writeup-twomillion/burp6.png)
![](htb-writeup-twomillion/burp7.png)

Ahora que ya somo admin, eso lo podemos validar con

- /api/v1/admin/auth
Ya puedo ver lo que me interesa, de todas las rutas a la única que no tenía permisos era 

- /api/v1/admin/vpn/generate

![](htb-writeup-twomillion/burp8.png)

Parece que es igual a las otras rutas de generar un VPN pero en este caso puedo poner cualquier usuario y va descargar la VPN 

Después de un rato pude notar un RCE, usando un `|` para concatenar un comandos

## RCE

![](htb-writeup-twomillion/burp9.png)

Si me pengo en escucha con tcpdump obtengo

### tcpdump

![](htb-writeup-twomillion/burp10.png)

otra forma es con un mensaje y se lo paso a nc

![](htb-writeup-twomillion/burp11.png)

### en escucha con nc

![](htb-writeup-twomillion/burp12.png)

Listo , ahora ganemos un Reverse shell ya basta de bobadas :v

![](htb-writeup-twomillion/burp13.png)

## intrusion

### reverse shell

![](htb-writeup-twomillion/burp14.png)

### tratamiento de la tty

tenemos que convertir esto a una consola completamente interactiva

- script /dev/null -c bash
- ctrl + z
- stty raw -echo;fg
- reset xterm
- export TERM=xterm
- export SHELL=bash
- stty rows 27 columns 127
	+ esto solo aplica para las dimensiones de mi pantalla

### ls

```bash
www-data@2million:~/html$ ls
Database.php  Router.php  VPN  assets  controllers  css  fonts  images  index.php  js  views
```
{: .nolineno}

### ls -la

```bash
www-data@2million:~/html$ ls -la
total 56
drwxr-xr-x 10 root root 4096 Nov  3 22:40 .
drwxr-xr-x  3 root root 4096 Jun  6 10:22 ..
-rw-r--r--  1 root root   87 Jun  2 18:56 .env
-rw-r--r--  1 root root 1237 Jun  2 16:15 Database.php
-rw-r--r--  1 root root 2787 Jun  2 16:15 Router.php
drwxr-xr-x  5 root root 4096 Nov  3 22:40 VPN
drwxr-xr-x  2 root root 4096 Jun  6 10:22 assets
drwxr-xr-x  2 root root 4096 Jun  6 10:22 controllers
drwxr-xr-x  5 root root 4096 Jun  6 10:22 css
drwxr-xr-x  2 root root 4096 Jun  6 10:22 fonts
drwxr-xr-x  2 root root 4096 Jun  6 10:22 images
-rw-r--r--  1 root root 2692 Jun  2 18:57 index.php
drwxr-xr-x  3 root root 4096 Jun  6 10:22 js
drwxr-xr-x  2 root root 4096 Jun  6 10:22 views
```
{: .nolineno}

Tenemos una archivo interesante `.env` este se usa para almacenar alguna variables de entorno

```bash
www-data@2million:~/html$ cat .env 
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```
{: .nolineno}

Revisando el archivo de usuarios para saber con cual se pueden reutilizar estas credenciales

```bash
www-data@2million:~/html$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/bin/bash
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false
admin:x:1000:1000::/home/admin:/bin/bash
memcache:x:115:121:Memcached,,,:/nonexistent:/bin/false
_laurel:x:998:998::/var/log/laurel:/bin/false
```
{: .nolineno}

vemos que existe `admin:x:1000:1000::/home/admin:/bin/bash` y ademas tiene una ruta personal en `/home/admin`
para estár más cómodos, recuerden que tenemos el puero 22 con ssh, y justo eso voy a hacer

### flag usuario admin

![](htb-writeup-twomillion/admin1.png)

para escalar privilegios lo que hice fué buscar archivos que tengan la palabra admin
y si eso no tiene éxito busco archivos que le pertenezcan a admin o estén en el gropo admin

```bash
find / -name admin 2>/dev/null
```
{: .nolineno}

![](htb-writeup-twomillion/admin2.png)

ahora voy de curioso a ver el archivo `/var/main/admin`

![](htb-writeup-twomillion/admin3.png)

De todo lo que dice me llama la atención que hablan de una vulnerabilidad que tiene de nombre `OverlayFS / FUSE`, después de bu
scar en google, di con un CVE potencial
- [CVE-2023-0386](https://github.com/xkaneiki/CVE-2023-0386)

## escalada de privilegios

![](htb-writeup-twomillion/admin4.png)

Lo que voy a hacer es clonar el repositorio, compilarlo y comprimirlo y subirlo a la máquina victima, ya que nos dicen que ejec
utemos un binario en una consola y el otro en una consola diferente.
Luego de lidear con un par de errores al intentar compilar los binarion, por fin pude subir subir los binarios a la máquina victima

- clonar el repositoio
- compilar los binarios
- comprimir la carpeta
- pasar la carpeta a la máquina víctima

![](htb-writeup-twomillion/admin5.png)

descargo la carpeta comprimida, para seguir los pasos de ejecucion que vimos en github

![](htb-writeup-twomillion/admin6.png)

ejecutamos los vinarios en consolas diferentes

![](htb-writeup-twomillion/admin7.png)

### flag de root

![](htb-writeup-twomillion/admin8.png)

