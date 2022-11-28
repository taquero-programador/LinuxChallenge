# LinuxChallenge for SysAdmin

## Day 0
Instalación, configuración y actualización del sistema.
```bash
sudo apt update -y && sudo apt upgrade -y && sudo apt dist-upgrade -y  
```
Crear un usuario con directorio para no usar el usuario `root`.
```bash
sudo useradd -m bender
```
Crear una contraseña para el nuevo usuario.
```bash
sudo passwd bender
```
Es mejor usar `adduser`, es más intuitivo; creá usario, directorio y solicita una contraseña.
```bash
sudo adduser bender
```
Añadir usuario a los grupos _sudo_ y _adm_.
```bash
sudo usermod -a -G adm,sudo bender
```
Eliminar usuario de un determinado grupo.
```bash
sudo deluser bender sudo
```

## Day 1
Conociendo el servidor

#### Usar `SSH` para acceder al servidor
```bash
ssh bender@192.168.0.10
```
Generar llaves para acceder sin contraseña (cubre la parte de "Password-less SSH login").

En el equipo local **no el remoto**.  
Primero validar si existe tu directorio `.ssh`, que es donde se guardan las llaves publicas y privadas.
```bash
ls ~/.ssh
# si no existe, lo podemos crear
mkdir /home/user/.ssh
# nos movemos al directorio
cd ~/.ssh
```
Generar las llaves.
```bash
ssh-keygen -t rsa -b 4096 -C "mimail@mail.com"
```
Copiar la llave `.pub` al servidor remoto.
```bash
ssh-copy-id -i ~/.ssh/key.pub bender@192.168.0.10
```
Durante este proceso se solicitara la contraseña por única ocasión.

#### Comandos simples
```bash
# lista los archivos del directorio actual
ls

# muestra el tiempo que lleva activo el sistema
uptime

# muestra la cantidad de memoria libre del sistema
free

# muestra el almacenamiento usado y disponible
df -h

# muestra versión del sistema, kernel y detalles de equipo
uname -a
Linux debian 5.10.0-19-686-pae #1 SMP Debian 5.10.149-2 (2022-10-21) i686 GNU/Linux
```
#### Cambiar la contraseña
Con el comando `passwd` se puede cambiar la contraseña del usuario actual.
```bash
sudo passwd user
```

#### Extensión
Tunnels ssh.

**Local tunnel:** permite traer un servicio del servidor remoto y ejecutarlo en el equipo de manera local `ssh -L local_port:127.0.0.1:remote_port user@ip`.
```bash
ssh -L 8000:127.0.0.1:8000 bender@192.168.0.10
```
Esto accede al servidor remoto, ahora si ejecutas algún servicio que use el puerto `8000`, en el navegador de tu equipo local podras ingresar a `127.0.0.1:8000` y ver la pagina o proyecto.

Esto es útil con base de datos, ya que por defecto está deshabilitado el acceso remoto. Ahora podras usar el usuario, contraseña y la url de la base de datos `127.0.0.1:3036` en MySQL o DBeaver.

**Remote tunnel:** el servidor remoto permite exponer un puerto del equipo local al exterior, ejemplo: equipo local `A`, tiene bloqueo por ISP y quiere exponer una página web que usa el puerto `8080`; equipo remoto `B`, tiene IP publica y acceso al exterior, entonces tomará el puero `8080` y lo expondra en `ip_public:8081`.
```bash
# ssh -R remote_port:ip_local:local_port server@ip_public
ssh -R 8081:192.168.0.100:8080 bender@192.168.0.10
```
Para que este paso surta efecto, se debe modificar el archivo /etc/ssh/sshd_config.
```bash
# línea a editar
GatewayPorts yes
```
Ahora desde el navegador podras hacer un `http://ip_public:8081` para acceder al servicio.

**Reenvío de puertos dinámico (proxy SOCKS):** todo el tráfico pasar por el servidor remoto, esto puedo ser de utilidad con bloqueos por ISP o redes empresariales.
```bash
# ssh -D local_ip:local_port user@ip
ssh -D 127.0.0.1:9090 bender@192.168.0.10
```
Puede añadir la dirección proxy y puerto en cualquier programa que lo permita.
***
Password-less SSH login.
***
SSH client configuration.

El archivo `config` podremos configurar las credenciales para acceder a servidores, github o cualquier otro donde usemos llaves ssh. El archivo esta ubicado en `~/.ssh`, si no existe lo creamos.
```bash
touch ~/.ssh/config
```
Hacer legible y escribible solo para el usuario actual.
```bash
sudo chmod 600 ~/.ssh/config
```
Añadir un perfil al archivo de configuración, en este caso para acceder al servidor remoto `vim ~/.ssh/config`.
```bash
# server lab
Host my_lab # my_lab sera el nombre a usar para la conexión SSH
    HostName 192.168.0.10 # ip local o public
    User bender # usuario real del servidor remoto
    Port 1022 # no necesario si tiene el puerto por defecto (22)
    AddKeysToAgent yes # añade las llaves al agente ssh
    IdentitiesOnly yes
    IdentityFile ~/.ssh/my_lab # ubicación de la llave
```
Ahora para la conexión, en lugar de hacer un `ssh bender@192.168.10` basta con `ssh bender`

Si quieras añadir otro perfil; por ejemplo, para github.
```bash
# server lab
Host my_lab
    HostName 192.168.0.10
    User bender
    Port 1022
    AddKeysToAgent yes
    IdentitiesOnly yes
    IdentityFile ~/.ssh/my_lab

# github personal
Host github
    HostName github.com
    User taquero-programador
    AddKeysToAgent yes
    IdentitiesOnly yes
    IdentityFile ~/.ssh/github
```
Cuando hagas un `git clone  git@github.com:taquero-programador/LinuxChallenge.git` cambia github.com por github, que es el valor de tu primera línea en `Host github`; después de eso no hay nada más que hacer.

## Day 2
Navegación básica

Acceder al servidor y ejecutar comandos.
```bash
ssh bender

# saber la ubicación actual
pwd
# retorna
/home/bender

# listar los directorios y archivos de la ubicación actual
ls

# crear un par de archivos
touch test{1..3}.txt
ls
# retorna
test1.txt  test2.txt  test3.txt

# listar las diferentes opciones a usar con ls
ls --help

# formato largo
ls -l
# a or all, muestra todos los archivos y directorio, incluye los ocultos
ls -a
# -R lista de manera recursiva
ls -Ra

# es posible usarlo con otros directorios
ls ~/.ssh

# crear directorios
mkdir dir{1..3}
# crear archivos dentro de los directorios
touch dir{1..3}/test{a,b,c}

# moverse entre directorios
cd dir1
pwd
/home/bender/Documentos/dir1
cd /var/log
pwd

# directorio raíz
cd /
# retrovecer un nivel
cd ..

# usar -ltr l: formato largo, t: por fecha (primero los nuevos), (r): recursivo
ls -ltr

# colorear la salida
ls -lh --color=auto
```

#### PS1, PS1, PS3, PS4 Y PROMPT_COMMAND

**PS1:** mostrar el nombre de usuario, host y directorio de trabajo
```bash
export PS1="\u@\h \w> "
```
- \u - nombre de usuario.
- \h - nombre de host.
- \w - nombre completo del directorio actual.

**PS2:** aviso interactivo de continuación. Cambiar esto `>` por `continue->`
```bash
export PS2="continue->"
```

**PS3:** utilizada para "seleccionar" dentro del script shell
```sh
select i in mon tue wed exit
do
  case $i in
    mon) echo "Monday";;
    tue) echo "Tuesday";;
    wed) echo "Wednesday";;
    exit) exit;;
  esac
done
```
Añadir permisos de lectura y escritura `sudo chmod +x ps3.sh`.

**PS4:** utilizado por "set-x" para prefijar la salida del seguimiento
```sh
set -x
echo "PS4 demo script"
ls -l /etc/ | wc -l
du -sh ~
```

**PROMPT_COMMAND:** `export PROMPT_COMMAND="date +%k:%m:%S"`

## Day 3

Comprobar los permisos de `/etc/shadow` con `ls -l`.
```bash
# ver los permisos de archivo
irw-r----- 1 root shadow 1299 oct 31 02:51 /etc/shadow

# usar cat para mostrar el contenido del archivo
cat /etc/shadow # lo cual retorna Permiso denegado
# usar sudo
sudo cat /etc/shadow
# less: muestra página a página el contendio del archivo
sudo less /etc/shadow
# usar nano, aunque a estas alturas prefiero VIM
sudo vim /etc/shadow

# reiniciar el servidor con reboot
sudo reboot
# revisar que se encuentre activo con uptime
uptime # muestra la hora actual, tiempo de actividad, usuarios activos, etc

sudo -i
# salir con exit o logout
exit

# ver el archivo /var/log/auth.log, donde se lleva un registro de sudo
sudo less var/log/auth.log

# filtrar usando grep
sudo grep 'sudo' /var/log/auth.log

# cambiar el nombre del host con hostnamectl
sudo hostnamectl set-hostname debian-power

# trabajar con la zona horaria timedateclt
# listar todas las zonas horarias disponibles
timedateclt list-timezones
# cambiar
sudo timedateclt set-timezone America/Monterrey
```

## Day 4 - Instalación de software, exploración de la estructura de datos

Buscar el software a instalar.
```bash
apt search mc
```
Instalar.
```bash
sudo apt install mc -y
```
***
#### apt and apt-get
apt se introdujo por primera vez en Debian, el cual se introdujo para resolver algunos problemas de apt-get. En pocas palabras apt tiene muchas similitudes con apt-get, haciendolo más amigable y eficiente.
***
#### DNF and APT
APT | DNF
-- | --
trabaja con .deb | trabaja con .rpm
front-end para dpkg | front-end para RPM
actualización de repos manualmente | actualización de repos automáticamente
se introdujo en Debian | se introdujo en Fedora
en Debian, Ubuntu, etc. | RHEL, CentOS, Fedora, etc.
más rapido que dnf | lento
necesita un .deb para instalar | se puede instalar desde una url
instalación a un solo click | no disponible
***
#### Package managment APT
[Enlace APT](https://ubuntu.com/server/docs/package-management)
***
#### Sistema de directorios Linux
**`/` - El directorio root (raíz)**  
Todo en el sistema se encuentra en `/`. Podría pensar que es similar a `C:\` de Windows.

**`/bin` - Binarios de usuario esenciales**  
Contiene los binarios de usuario esenciales (programas) que deben estar presentes cuando el sistema se monta en modo usuario único. Las aplicaciones como Firefox se almacenan en `/usr/bin`, mientras que los programas y utilidades del sistema como shell se almacen en `/bin`. El directorio `/usr` puede almacenarse en otras partición.

**`/boot` - Archivos de arranque estaticos**  
Contiene los archivos necesarios para iniciar el sistema; por ejemplo, el cargador de inicio de GRUB y sus Kernels de Linux se almacena ahí. Los archivos de configuración se encuentran en `/etc`.

**`/cdrom` - Punto de monjate historico para CD-ROM**  
Es una ubicación temporal para los CD-ROM insertados en el sistema. La ubicación estándar de los medios temporales están en `/media`.

**`/dev` - Archivos de dispositivos**  
Linux exponse los dispositivos como archivos y el directorio `/dev` contiene varios archivos especiales que representán dispositivos. No son archivos, pero parecen archivos; por ejemplo, `/dev/sda` representa la primera unidad SATA del sistema.

`/dev/random` produce números aleatorios. `/dev/null` no produce ningún resultado.

**`/etc` - Archivos de configuración**  
Contiene archivos de configuración, que generalmente se pueden editar a mano con algún editor de textos. Tiene los archivos de configuración de todo el sistema, los archivos para el usuario se encuentran en el directorio de inicio.

**`/home` - Carpetas de inicio**  
Contiene una carpeta de inicio para cada usuario. Por ejemplo, `/home/bender`, cada usuario tiene permisos de escritura y para modificaciones más elevendas necesita acceso root.

**`/lib` - Bibliotecas compartidas esenciales**   
Contiene las bibliotecas que necesitan los binarios esenciales en las carpetas `/bin` y `/sbin`. Las Bibliotecas en la carpeta `/usr/bin` se encuentran en `/usr/lib`.

**`/lost+found` - Archivos recuperados**  
Si el sistema de archivos falla, se realiza una verificación del sistema de archivos en el próximo arranque. Todos los archivos dañados se encuentran en ese directorio, por lo que se puede intentar recuperar la mayor cantidad de datos posibles.

**`/media` - Medios extraibles**  
Contiene subdirectorios de los dispositivos de medios extraibles insertados en la computadora. Por ejemplo, al insertar un CD, se creará un directorio dentro de `/media`, desde ahí se puede acceder al contenido dentro de CD.

**`/mnt` - Punto de montaje temporales**  
Por ejemplo, si está montando una partición Windows para realizar alguna recuperación, puede montarla en `/mnt/windows`. Sin embargo puede montar el sistema de archivos en cualquier parte del sistema.

**`/opt` - Paquetes opcionales**  
Subdirectorio para paquetes de software opcionales. Es comúnmente usado para software propietario que no obedece la jerarquía estándar del sistema de archivos; por ejemplo, `/opt/application`.

**`proc` - Archivos de proceso y Kernel**  
Es similar a `/dev` porque no contiene archivos estándar. Contiene archivos especiales que representán información del sistema y del proceso.

**`/root` - Directorio de inicio root**  
Es el directorio de inicio para el usuario root. En lugar de estar ubicado en `/home/root` está en `/root`. Esto es distinto a `/`, que es el directorio raíz del sistema.

**`/run` - Archivos de estado de aplicación**  
Es bastane nuevo y brinda a las aplicaciones un lugar estándar para almacenar los archivos transitorios que requieran, como sockets e ID's de procesos. No se pueden almacenar en `/tmp` porque los archivos en ese directorio se pueden eliminar.

**`/sbin` - Binarios de adminstración de sistema**  
Es similar a `/bin`. Contiene binarios esenciales que generalmente están destinado a ser ejecutados por el usuario root para la administración del sistema.

**`/selinux` - Sistema de archivos virtuales SELinux**  
Sistema Linux para la seguridad (Fedora, Red Hat, etc.) contiene archivos especiales para selinux.

**`/srv` - Datos de servicio**  
Contiene "datos para los servicios proporcionados por el sistema". Un servidor Apache HTTP, probablemente almacenaría los archivos en `/srv`.

**`/tmp` - Archivos temporales**  
Estos archivos generalmente se eliminan al reiniciar el sistema y pueden eliminarse en cualquier otro momento usando algo como tmpwatch.

**`/usr` - Binarios de usuario y datos de solo lectura**  
Contiene aplicaciones y archivos utilizados por el usuario. Por ejemplo, las aplicaciones no esenciales se encuentran en `/usr/bin` en lugar de `/bin` y los binarios de administración del sistema no esenciales están en `/usr/sbin` en lugar de `/sbin`. Las bibliotecas para cada uno se encuentra en `/usr/lib`. Este directorio también contiene otros directorio; por ejemplo, archivos de la arquitectura, como los gráficos, se encuentran en `/usr/share`.

El directorio `/usr/local` es donde las aplicaciones compiladas localmente se instalan de forma predeterminada; esto evita que estropeen el resto del sistema.

**`/var` - Archivos de datos variables**  
Es la contrapartida grabable  de `/usr`, que debe ser de solo lectura. Los archivos de registro y todo lo demás que normalmente se escribiría en `/usr` durante el funcionamiento normal se escriben en el directorio `/var`.

## Day 5 - More or less

**less:** muestra página por página el contenido de un fichero.
```bash
sudo less /var/log/auth.log
```
Comandos básicos:
- `g`: se va al inicio del documento.
- `G`: al final del documento.
- `/`: para realizar busquedas, después se presiona `enter`.
- `n`: para el siguiente resultado.
- `N`: resultado anterior.
- `h`: muestra la ayuda.
- `less file1 file2`: abrir más de un archivo.
- `:e file1`: abre uno de los archivos con less.
- `:n`: ir al siguiente archivo.
- `:p`: ir al archivo anterior.

#### History
El comando `history` lista todos los comandos ejecutados en la terminal.
```bash
# listar todos los comandos ejecutados
history
```
Usando `!` junto a un número traera/ejecutara el comando del historial.
```bash
!20
```
Con la combinación `ctrl + r`, permite realizar una busqueda en el hisorial de comandos mientras se escibre. Con `!!` trae/ejecuta el último comando. `!sudo` ejecuta el último comando con `sudo`. `sudo !!` ejecuta el último comando usando permisos `sudo`.

Ver el historial del archivo `.bash_history` o `.zsh_history`.
```bash
less ~/.zsh_history
```
Usar nano o VIM para abrir un archivo.
```bash
vim ~/.zsh_history
```

#### Archivo y comandos de historial
Modificar el archivo `.bashrc` o `.zshrc` para ampliar el almacenamiento de historial. En `bashrc` basta con añadir:
```bash
HISTSIZE=10000000
SAVEHIST=10000000
```
Mientras que en `.zshrc`:
```bash
HISTFILE="$HOME/.zsh_history"
HISTSIZE=10000000
SAVEHIST=10000000
```
[Referencía](https://www.digitalocean.com/community/tutorials/how-to-use-bash-history-commands-and-expansions-on-a-linux-vps).

## Day 6 - VIM

Crear un archivo:
```bash
cp -v /etc/services testfile

# abrir un archivo
vim testfile
```
[VIM adventures](vim-adventures.com).

## Day 7 - El servidor y sus servicios

- Actualizar la lista de paquetes `sudo apt update`.
- Instalar apache `sudo apt install apache2`.
- Validar que el servicio esté arriba `localhost`, `192.168.0.10` or `curl -I localhost`.
- Intentar detener el servicio `susy stop apache2`.
- Abrir archivo de configuración `sudo vim /etc/apache2/apache2.conf`.
- Ver el archivo `sudo vim /var/log/apache2/access.log` y `sudo vim /var/log/apache2/error.log`.

#### Recursos
[HTTP](https://ubuntu.com/server/docs/web-servers-apache).

## Day 8 - grep y otros procesadores de texto

Ahora que el servidor ejecuta servicios, genera registros a medida que accede al servidor, y estos son archivos que se pueden analizar.

- Usar `cat` para mostrar todo el contenido de `access.log`, `sudo cat /var/log/apache2/access.log`.
- `tac` es similar a `cat`, pero la última línea en consola es la primera del archivo.
- `head` muestra solo las primeras líneas del archivo, con `-n` permite monstrar solo el número de líneas pasadas como argumento.
- `tail`es a la inversa de `head`, lo cual solo muestra las últimas líneas del archivo y también permite pasar el número de líneas a mostrar con `-n`. `-f` permite mantener el archivo abierto y recuperar los nuevos logs sobre la marcha.
- Usar `sudo cat /var/log/apache2/access.log | grep -i "auth"`.
- `wc -l file`.
- Usar `cut` con delimitador `-d`; campo `-f`: ejemplo, `sudo cat /var/log/apache2/access.log | grep -i "auth" | cut -f 10- -d " "`, campo 10 en adelante y el delimitador es " ".
- Redireccionar la salida a un archivo, `sudo cat /var/log/apache2/access.log | grep -i "root" > output.txt`.
- `cut -d":" -f5 /etc/pass`, retorna solo los nombre de usuario que están después del campo 5 que está delimitado por ":". `cut` corta y solo trae el valor requerido.
- Obtener solo las direcciones IP's del archivo `auth.log`, ejemplo, `sudo cat /var/log/auth.log | grep -o "[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}"`. Con `-o` solo retorna la concidencia exacta.
- Usar `sort | uniq`, sort ordena y uniq devuelve únicos.
- `-n` muestra el número de la línea dentro del archivo.

Searchs "linux sed tricks" and "awk one liners". [grep](https://ostechnix.com/the-grep-command-tutorial-with-examples-for-beginners/).

## Day 9 - Buceando en la red

Usar un par de comandos para ver los puertos abiertos en el servidor.

- `netstat` comprueba el estado de las interfaces. Con `netstat -l` lista los puertos que están escuchando.
- `ss` "estado de socket", es una utilidad estándar. reemplazando `netstat`, usar `ss -ltp`.
```bash
State     Recv-Q    Send-Q       Local Address:Port         Peer Address:Port    Process
LISTEN    0         16                 0.0.0.0:8200              0.0.0.0:*
LISTEN    0         128                0.0.0.0:10222             0.0.0.0:*
LISTEN    0         128              127.0.0.1:ipp               0.0.0.0:*
LISTEN    0         128                   [::]:10222                [::]:*
LISTEN    0         128                  [::1]:ipp                  [::]:*
```
- `nmap` permite escanear puertos, no viene de manera predeterminada `sudo apt install namp -y`. Ver los puertos abiertos en el servidor `nmap localhost`.
```bash
Starting Nmap 7.80 ( https://nmap.org ) at 2022-11-14 22:07 CST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00064s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 998 closed ports
PORT     STATE SERVICE
631/tcp  open  ipp
8200/tcp open  trivnet1

Nmap done: 1 IP address (1 host up) scanned in 0.38 seconds
```

#### Servidor de seguridad del anfritrion
Enumera la regas vigentes con `sudo iptable -L`.
```bash
# habilitar un servicio con ufw
sudo ufw allow ssh
# en mi caso es otro puerto
# luego
sudo ufw enable # después de cada cambio
```

#### Uso de puertos no estándar
Es recomendable cambiar los puertos de los servicos, por ejemplo, cambiar el puerto 22 de SSH por otro.

#### 12 comandos con ss
1. Listar todas las conexiones. Enumera todas las conexión independientemente del estado en que se encuentren.
```bash
ss
```
2. Listar los puertos de escucha y no escucha.
```bash
ss -a
```
3. Listar puertos de escucha.
```bash
ss -l
```
4. Listar todas las conexiones TCP.
```bash
ss -t
```
5. Conexiones TCP de escucha.
```bash
ss -lt
```
6. Listar todas las conexiones UDP.
```bash
ss -ua
```
7. Conexiones UDP de escucha.
```bash
ss -lu
```
8. Mostrar el ID de proceso (PID) en socket.
```bash
ss -p
```
9. Monstrar estadisticas de resumen.
```bash
ss -s
```
10. Mostrar conexiones IPv4 e IPv6.
```bash
# ipv4
ss -4
# ipv6
ss -6
```
11. Filtrar conexiones por número de puerto.
```bash
ss -at '( dport = :22 or sport = :22 )'
# or
ss -at '( sport = :ssh or sport = :ssh )'
```
12. El comando `man`.
```bash
man ss
```

#### UFW
UFW es una herramienta de cortafuegos que facilita la configuración con iptables.
```bash
# demonio
sudo systemctl status ufw
# listar puertos y ver el estatus
sudo ufw status

# listar la configuración de aplicaciones disponibles
sudo ufw app list
```

Habilitar y deshabilitar.
```bash
sudo ufw enable
# ver el estatus
sudo ufw status verbose
# deshabilitar
sudo ufw disable
```
Permitir y denegar (UFW)

La sintax básica es `sudo ufw allow/deny port/optional`.
```bash
# habilitar un puerto para tcp y udp
sudo ufw allow 52

# habilitar solo para tcp
sudo ufw allow 52/tcp
# or udp
sudo ufw allow 52/udp
```
Eliminar una regla existente.
```bash
# primero deshabilitar
sudo ufw deny 93/tcp
# eliminar
sudo ufw delete deny 93/tcp
```

Se puede permitir o denegar un servico con nombre, ya que ufw lee en `/etc/services`. Ejemplo, `sudo ufw allow https`.
```bash
Allow
# permitir una IP especifica
sudo ufw allow from 192.168.0.100

# por subnet
sudo ufw allow from 192.168.0.0/24

# especificar ip y puerto
sudo ufw allow from 192.168.0.100 to any port 22

# especificar ip, puerto y protocolo
sudo ufw allow from 192.168.0.10 to any port 22 proto tcp
```
Deny
```bash
# denegar por IP
sudo ufw deny from 192.168.0.100

# especificar ip y puerto
sudo ufw deny from 192.168.0.100 to any port 22
```

#### IPTables
[Source](https://linuxconfig.org/collection-of-basic-linux-firewall-iptables-rules).
#### Netstat
[Source](https://www.thegeekstuff.com/2010/03/netstat-command-examples/).

## Day 10 - Hacer que la computadora haga el trabajo por ti

#### CRON
Cada usuario tiene un conjunto de herramientas que puede listar con `crontal -l`.

También hay un cron para todo el sistema definido en `/etc/crontab`, echar un vistazo con `less`.

Ver el directorio `/etc/cron.daily`:
```bash
0anacron  apache2  apt-compat  dpkg  logrotate  man-db  popularity-contest
```
Cada directorio tiene scripts que son ejecutados por el archivo cron del sistema y se ejecutan en orden alfabético usando `run-parts`.

#### AT
Programador de tareas no repetitivas

#### Temporizador de sistema
[Enlace](https://wiki.archlinux.org/title/Systemd/Timers)

Systemd ahora incluido en casi todas las distribuciones Linux, también se puede usar para ejecutar tareas programadas en momentos especificos. Ver cuáles ya están configurados:
```bash
systemctl list-timers
```

#### Los temporizadores son archivos `.times`

#### 1. Unidades de temporizador
- **Temporizadores en tiempo real** (también conocidos como reloj de pared) se activan en un evento del calendario, de la misma manera que los cronjobs.
- **Temporizadores monotonicós** se activan después de un tiempo relativo a un punto de inicio de variable. Se detienen si la computadora se suspende o se apaga.

#### 2. Unidades de servicio
Parar cada archivo `.timer`, existe un archivo `.service` (ej, `foo.timer` y `foo.service`). El archivo `.timer` activa y controla a `.service`. El archivo `.service` no requiere `[Install]`. Si es necesario, se pude usar un nombre diferente para controlar el archivo usando Unit= en la seción [Timer].

#### 3. Administración
Se habilita y se inicia con `sudo systemctl` con el subfijo `.time`.
Notas:
- Listar todos incluido los inactivos `systemctl list-times --all`.
- Lo más probable es que el servicio este inactivo a menos que se esté ejecutando.
- Si un temporizador no está sincronizado, se puede eliminar `stamp-*` presente en `var/lib/systemd/timers` o `~/.local/share/systemd/`. Si se elimina, se reconstruira en el próximo inicio del temporizador.

#### 4. Ejemplos

#### Temporizador monotonicós
Un temporizador que se inicia 15 minutos después del arranque y nuevamente cada semana mientras el sistema esté funcionando.
```bash
/etc/systemd/system/foo.timer

[Unit]
Description=Run foo weekly and on boot

[Timer]
OnBootSec=15min
OnUnitActiveSec=1w

[Install]
WantedBy=timers.target

```

#### Temporizador en tiempo real
Temporizador que se inicia una vez a la semana (a las 00:00 del lunes). Cuando se activa, se activa el servicio de inmediato si se perdió la última hora de inicio (`Persistent=true`), por ejemplo, si el sistema estaba apagado.
```bash
/etc/systemd/system/foo.timer

[Unit]
Description=Run foo weekly

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
```
Cuando se requieran fechas y horas más especificas, el evento `OnCalendar` utiliza el siguiente formato.
```bash
DayOfWeek Year-Month-Day Hour:Minute:Second
```
Se puede usar un asterisco para especificar cualquier valor y se pueden usar comas para enumerar los valores posibles. Dos valores separados por `..` indican un rango continuo.

Ejempo, el servico se ejecuta los primeros cuatro días de cada mes a las 12:00pm, pero solo si es lunes o martes.
```bash
OnCalendar=Mon,Tue *-*-01..04 12:00:00
```
Ejecutar el servicio el primer sabado de cada mes:
```bash
OnCalendar=Sat *-*-1..7 18:00:00
```
Al usar DayOfWeek se debe especificar al menos un día de la semana. Para ejecutar todos los días a las 4 am:
```bash
OnCalendar=*-*-* 4:00:00
```
Ejecutar en diferentes momentos, más de una vez. Por ejemplo, de lunes a viernes a las 22:30 y otro a las 20:00 en fines de semana:
```bash
OnCalendar=Mon..Fri 22:30
OnCalendar=Sat,Sun 20:00
```
Consejos:
- `OnCalendar` se pude probar usando `sudo systemd-analyze calendar "Mon *-*-* 13:00:00"`.
- Existe la opción de `faketime`.

#### 5. Unidades de temporizador transitorios
Se puede usar `sytemd-run` para crear un `.timer` sin tener un archivo de servicio. Ejemplo, usar touch después de 30 segundos:
```bash
systemd-run --on-active=30 /bin/touch /tmp/foo
```
Usar un archivo `.service` que no tiene un `.timer`:
```bash
systemd-run --on-active="12h 30m" --unit someunit.service
```

#### 6. Systemd como reemplazo de cron
Cron es el administrador de servicios más conocido, pero systemd puede ser una alternativa

#### Beneficios
- Los trabajos se pueden iniciar fácilmente, independiente de sus temporizadores.
- Cada trabajo puede configurarse para ejecutarse en un entorno específico.
- Se pueden adjuntar a `cgroups`.
- Se pueden configurar para que dependan de otros systemd.
- Se registran en systemd para facilitar la depuración.

#### Enlaces adicionales
- [Sytemd en lugar de cron](https://www.maketecheasier.com/use-systemd-timers-as-cron-replacement/)
- [IBM cron](https://developer.ibm.com/tutorials/l-lpic1-107-2/)
- [IBM tutorial](https://developer.ibm.com/tutorials/au-usingcron/)

## Day 11 - Encontrando cosas

#### locate
Localizar el archivo `access.log`:
```bash
# instalar
sudo apt install mlocate -y

locate access.log
```
Puede retornar un error o no localizar el archivo, usar `sudo updatedb`. Resultado:
```bash
/var/log/nginx/access.log
/var/log/nginx/access.log.1
```

#### find
El comando buscara a través de una estructura de directorio en busca de archivos que coincidan con algunos criterios, por ejemplo, nombre, tamaño, o cuando se actualizó por última vez.
```bash
sudo find /var -name acceder.log
sudo find /home -mtime -3
```
El primero busca archivos con el nombre `access.log`, el segundo busca en el directorio `/home` archivos con una última fecha de actualización de 3 días.

Filtrar los errores al ejecutar `find` sin permisos root:
```bash
find /var -name access.log 2>&1 | grep -vi "Permission denied"
```

#### grep-r
Permite una busqueda recursiva dentro de un directorio y se le puede añadir el patron a buscar
```bash
grep -R -i "PermitRootLogin" /etc/*
```
Para archivos comprimidos se puede usar `zless` o `zgrep`.

#### which
Permite saber la ruta desde donde se ejecuta determinado comando

Ver de donde viene el binario de `nano`:
```bash
/usr/bin/vim
```

#### 26 comandos con find
Sintax básica
```bash
find <path> {dir or file} <option> <action or result>
```
1. Encontrar todos los directorio o archivos del directorio actual:
```bash
# directorios
find . -type d

# archivos
find . -type f
```
2. Listar los archivos de un directorio:
```bash
# listar directorio y archivos
find Downloads/

# solo archivos
find Downloads/ -type d

# directorios
find Downloads/ -type f
```
3. Encontrar archivo con nombre en un directorio:
```bash
find Documentos/ -type f -name main.rs

# buscar por tipo de archivo
find . -type f -name "*.rs"
```
4. Encontrar archivos en múltiples directorios:
```bash
find dir1/ dir2/ -type f -name "*.md"
```
5. Encontrar archivos ingorando mayúsculas y minúsculas:
```bash
find dir1/  -type f -iname readme.md
```
6. Encontrar los archivos que no coincidan con lo ingresado:
```bash
find Música/ -type f -not -name "*.flac"
```
7. Encontrando archivos con múltiples condiciones:
```bash
# encuentra archivo .opus y .mp3
find Música/ -type f -regex ".*\.\(mp3\|opus\)$"
```
8. Encuentra archivos usando la condición `OR`:
```bash
find Música/ -type f -name "*.gz" -o -type f -name "*.csv"
```
9. Archivos basados en sus permisos:
```bash
find . -type f -perm 0777

# encontrar los ejecutables
find . -type f -perm /a+x
```
10. Encuentra los archivos ocultos:
```bash
find Documentos/git -type f -name ".*"
```
11. Localizar los archivo SGID:
```bash
sudo find / -perm /g=s
```
12. Archivos SUID:
```bash
sudo find / -perm /u=s
```
13. Archivos legibles que no tiene permiso de ejecución:
```bash
find $HOME -perm -a+r \! -perm /a+x
```
14. Buscar varios tipos de archivos:
```bash
find $HOME -type f,d,l
```
15. Encuentra los archivos pertenecientes a determinado usuario:
```bash
sudo find /home/bender -user bender -type f -name "*.sh"
```
16. Archivos propiedad de un grupo:
```bash
sudo find / -group adm
```
17. Encontrar archivo según su tamaño:
```bash
find Documentos/ -size 21M

# superior
find Documentos/ -size +50M

# menor
find Documentos/ -size -12M

# rango
find Documentos/ -size +30M -size -35M
```
18. No desciende directorios en otro sistema de archivos:
```bash
find / -xdev -size +100M 2>/dev/null
```
19. Encutra archivos modificados hace N días:
```bash
find / -mtime 3
```
20. Archivos accedidos N días:
```bash
find / -atime 3
```
21. Encuentra archivos y directorios vacios:
```bash
# archivos
find / -type f -empty
# or
find / -type f -size 0

# directorios
find / -type d -empty
```
22. Buscar y eliminar archivos:
```bash
find $HOME -type f -name "*.mp3" -delete
```
23. Encuentra archivos más grandes y más pequeños:
```bash
find $HOME -type f -exec ls -s {} \; | sort -n -r | head -3
```
24. Enviar el resultado a un archivo:
```bash
find ~/Música/ -size +65M -exec ls -sh {} \; > output.txt
```
25. Buscar archivos y cambiar permisos:
```bash
find $HOME -type f -perm 777 -exec chmod 644 {} \;
```
26. Buscar texto en archivos:
```bash
find Dir/ -type f -name "*.md" -exec grep -i "command" {} \;
```

## Day 12 - Transferencia de archivos
Mover archivos entre un sistema y servidor

#### Protocolos
Existe una amplia forma de que Linux comparta archivos, como:
- SMB: intercambio de archivos de Microsoft, usado en sistemas Windows para red local.
- AFP: compartir archivos de Apple, útil en red local.
- WebDAV: para compartir sobre protocolos web (http y https si está disponible).
- FTP: protocolo tradicional de uso compartido en internet.
- scp: soporte simple para copiar archivos.
- rsync: copia de archivos rápida y eficiente.
- SFTP: acceso y copia de archivos sobre SSH.

## Day 13 - Permisos
Los archivos en un sistema Linux siempre tiene "permisos" asociados, controlando quién tiene acceso y qué tipo de acceso. 

#### Propiedades
Todos los archivos están etiquetados con el nombre de usuario y el grupo que los posee, ejemplo:
```bash
-rw------- 	1 steve  staff  	4478979  6 Feb  2011 private.txt
-rw-rw-r-- 	1 steve  staff  	4478979  6 Feb  2011 press.txt
-rwxr-xr-x 	1 steve  staff  	4478979  6 Feb  2011 upload.bin
```
Entonces los archivos son propiedad de "steve" y del grupo "staff".

#### Permisos
Para la lista del ejemplo anterior:
- pritave.txt: Steve tiene permisos de "rw" (lectura y escritura), pero ningún otro tiene permisos.
- press.txt: tanto Steve como cualquier otro usuario tiene permiso de lectura y escritura.
- unpload.bin: Steve puede leer, escribir y los demás solo leer, además todos pueden ejecutar el archivo.

Crear un archivo de prueba `touch test.txt && echo "this a test" > test.txt`.
- `u`: para usuario.
- `g`: para el grupo.
- `o`: otros.
- `a`: todas las anteriores.
- `-`: para eliminar un permiso
- `+`: agrega permisos.
- `=`: funciona en ambos casos.

Eliminar los permisos de escritura para el archivo:
```bash
chmod a-w test.txt
```
Eliminar permisos de lectura:
```bash
chmod a-r test.txt
```
Añadir permisos de lectura y escritura en grupos:
```bash
chmod g+rw test.txt
```
Cambiar el grupo a un directorio o archivo (solo puede haber un grupo como propietario):
```bash
sudo chgrp new_group dir/
```
Quitar todos los permisos y dejarlo en solo lectura:
```bash
chmod u=r test.txt
```
Quitar todos los permisos:
```bash
chmod u=
```

#### Grupos
En la mayoría de los sistemas Linux modernos, se creá un grupo para cada usuario. Sin embargo se pueden añadir nuevos grupos.

Para ver los grupos a los que eres miembro `groups`, para ver los de otro usuario `groups bender`.

Añadir un usuario a un grupo existente:
```bash
sudo usermod -a -G name_group user
```

#### UMASK
Se utiliza para controlar la máscara del modo de creación de archivos, que determina el valor inicial de los bits de permisos para los archivos recién creados.

Mostrar el valor actual de la máscara:
```bash
umask
```
Referencía:
Octal | Binario | Significado
-- | -- | --
0 | 000 | sin permisos
1 | 001 | solo ejecución
2 | 010 | solo escritura
3 | 011 | escritura y ejecución
4 | 100 | solo lectura
5 | 101 | lectura y ejecución
6 | 110 | lectura y escritura
7 | 111 | lectura, escritura y ejecución

#### ACL
Los ACL son un segundo nivel de permisos, que puede anular los estándares ugo/rwx. Cuando se usan correctamente, pueden otorgar una mayor granularidad al configurar el acceso a un archivo o directorio.

Para poder utilizarlo hay que confirmar con el siguiente comando `tune2fs -l`.

[Más info](https://linuxconfig.org/how-to-manage-acls-on-linux) & [IBM](https://www.redhat.com/sysadmin/linux-access-control-lists).

#### CHMOD
[info](http://catcode.com/teachmod/).

## Day 14 - Usuarios y grupos

#### Agregar usuario(s)
Comando para agregar el nuevo usuario:
```bash
sudo adduser katulu
```
El comando puede funcionar diferente en cada sistema, si no solicita una contraseña, crearla con:
```bash
sudo passwd katulu
```
Para que el usuario tenga permisos `root` hay que agregarlo a `sudoers`:
```bash
sudo visudo
# añadir
username ALL=(ALL:ALL) PASSWD: ALL

# or
sudo usermod -a -G sudo username
```

## Day 15 - Repositorios

#### Dónde se encuentra toda esa configuración?
Administración de paquetes `apt` es usado en distribuciones como Debian y Ubuntu.

La configuración se realiza en archivos de configuración en `/etc/apt`, y para ver de dónde proviene los paquetes que instala usar `less` en `/etc/apt/sources.list`, donde aparecera varias URL a un repositorio de una versión especifica.
```bash
deb http://deb.debian.org/debian bullseye main contrib non-free
```

#### Repositorios adicionales
Existe una gran cantidad de software en los repositorios "estándar", a menudo hay paquetes que no están disponibles, generalmente por estas dos razones:
- Estabilidad: CentOS se basa en RHEL, que se centra firmemente en la estabilidad de grandes instalaciones de servidores comerciales, por lo que los juegos y muchos paquetes menores no están disponibles.
- ideología: Ubuntu y Debian tienen una fuerte ética de "libertad de software", lo que significa que ciertos paquetes pueden no estar disponibles.

#### habilitar repositorios adicionales
Verificación rápida para saber cuántos paquetes tiene disponible para instalar:
```bash
apt-cache dump | grep "Package" | wc -l
```
A veces hay paquetes adicionales disponibles si habilita esos repositorios. La mayoría de las distribuciones Linux tiene un concepto similar, pero en Ubuntu, a menudo los repositorios "Universe" y "Multiverse" están deshabilitados. 
- Para habilitar el Repositorio "Multiverse", siga la siguiente liga: [wiki](https://help.ubuntu.com/community/Repositories/CommandLine).
Después actualice su caché local de aplicaciones disponibles:
```bash
sudo apt update
```
Ahora podra instalar un paquete:
```bash
sudo apt install netperf
```

#### Extensión - PPA Ubuntu
Ubuntu también permite a los usuarios registrar una cuenta y configurar el software en un archivo de paquete personal (PPA); por lo general, estos son configurados por desarrolladores entusiastas y le permite instalar el último software de "vanguardia".

Por ejemplo, `neofetch`, si quisiera una versión anterior podría hacerlo instalando un PPA del desarrollador:
```bash
sudo add-apt-repository ppa:dawidd0811/neofetch
```
Actualizar `sudo apt update`.

Instalar `sudo apt install neofetch`.

Cuando haga un `upgrade`, probablemente se actualice a la versión más reciente, pues los desarrolladores simpre están actualizando.

#### Recursos
- [Comparación de administración de paquetes](https://wiki.archlinux.org/title/Pacman/Rosetta).
- [Introducción yum](https://fedoranews.org/tchung/howto/2003-11-09-yum-intro.shtml).
- [Gestión de paquetes APT](https://fedoranews.org/tchung/howto/2003-11-09-yum-intro.shtml).
- [Qué es software libre](https://www.debian.org/intro/free).

## Day 16 - Archivar y comprimir
Como administrador de sistemas, debe poder trabajar con confianza con archivos comprimidos. En particular, dos de las responasabilidades clave; instalación de software nuevo y la gestión de copias de seguridad a menudo requieren esto.

#### Crear archivos
En otros sistemas operativos, las aplicaciones como WinZip y pkzip se han utilizado durante mucho tiempo para reunir una serie de archivos y carpetas en un archivo comprimido, con la extensión `.zip`. Linux adopta un enfoque ligeramente diferente, con la "reunión" de archivos y carpetas en un paso y en otro la compresión.

Entonces, podría crear una "instantánea" de los archivos actuales:
- `-c`: creá un archivo comprimido.
- `-x`: extrae el contenido.
- `-v`: `verbose`, muestra los archivos comprimidos durante el proceso.
- `-z`: genera un archivo `gzip`.
- `-f`: permite especificar un nombre de archivo de salida.
- `-t`: para ver el contenido de un tar.
- `-j`: para crear archivos `bzip2`.
- `--wildcards`: extraer grupos por tipo de archivo:
- `--exclude`: excluye archivos y directorios al crear tar.
- `--delete`: elimina archivos y directorios de un tar.
```bash
tar cvzf output.tar.gz dir/
```

#### Comandos TAR
1. Crear un archivo `.tar`:
```bash
tar -cvf output.tar dir/
```
2. Crear un `tar.gz` o `.tgz`:
```bash
tar -cvzf output.tar.gz dir/
# or
tar -cvzf output.tgz dir/
```
3. Crear un `tar.bz2`: la función `bz2` comprime y crear un archivo de almacenamiento de menos tamaño que `gzip`. La compresión con `bz2` toma más tiempo para comprimir y descomprimir a diferencia de `gzip`.

Para crear un archivo altamente comprimido se usa `-j`, (tar.bz2 y tbz es similar a tb2).
```bash
# bz2
tar -cvfj output.tar.bz2 dir/
# tbz
tar -cvzj output.tar.tbz dir/
# tb2
tar -cvzj output.tar.tb2 dir/
```
4. Descomprimir un archivo tar, usar `x`, por defecto se descomprimen en el directorio actual, para cambiar la ubiación usar `-C`.
```bash
# archivo tar
tar -xvf inout.tar

# gzip
tar -xvzf input.tar.gz
# descomprimir en otro directorio
tar -xvzf input.tar.gz -C destino

# tar.bz2
tar -xvf input.tar.bz2
```
5. Listar el contenido de un archivo tar:
```bash
tar -tf input.tar
```
6. Extrar un archivo único de un tar:
```bash
# tar
tar -xvf input.tar file_name.txt
# or
tar --extract --file=input.tar file_name.txt

# gzip
tar -zxvf input.tar.gz file.txt
# or
tar --extract --file=input.tar.gz file.txt

# bz2
tar -jxvf input.tar.b2 file.txt
# or
tar --extract --file=input.tar.bz2 file.txt
```
7. Extraer más de un archivo:
```bash
# tar
tar xvf input.tar file1.txt file4.jpg

# gzip
tar xvzf input.tar.gz file2.txt doc.docx

# bz2
tar xvfj input.tar.bz2 file3.txt file.xlsx
```
8. Extrar un grupo de archivos por extensión:
```bash
# tar
tar xvf input.tar --wildcards "*.rs" --wildcards "*.md"

# gzip
tar xvzf input.tar.gz --wildcards "*.py"

# bz2
tar xvfj input.tar.bz2 --wildcards "*.md"
```
9. Añadir archivos o directorios a un archivo tar:
```bash
# tar
tar -rvf input.tar input.txt
```
Los comprimidos `tar.gz` y `bz2` no permiten añadir archivos.

10. Excluir archivos o directorios al crear un tar:
```bash
# file
tar cvzf output.tar.gz --exclude="file.txt" --exclude="*.cpp" dir/
# dir
tar cvzf output.tar.gz --exclude="dir/dir3" dir/
# excluir multiple tipo de archivo
tar cvzf output.tar.gz --exclude="*.jpg" dir/
```
11. Eliminar archivos o directorios de un tar (no funciona en `gzip` y `bz2`):
```bash
# file
tar --delete -f input.tar filename.txt
# dir
tar --delete -f input.tar dir/dir_to_delete
```

## Day 17 - Construir desde la fuente
Instalar paquetes desde la fuente

#### Lo escencial
Los proyectos normalmente proporcionan sus aplicaciones como "archivos fuente", escritos en `C`, `C++` u otro lenguaje. Vamos a extraer dicha fuente, no servira de nada hasta que no se compile en un "ejecutable". La primera herramientas es `build-essential`.
```bash
sudo apt install build-essential
```

#### Obtener la fuente
Probar que ya se tiene `nmpa` haciendo uso de `namp -V` para ver la versión instalada. A continuación `which nmap` para ver dónde está almacenado el ejecutable.
```bash
/usr/bin/nmap
```

Ahora en la ir a la página del proyecto para los desarrolladores [nmap.org](http://nmap.org/) y tomar la última versión de vanguardia. Ir a la sección descargas, luego "distribución de código de fuente" y seleccionar "tarball de lanzamiento", usar la URL para el archivo `bz2` or `gzip`.
```txt
https://nmap.org/dist/nmap-7.93.tar.bz2
```
Descargar con `wget`:
```bash
wget -c --show-progress https://nmap.org/dist/nmap-7.93.tar.bz2
```
- `-c`: permite reanudar la descarga si se interrumpe.
- `--show-progress`: muestras el progreso de la descarga.

Descomprimir el archivo tar:
```bash
tar xvfj https://nmap.org/dist/nmap-7.93.tar.bz2
```
Por convención, los archivos de origen suelen incluir en su directorio raíz una serie de archivos de texto en mayúsculas, como: README e INSTALL. 

Ver el archivo INSTALL:
```bash
Ideally, you should be able to just type:

./configure
make
make install

For far more in-depth compilation, installation, and removal notes,
read the Nmap Install Guide at https://nmap.org/book/install.html.
```
Esto es lo que hace cada uno de los pasos:
- `./configure`: es un script que verifica un servidor (para ver si está basado en ARM o INTEL, 32 o 64 bits, qué compilador tiene, etc). Si el proceso realiza preguntas, seleccionar las opciones predeterminadas y los mensaje de ADVERTENCIA no son para preocuparse, es probable que todo salga bien.
- `make`: compila el software, normalmente llamando al compilador GNU `gcc`. Esto puede generar una gran cantidad de texto de aspecto aterrador y tomar uno o dos minutos, o hasta horas para paquetes como LibreOffice.
- `make install`: este paso toma los archivos compilados e instala esa documentación más en su sistema, en algunos casos, configurar servicios y tareas programadas. El proceso se instala en todo el sistema para todos los usuarios, por lo que requiere permisos `root` y ejecutar: `sudo make install`.

Este último paso probablemente habrá sobrescrito `nmap`, pero la nueva instalación tendra la última versión.

En general, `/bin` es para partes clave del sistema operativo, `/usr/bin` para utilidades menos críticas y `/usr/local/bin` para software que ha elegido instalar manualmente. Cuando escribe un comando, buscará en cada uno de los directorios proporcionados en su variable de entorno `PATH`. 

Con `locate` puede ubicar este nuevo archivo, pero debido a que este nuevo archivo se acaba de agragar, necesitar actualizar el indice de los archivos:
```bash
sudo updatedb
```
Luego buscar en el índice:
```bash
locate bin/nmap
```
Esto debería encontrar su antiguo como copias de `nmap`.

Ahora intente ejecutar cada una de ellas, ejemplo:
```bash
/usr/bin/nmap -V

/usr/local/bin/nmap -V
```
NOTA: Debido a que esta instalación se hizo fuera del manejador de paquetes APT, este binario no recibira actualizaciones.

#### Qué es Linux From Scratch (LFS)
Linux From Scratch es un proyecto que te proporciona instrucciones paso a paso para contruir tu propio sistema Linux personalizado desde la fuente.

- **Por qué un sistema LSF**  
LSF le enseña a la gente cómo funciona internamente un sistema Linux. Construir LSF te enseña todo lo que hace que Linux funcione, cómo funcionan las cosas. Y lo más importante, cómo personalizarlo según tus propios gustos y necesidades.

- **Construir LSF produce un sistema Linux muy compacto**  
Cuando instala una distribución regular, a menudo termina instalando muchos programas que probablemente nunca usarías.

- **LSF es extremadamente flexible**

- **LSF le ofrece mayor seguridad**

#### Qué es Gentoo
Gentoo es un sistema operativo gratuito basado en Linux que puede optimizarse y personalizarse automáticamente para casi cualquier aplicación o necesidad.

Gracias a una tecnología llamada **Portage**, Gentoo puede convertirse en un servidor seguro ideal, estación de trabajo de desarrollo, computadora de escritorio profesional, sistema de juegos, o casi cualquier cosa.

#### Enlaces
- [La magia detrás de configure, make y make install](https://thoughtbot.com/blog/the-magic-behind-configure-make-make-install)
- [Cómo recontruir paquetes Debian](https://raphaelhertzog.com/2010/12/15/howto-to-rebuild-debian-packages/)
- [Compilar cosas en Ubuntu de forma fácil](https://help.ubuntu.com/community/CompilingEasyHowTo)

## Day 18 - Rotación de registro
Cuando administra un servidor, los registros son su mejor amigo, pero los problemas de espacio en disco pueden ser un problema, las aplicaciones en Linux son generalmente buenas para llevar un registro, pero deben de ser controladas.

Los `logrotate` mantienen su registro bajo control. Con esto, puede elegir cuántos días de registro desea conservar; dividirlos en archivos manejables; comprimirlos para ahorrar espacio, o incluso mantenerlos en un servidor separado.

#### ¿Están rotando sus registros?
