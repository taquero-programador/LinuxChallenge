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
Es mejor usar `adduser`, es mas intuitivo, creá usario, directorio y solicita una contraseña.
```bash
sudo adduser bender
```
Añadir usuario a los grupos _sudo_ y _adm_.
```bash
sudo usermod -a -G adm,sudo bender
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

## Day 4
Instalación de software, exploración de la estructura de datos

Buscar el software a instalar.
```bash
apt search mc
```
Instalar.
```bash
sudo apt install mc -y
```

#### apt and apt-get
apt se introdujo por primera vez en Debian, el cual se introdujo para resolver algunos problemas de apt-get. En pocas palabras apt tiene muchas similitudes con apt-get, haciendolo más amigable y eficiente.

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

#### Package managment APT
[Enlace APT](https://ubuntu.com/server/docs/package-management)

#### Sistema de directorios Linux
#### `/` - El directorio root (raíz)
Todo en el sistema se encuentra en `/`. Podría pensar que es similar a `C:\` de Windows.

### `/bin` - Binarios de usuario esenciales
Contiene los binarios 

## Day 5
