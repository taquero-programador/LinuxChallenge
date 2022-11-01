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

## Day 1
Task:
- [x] Conectar e iniciar sesión en el servidor.
- [x] Ejecutar comandos simples para ver el estado del servidor.
- [x] Cambiar la contraseña

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

Si quieras añadir otro perfil, por ejemplo para github.
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
