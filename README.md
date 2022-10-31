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
Generar llaves para acceder sin contraseña.

En el equipo local **no el remoto**.  
Primero validar si existe tu directorio `.ssh`, que es donde se guardan las llaves publicas y privadas.
```bash
ls ~/.ssh
# si no existe, la podemos crear
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
Durane este proceso se solicitara la contraseña por única ocasión.

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
**Local tunnel:** permite traer un servicio del servidor remoto y ejecutarlo en el equipo de manera local `ssh -L localport:127.0.0.1:remoteport user@ip`.
```bash
ssh -L 8000:127.0.0.1:8000 bender@192.168.0.10
```
Esto accede al servidor remoto, ahora si ejecutas algún servicio que use el puerto `8000`, en el navegador de tu equipo local podras ingresar a `127.0.0.1:8000` y ver la pagina o proyecto.

Esto es útil con base de datos, ya que por defecto está deshabilitado el acceso remoto. Ahora podrías usar el usario, contraseña y la url de la base de datos `127.0.0.1:3036` en MySQL o DBeaver.

**Remote tunnel:** el servidor remoto permite exponer un puerto del equipo local al exterior, ejemplo: equipo local `A` tiene bloqueo por ISP y quiere exponer una página web que usa el puerto `8080`, equipo remoto `B` tiene IP publica y acceso al exterior, entonces tomara el puero `8080` y lo expondra en `ip_public:8081`.
```bash
# ssh -R remoteport:ip_local:localport server@ip_public
ssh -R 8081:192.168.0.100:8080 bender@192.168.0.10
```
Para que este paso surta efecto, se debe modificar el archivo /etc/ssh/sshd_config.
```bash
# línea a editar
GatewayPorts yes
```
Ahora desde el navegador podras hacer un http://ip_public:8081.
