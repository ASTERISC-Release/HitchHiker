## Real-World Applications

### 1. Nginx Setup

```bash
apt install nginx
```

The configuration file is located at `/etc/nginx/nginx.conf` (based on adeb's root). 
After the configuration, nginx will listen to the port `8090`.

Default logs:
- access log: `/var/log/nginx/access.log`
- error log: `/var/log/nginx/error.log`

Set log-level (edit `nginx.conf`):

```bash
access_log /var/log/nginx/access.log;
error_log /var/log/nginx/error.log [level];
```
Level (only for error_log): Debug | Info | Notice | Warn | Error | 

After the current configuration, the Nginx files are under:
* `/root/web-source` based on adeb's root.
* `/data/androdeb/debian/root/web-source` based on the absolute path.

Request:

```bash
nginx               # start nginx
nginx -s reload     # if nginx is already start and you want to reload the config file
nginx -s stop       # stop nginx
# test connection
curl localhost:8090/index.html
curl localhost:8090/data/file-4kb --output -        # output to stdout
```


### 2. Httpd Setup

```bash
apt install apache2
```

After installation, `apache2` (a.k.a. `httpd`) is installed at `/usr/sbin/apache2`.
The configuration file is located at `/etc/apach2/` (based on adeb's root).

After the configuration, apache2 is listening on the port `8180` (see `/etc/apache2/ports.conf`),

Since we're under the chroot environment in the JUNO board, we should manually manage the 
apache2 services:

```bash
source /etc/apache2/envvars
apache2 -k stop | start | restart
```

### 3. Redis Setup

```bash
apt install redis
```

The configuration file is located at `/etc/redis/redis.conf` (based on adeb's root).
After the configuration, redis will listen to the default port `6379` with loglevel `verbose`.

Default log: `/var/log/redis/redis-server.log`.

Startup:

```bash
service redis-server start / restart
service redis-server stop
# test connection
redis-cli
> exit
```

### 4. Memcached Setup

```bash
apt install memcached libmemcached-tools
```

The configuration file is located at `/etc/memcached.conf` (based on adeb's root).
After the configuration, memcached will listen to the default port `11211` at verbose `-vv`.

Default log: `/var/log/memcached.log`.

Startup:

```bash
memcached -d -u root
(recommend) service memcached start/stop
# test connection
telnet 127.0.0.1 11211
```

### 5. SQLite Setup

```bash
apt install sqlite3
```

After the installation, the `sqlite` database can be directly interacted by `sqlite3 ...`. 
Note that SQLite is a [zero-configuration database, and there is no server process](https://www.sqlite.org/zeroconf.html).

### 6. MySQL Setup

```bash
apt install default-mysql-server
vim /etc/mysql/mariadb.conf.d/50-server.conf
```

The configuration file of `mysql-server` (a.k.a. mysqld) is under `/etc/mysql/mariadb.conf.d/50-server.conf`.
After the configuration, mysql-server will listen to the default port `3306` with only error.log.

Now let's config the priviledge and create a test database:
```bash
$mysql
MariaDB> CREATE USER 'mysql'@'%' IDENTIFIED BY '';
MariaDB> GRANT SELECT ON *.* TO 'mysql'@'%';
MariaDB> GRANT ALL PRIVILEGES ON *.* TO 'mysql'@'%' WITH GRANT OPTION;
MariaDB> FLUSH PRIVILEGES;
MariaDB> CREATE DATABASE testdb;
^C
```

We can connect to this mysql server on the client now:
```bash
(client)$ mysql -h <server-ip> -P 3306 -u mysql
```

### 7. GNU Octave Setup

```bash
apt install octave
```

Then you can simply type: `octave --no-gui` to yield an interactive shell with octave.

### 8. Firefox Setup

```bash
apt install firefox-esr
apt install xvfb
```

Now you can run firefox with `headless` mode:

```
firefox --headless https:www.baidu.com --screenshot ./output
```

Now, let's configure the application log settings based on `MOZ_LOG`.
```bash
# verbose (debug)
export MOZ_LOG=timestamp,rotate:200,nsHttp:5,cache2:5,nsSocketTransport:5,nsHostResolver:5
# info
export MOZ_LOG=timestamp,rotate:200,nsHttp:3,cache2:3,nsSocketTransport:3,nsHostResolver:3
export MOZ_LOG_FILE=/var/log/firefox/log.txt
```

To set up the virtual display (which is necessary for speedometer benchmark) on this 
server computer, simply type:
```bash
# create a virtual screen
Xvfb :7 -screen 0 1024x1024x16 &
export DISPLAY=:7
# setup x11 vnc
x11vnc -listen 0.0.0.0 -rfbport 5900 -noipv6 -passwd password -display :7
# after that, run firefox
firefox &
```

Now, on your clinet machine, you can just VNCViewer to connect to this firefox virtual display.

### 9. 7zip

```bash
apt install p7zip-full
```       

## Benchmarks

### 1. ab (ApacheBenchmark) Setup

```bash
apt install apache2-utils
```

**Use ab benchmark:**

```bash
ab -n <num_reqs> -c <concurrency> <addr>:<port><path>
# to test nginx
ab -n 100000 -c 100 localhost:8090/data/file-4kb
```


### 2. memtier_benchmark setup

First install the required packages.

```bash
apt install build-essential autoconf automake libpcre3-dev libevent-dev pkg-config zlib1g-dev libssl-dev
```

Now clone and install the deb package from its official repo.
```bash
wget https://github.com/RedisLabs/memtier_benchmark/releases/download/1.4.0/memtier-benchmark_1.4.0.bionic_arm64.deb
dpkg -i memtier-benchmark_1.4.0.bionic_arm64.deb
```

**Use memtier_benchmark:**

```bash
memtier_benchmark -s <ip> -p <port> -c <connect_numbers> -n <num_reqs> -t <threads> -d <data_size> --ratio <SET:GET> -P <protocal>
# to test for memcached 
# memtier_benchmark -s 127.0.0.1 -p 11211 -c 20 -n 10000 -t 2 -d 32 --key-pattern S:R --ratio 1:9 -P memcache_text --hide-histogram
# to test for redis
memtier_benchmark -s 127.0.0.1 -p 6379 -c 20 -n 10000 -t 2 -d 32 --key-pattern S:R --ratio 1:9 -P redis --hide-histogram
```

references: 
* https://stackoverflow.com/questions/35219535/using-memtier-benchmark-every-key-is-missed
* 

### 3. phoronix-test-suite

Install the phoronix-test-suite:

```bash
apt install php-cli php-curl php-xml
dpkg -i phoronix-test-suite_x.x.x_all.deb
```

Install the `pts/sqlite-speedtest`:

```bash
phoronix-test-suite install pts/sqlite-speedtest
phoronix-test-suite install system/octave-benchmark
```

### 4. LMBench

Install the lmbench:

```bash
apt install lmbench
```

After the installation, lmbench utils are located at `/usr/lib/lmbench`:
* lat_syscall
* bw_file_rd
* ...

### 5. Sysbench

```bash
wget -qO - https://packagecloud.io/install/repositories/akopytov/sysbench/script.deb.sh | bash
apt install sysbench
```

## Setup USB 10/100/1000 LAN: Client machine <-> Juno

The following are general steps for directly connecting a development board (like Raspberry Pi, Arduino, etc.) via Ethernet cable. However, please note that specific steps might differ slightly depending on the exact model of your development board and device.

Here we take the Macbook Pro client machine and the Juno development board server as an example.

Hardware connection: Use an Ethernet cable to connect your Mac computer and the development board. One end goes into your Mac, and the other into your development board.

Configure Network Sharing:

* Open "System Preferences" on your Mac.

* Select "Sharing".

* In the left column, select "Internet Sharing".

* In the "Share your connection from" drop-down menu on the right, choose your internet connection method (like Wi-Fi).

* In the "To computers using" list, choose "Ethernet" or "Thunderbolt Ethernet", depending on the specific port type of your Mac.

* Check the box next to "Internet Sharing" on the left. Then in the pop-up dialog box, select "Start".

SSH Connection to the Development Board: 

If your development board supports SSH connection, you can connect to it using the following steps. If you're unsure of your development board's IP address, you will need to refer to your development board's documentation or run certain commands on your development board to get its IP address.

* Open the "Terminal" application.

* Type ssh username@ipaddress. Here, the username is your development board's username, and ipaddress is your development board's IP address. For example, if your username is "pi", and your development board's IP address is "192.168.2.2", you should type ssh pi@192.168.2.2.

* Hit the return key, then enter the password. The password will not be displayed as you type it in, just hit return once you've finished entering it.
