#!/bin/bash
# This script is used for create virtual hosts on CentOs.
# Created by alexnogard from http://alexnogard.com
# Improved by mattmezza from http://you.canmakethat.com
# Feel free to modify it
#   PARAMETERS
#
# $usr          - User
# $dir          - directory of web files
# $servn        - webserver address without www.
# $cname        - cname of webserver
# EXAMPLE
# Web directory = /var/www/
# ServerName    = domain.com
# cname            = devel
#
#
# Check if you execute the script as root user
#
# This will check if directory already exist then create it with path : /directory/you/choose/domain.com
# Set the ownership, permissions and create a test index.php file
# Create a vhost file domain in your /etc/httpd/conf.d/ directory.
# And add the new vhost to the hosts.
#
#
if [ "$(whoami)" != 'root' ]; then
echo "You have to execute this script as root user"
exit 1;
fi
read -p "Enter the server name your want (without www) : " servn
read -p "Enter a CNAME (e.g. :www or dev for dev.website.com) : " cname
read -p "Enter the path of directory you wanna use (e.g. : /var/www/, dont forget the /): " dir
read -p "Enter the user you wanna use (e.g. : apache) : " usr
read -p "Enter the listened IP for the server (e.g. : *): " listen


#servn=${1:-DEFAULTVALUE}  
#cname=${1:-DEFAULTVALUE}

adduser $cname_$servn
usermod -s /sbin/nologin $cname_$servn

#
# Create root directory
#

if ! mkdir -p $dir$cname_$servn; then
echo "Web directory already Exist !"
else
echo "Web directory created with success !"
fi

semanage fcontext -a -t httpd_sys_content_t '$dir$cname_$servn(/.*)?'

#
# Create html directory
#

if ! mkdir -p $dir$cname_$servn/html; then
echo "Web html directory already Exist !"
else
echo "Web html directory created with success !"
fi

chown -R $cname_$servn:$usr $dir$cname_$servn/html
chmod -R '750' $dir$cname_$servn/html
chmod g+s $dir$cname_$servn/html
semanage fcontext -a -t httpd_sys_content_t '$dir$cname_$servn(/.*)?'


#
# Create application directory
#

if ! mkdir -p $dir$cname_$servn/app; then
echo "Web App directory already Exist !"
else
echo "Web App directory created with success !"
fi

chown -R $cname_$servn:$usr $dir$cname_$servn/app
chmod -R '750' $dir$cname_$servn/app
chmod g+s $dir$cname_$servn/app
semanage fcontext -a -t httpd_sys_content_t '$dir$cname_$servn/app(/.*)?'


#
# Create data directory
#

if ! mkdir -p $dir$cname_$servn/data; then
echo "Web Data directory already Exist !"
else
echo "Web Data directory created with success !"
fi

chown -R $cname_$servn:$usr $dir$cname_$servn/data
chmod -R '770' $dir$cname_$servn/data
chmod g+s $dir$cname_$servn/data
semanage fcontext -a -t httpd_sys_rw_content_t '$dir$cname_$servn/data(/.*)?'

#
# Create log directory
#

mkdir -p /var/log/httpd/$cname_$servn/
chown -R $usr:$cname_$servn /var/log/httpd/$cname_$servn/
chmod -R '750' /var/log/httpd/$cname_$servn/
chmod g+s /var/log/httpd/$cname_$servn/
semanage fcontext -a -t httpd_sys_rw_content_t '/var/log/httpd/$cname_$servn(/.*)?'

#
# Create index.html page
#

echo  "<html>
<head>
<title>First $cname_$servn </title>
</head>
<body>
$cname_$servn
</body>
</html> " > $dir$cname_$servn/html/index.html

#
# Create index.php page
#

echo "<?php echo '<h1>$cname $servn</h1>'; ?>" > $dir$cname_$servn/html/index.php

#
# Create apache virtual domain config file
#

alias=$cname.$servn
if [[ "${cname}" == "" ]]; then
alias=$servn
fi

echo "#### $cname $servn
<VirtualHost $listen:80>
ServerName $servn
ServerAlias $alias
DocumentRoot $dir$cname_$servn/html/
ErrorLog logs/$cname_$servn/error_log
CustomLog logs/$cname_$servn/access_log combined

<Directory $dir$cname_$servn>
Options Indexes FollowSymLinks MultiViews
ServerTokens Prod 
ServerSignature Off
AllowOverride All
Order allow,deny
Allow from all
#Require all granted
# RewriteEngine On
# RewriteCond %{REMOTE_ADDR} !^123\.456\.789\.000
# RewriteCond %{DOCUMENT_ROOT}/maintenance.html -f
# RewriteCond %{DOCUMENT_ROOT}/maintenance.enable -f
# RewriteCond %{SCRIPT_FILENAME} !maintenance.html
# RewriteRule ^.*$ /maintenance.html [R=503,L]
# ErrorDocument 503 /maintenance.html
# Header Set Cache-Control "max-age=0, no-store"
# RewriteCond %{HTTPS} !on
# RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}
</Directory>
</VirtualHost>" > /etc/httpd/conf.d/$cname_$servn.conf

if ! echo -e /etc/httpd/conf.d/$cname_$servn.conf; then
echo "Virtual host wasn't created !"
else
echo "Virtual host created !"
fi

#
# Create apache ssl virtual domain config file
#

echo "Would you like me to create ssl virtual host [y/n]? "
read q
if [[ "${q}" == "yes" ]] || [[ "${q}" == "y" ]]; then
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout  /etc/pki/tls/private/$cname_$servn.key -out /etc/pki/tls/certs/$cname_$servn.crt
if ! echo -e /etc/pki/tls/private/$cname_$servn.key; then
echo "Certificate key wasn't created !"
else
echo "Certificate key created !"
fi
if ! echo -e /etc/pki/tls/certs/$cname_$servn.crt; then
echo "Certificate wasn't created !"
else
echo "Certificate created !"
fi

echo "#### ssl $cname $servn
<VirtualHost $listen:443>
SSLEngine on
SSLCertificateFile /etc/pki/tls/certs/$cname_$servn.crt
SSLCertificateKeyFile /etc/pki/tls/private/$cname_$servn.key
SSLCACertificateFile  /etc/pki/tls/certs/ca-bundle.crt
Header always set Strict-Transport-Security "max-age=63072000; includeSubdomains;"
Header always set X-Frame-Options DENY
#SSLCompression off
SSLProtocol All -SSLv2 -SSLv3
SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
#SSLCipherSuite EECDH+ECDSA+AESGCM:EECDH+aRSA+AESGCM:ECDH+AES256:DH+AES256:EECDH+ECDSA+SHA384:EECDH+ECDSA+SHA256:EECDH+aRSA+SHA384:EECDH+aRSA+SHA256:EECDH:EDH+aRSA:!RC4:!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS;

ServerName $servn
ServerAlias $alias
DocumentRoot $dir$cname_$servn/html
ErrorLog logs/$cname_$servn/ssl.error_log
CustomLog logs/$cname_$servn/ssl.access_log combined

#<Location /server-status>
#    SetHandler server-status
#    Order deny,allow
#    Deny from all
#    Allow from localhost
#</Location>

# RewriteEngine On
# RewriteCond %{REMOTE_ADDR} !^123\.456\.789\.000
# RewriteCond %{DOCUMENT_ROOT}/maintenance.html -f
# RewriteCond %{DOCUMENT_ROOT}/maintenance.enable -f
# RewriteCond %{SCRIPT_FILENAME} !maintenance.html
# RewriteRule ^.*$ /maintenance.html [R=503,L]
# ErrorDocument 503 /maintenance.html
# Header Set Cache-Control "max-age=0, no-store"

<Directory $dir$cname_$servn>
Options Indexes FollowSymLinks MultiViews
ServerTokens Prod 
ServerSignature Off
AllowOverride All
Order allow,deny
Allow from all
#Satisfy Any
</Directory>
</VirtualHost>" > /etc/httpd/conf.d/ssl.$cname_$servn.conf
if ! echo -e /etc/httpd/conf.d/ssl.$cname_$servn.conf; then
echo "SSL Virtual host wasn't created !"
else
echo "SSL Virtual host created !"
fi
fi

echo "127.0.0.1 $servn" >> /etc/hosts
if [ "$alias" != "$servn" ]; then
echo "127.0.0.1 $alias" >> /etc/hosts
fi
echo "Testing configuration"
service httpd configtest
echo "Would you like me to restart the server [y/n]? "
read q
if [[ "${q}" == "yes" ]] || [[ "${q}" == "y" ]]; then
service httpd restart
fi

echo "Would you like me create ssh and sftp jailed systen account [y/n]? "
read q
if [[ "${q}" == "yes" ]] || [[ "${q}" == "y" ]]; then
	
	JAIL_ROOT=/home/jails/$cname_$servn 
	mkdir -p  $JAIL_ROOT
	chown root:root $JAIL_ROOT

	# TODO: ajustar mejor
	jk_init -v -j $JAIL_ROOT basicshell editors extendedshell netutils ssh sftp scp
	
	mkdir -p $JAIL_ROOT/var/log/httpd/$cname_$servn $JAIL_ROOT/var/www/$cname_$servn

	echo "/var/log/httpd/$cname_$servn $JAIL_ROOT/var/log/httpd/$cname_$servn        none    bind" >> /etc/fstab
	echo "$dir$cname_$servn $JAIL_ROOT/var/www/$cname_$servn        none    bind" >> /etc/fstab

	jk_jailuser -s /bin/bash -m -j $JAIL_ROOT $cname_$servn
	semanage fcontext -a -t usr_t "$JAIL_ROOT/home/$cname_$servn.ssh(/.*)?"
	NEW_PASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
	echo "$NEW_PASS" | passwd "$cname_$servn" --stdin

	#
	# Directorio home 
	#

	#mkdir $JAIL_ROOT/home/$cname_$servn
	#chown $cname_$servn $JAIL_ROOT/home/$cname_$servn

	#
	# Directorio tmp
	#

	mkdir -p  $JAIL_ROOT/tmp 
	chmod a+rwx $JAIL_ROOT/tmp

	#
	# Directorio de logs del usuario
	#

	mkdir -p  /var/log/$cname_$servn  $JAIL_ROOT/var/log/$cname_$servn
	chown  root:$cname_$servn /var/log/$cname_$servn
	chmod 0770 /var/log/$cname_$servn

    	#semanage fcontext -a -t httpd_sys_rw_content_t '/var/lib/simplesamlphp/log(/.*)?'

	echo "/var/log/$cname_$servn $JAIL_ROOT/var/log/$cname_$servn        none    bind" >> /etc/fstab

	echo "	/var/log/$cname_$servn/*.log /var/log/$cname_$servn/*/*.log {
	    missingok
	    notifempty
	    size 20M
	    rotate 4
            compress
	}" > /etc/logrotate.d/$cname_$servn

	# 	mkdir -p  $JAIL_ROOT/tmp /var/log/$cname_$servn  
	
	#
	# Cron
	# 

	mkdir -p $JAIL_ROOT/etc/cron.frequently $JAIL_ROOT/etc/cron.hourly $JAIL_ROOT/etc/cron.daily $JAIL_ROOT/etc/cron.monthly $JAIL_ROOT/etc/cron.yearly
	chown  root:$cname_$servn $JAIL_ROOT/etc/cron.*
	chmod 0770 $JAIL_ROOT/etc/cron.*
echo "
# Run cron: [daily]
#!/bin/bash
SHELL='/usr/sbin/jk_chrootsh'
#SHELL=/bin/bash
#PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=aulasvirtuales.uhu.es
HOME=$JAIL_ROOT/home/$cname_$servn

*/5 * * * *  $cname_$servn run-parts /etc/cron.frequently
01  * * * *  $cname_$servn run-parts /etc/cron.hourly
02  0 * * *  $cname_$servn run-parts /etc/cron.daily
0   0 * * 0  $cname_$servn run-parts /etc/cron.weekly
0   0 1 * *  $cname_$servn run-parts /etc/cron.monthly
0   0 1 1 *  $cname_$servn run-parts /etc/cron.yearly
" >> /etc/cron.d/$cname_$servn

	jk_cp $JAIL_ROOT /usr/bin/run-parts
fi

echo "======================================"
echo "All works done! You should be able to see your website at http://$servn"
echo ""
echo "Share the love! <3"
echo "======================================"
echo ""
echo "Wanna contribute to improve this script? Found a bug? https://gist.github.com/mattmezza/2e326ba2f1352a4b42b8"
