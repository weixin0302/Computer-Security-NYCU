all:
	openssl genrsa -out myCA.key 4096
	openssl req -new -x509 -days 1826 -key myCA.key -out myCA.crt
	chmod +x mitm_attack.py
	chmod +x pharm_attack.py
	mv mitm_attack.py mitm_attack
	mv pharm_attack.py pharm_attack

clean:
	mv mitm_attack mitm_attack.py
	mv pharm_attack pharm_attack.py
	sudo rm -rf ca.key ca.crt sslsplit connections.log