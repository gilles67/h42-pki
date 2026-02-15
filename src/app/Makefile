all:
	apt-get update -y
	apt-get upgrade -y
	apt-get install -y --no-install-recommends opensc opensc-pkcs11 python3 python3-pip python3-venv
	apt-get -y autoremove
	apt-get clean
	python3 -m venv /app 
	source /app/bin/activate
	pip install PyKCS11
