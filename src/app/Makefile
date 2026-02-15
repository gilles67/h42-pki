all:
	apt-get update -y
	apt-get upgrade -y
	apt-get install -y --no-install-recommends opensc opensc-pkcs11 python3 python3-pip python3-venv g++ python3-dev pcscd libxml2 libicu74 libccid
	apt-get -y autoremovenan	
	apt-get clean
	python3 -m venv /app
	. /app/bin/activate && pip install PyKCS11
	echo ". /app/bin/activate" >> /root/.bashrc 
	echo "export PYKCS11LIB=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so" >> /root/.bashrc 
