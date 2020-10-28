#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo "[-] This script must be run as root." 
    exit 0
else
	if [ -f /etc/redhat-release ]; then
		yum update
		yum install -y yum-utils python36-setuptools postgresql postgresql-contrib python3-psycopg2 wget unzip git openssl
		easy_install-3.6 pip
	fi

	if [ -f /etc/lsb-release ]; then
		apt update
		apt install -y python3 python3-pip python3-psycopg2 postgresql postgresql-contrib build-essential wget unzip git openssl
		service postgresql start
	fi

	if [ -e /etc/os-release ]; then
		. /etc/os-release
	else
		. /usr/lib/os-release
	fi

	if [[ "$ID_LIKE" = *"suse"* ]]; then
		zypper update
		zypper install -n python3 python3-pip python3-psycopg2 postgresql postgresql-contrib wget unzip git openssl
		zypper install -n -t pattern devel_basis
		systemctl start postgresql
	fi

	LINE=`printf %"$COLUMNS"s |tr " " "-"`

	echo "[+] Creating protected directory."
	mkdir ../lib/static/protected
	mkdir ../lib/static/protected/output
	mkdir ../lib/static/protected/screenshots
	echo "[+] Changing owner of protected directory to user $SUDO_USER."
	chown $SUDO_USER:$SUDO_USER ../lib/static/protected
	chown $SUDO_USER:$SUDO_USER ../lib/static/protected/output
	chown $SUDO_USER:$SUDO_USER ../lib/static/protected/screenshots
	echo "[+] Obtaining Chrome Driver."
	mkdir chrome_dev
	cd ./chrome_dev
    LatestVersions=`curl -X GET "http://chromedriver.chromium.org/downloads" | grep -oP "(https\:\/\/chromedriver\.storage\.googleapis\.com\/index\.html\?path\=[0-9\.]+\/)" | sort -u | tail -n 3`
    for lv in ${LatestVersions[$i]}
    do
        if [[ $lv == *"$GoogleChromeVersion"* ]]
        then
            ShortLV=`echo "$lv" | awk -F "=" '{print $2}' | awk -F "/" '{print $1}'`
            wget "https://chromedriver.storage.googleapis.com/$ShortLV/chromedriver_linux64.zip"
            if [ -f "chromedriver_linux64.zip" ]
            then
                echo "[+] Unzipping chromedriver_linux64.zip."
                unzip chromedriver_linux64.zip
                if [ -f "chromedriver" ]
                then
                    echo "[+] Moving the unzipped chromedriver binary to the /usr/bin directory."
                    mv ./chromedriver /usr/bin/chromedriver
                else
                    echo "[-] Failed to locate the chromedriver file."
                    exit 0
                fi
            else
                echo "[-] Failed to locate the chromedriver_linux64.zip file."
                exit 0
            fi
            echo "[i] Cleaning up."
            rm chromedriver_linux64.zip
        fi
    done
	cd ..

	echo "[+] Setting up python3 dependencies."
	echo $LINE
	git clone https://github.com/bryand1/python-pinterest-api
	cd ./python-pinterest-api
	python3 setup.py install
	cd ..
	pip3 uninstall requests
	pip3 install -r python_requirements.txt
	MODULELOC=`python3 -m site --user-site`
	mv site-packages/defectdojo.py $MODULELOC/defectdojo.py
	echo $LINE
	echo "[+] Dependency installation complete. Configuring."
	echo $LINE

	DATABASE="scrummage"
	USER="scrummage"
	PASSWD=`tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1`
	FLASK_ENVIRONMENT="development"
	echo "export FLASK_ENV=$FLASK_ENVIRONMENT" >> ~/.bashrc
	echo "[+] Environment variable added to startup."

	sudo -u postgres psql -c "CREATE DATABASE $DATABASE;"
	sudo -u postgres psql -c "CREATE USER $USER WITH ENCRYPTED PASSWORD '$PASSWD';"
	sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DATABASE TO $USER;"
	echo "[+] Database has been created with the following details, please retain these for later."
	PRINT_DATABASE="Database: $DATABASE"
	PRINT_USER="Username: $USER"
	PRINT_PASSWD="Password: $PASSWD"
	echo "Database Details:"
	echo $PRINT_DATABASE
	echo $PRINT_USER
	echo $PRINT_PASSWD
	echo $LINE
	echo "[+] Creating Tables using Create_Tables.py"
	echo "{" > db.json
	echo "    \"postgresql\": {" >> db.json
	echo "        \"host\": \"127.0.0.1\"," >> db.json
	echo "        \"port\": 5432," >> db.json
	echo "        \"database\": \"$DATABASE\"," >> db.json
	echo "        \"user\": \"$USER\"," >> db.json
	echo "        \"password\": \"$PASSWD\"" >> db.json
	echo "    }" >> db.json
	echo "}" >> db.json
	chown $SUDO_USER:$SUDO_USER db.json
	echo $LINE
	python3 Create_Tables.py
	echo $LINE
	API_SECRET=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-64} | head -n 1`
	echo "[+] Generating JSON configuration for the web application."
	printf "{\n    \"craigslist\": {\n        \"city\": \"Sydney\"\n    },\n    \"csv\": {\n        \"use-csv\": false\n    },\n    \"docx-report\": {\n        \"use-docx\": false\n    },\n    \"defectdojo\": {\n        \"api_key\": \"\",\n        \"host\": \"https://host.com\",\n        \"user\": \"admin\",\n        \"engagement-id\": 1,\n        \"product-id\": 1,\n        \"test-id\": 1,\n        \"user-id\": 1\n    },\n    \"ebay\": {\n        \"access_key\": \"\"\n    },\n    \"email\": {\n        \"smtp_server\": \"\",\n        \"smtp_port\": 25,\n        \"from_address\": \"\",\n        \"from_password\": \"\",\n        \"to_address\": \"\"\n    },\n    \"flickr\": {\n        \"api_key\": \"\",\n        \"api_secret\": \"\"\n    },\n    \"elasticsearch\": {\n        \"service\": \"http://\",\n        \"host\": \"\",\n        \"port\": 9200\n    },\n    \"general\": {\n        \"location\": \"au\"\n    },\n    \"google\": {\n        \"cx\": \"\",\n        \"application_name\": \"\",\n        \"application_version\": \"v1\",\n        \"developer_key\": \"\"\n    },\n    \"google-chrome\": {\n        \"application-path\": \"/usr/bin/google-chrome\",\n        \"chromedriver-path\": \"/usr/bin/chromedriver\"\n    },\n    \"haveibeenpwned\": {\n        \"api_key\": \"\"\n    },\n    \"hunter\": {\n        \"api_key\": \"\"\n    },\n    \"ipstack\": {\n        \"api_key\": \"\"\n    },\n    \"JIRA\": {\n        \"project_key\": \"\",\n        \"address\": \"\",\n        \"username\": \"\",\n        \"password\": \"\",\n        \"ticket_type\": \"\"\n    },\n    \"naver\": {\n        \"client_id\": \"\",\n        \"client_secret\": \"\"\n    },\n    \"pinterest\": {\n        \"oauth_token\": \"\"\n    },\n    \"postgresql\": {\n        \"host\": \"127.0.0.1\",\n        \"port\": 5432,\n        \"database\": \"$DATABASE\",\n        \"user\": \"$USER\",\n        \"password\": \"$PASSWD\"\n    },\n    \"reddit\": {\n        \"client_id\": \"\",\n        \"client_secret\": \"\",\n        \"user_agent\": \"\",\n        \"username\": \"\",\n        \"password\": \"\",\n        \"subreddits\": \"all\"\n    },\n    \"rtir\": {\n        \"service\": \"http\",\n        \"host\": \"\",\n        \"port\": 80,\n        \"user\": \"\",\n        \"password\": \"\",\n        \"authenticator\": \"\"\n    },\n    \"scumblr\": {\n        \"host\": \"\",\n        \"port\": 5432,\n        \"database\": \"\",\n        \"user\": \"\",\n        \"password\": \"\"\n    },\n    \"shodan\": {\n        \"api_key\": \"\"\n    },\n    \"slack\": {\n        \"token\": \"\",\n        \"channel\": \"\"\n    },\n    \"sslmate\": {\n        \"search_subdomain\": false\n    },\n    \"twitter\": {\n        \"CONSUMER_KEY\": \"\",\n        \"CONSUMER_SECRET\": \"\",\n        \"ACCESS_KEY\": \"\",\n        \"ACCESS_SECRET\": \"\"\n    },\n    \"ukbusiness\": {\n        \"api_key\": \"\"\n    },\n    \"vkontakte\": {\n        \"access_token\": \"\"\n    },\n    \"vulners\": {\n        \"api_key\": \"\"\n    },\n    \"web-app\": {\n        \"debug\": false,\n        \"host\": \"127.0.0.1\",\n        \"port\": 5000,\n        \"certificate-file\": \"../certs/certificate.crt\",\n        \"key-file\": \"../certs/privateKey.key\",\n        \"api-secret\": \"$API_SECRET\",\n        \"api-validity-minutes\": 1440,\n        \"api-max-calls\": 10,\n        \"api-period-in-seconds\": 60\n    },\n    \"web-scraping\": {\n        \"risk-level\": 2\n    },\n    \"yandex\": {\n        \"username\": \"\",\n        \"api_key\": \"\"\n    },\n    \"youtube\": {\n        \"developer_key\": \"\",\n        \"application_name\": \"\",\n        \"application_version\": \"v3\",\n        \"location\": \"\",\n        \"location_radius\": \"\"\n    }\n}" > ../lib/plugins/common/config/config.json
	chown $SUDO_USER:$SUDO_USER ../lib/plugins/common/config/config.json
	ADMIN_USER="admin"
	ADMIN_PASSWD=`tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1`

	echo "[+] Creating Admin user using Create_User.py"
	echo $LINE
	python3 Create_User.py -u $ADMIN_USER -p $ADMIN_PASSWD -a True -b False
	echo $LINE
	echo "[+] Admin user created, user details:"
	ADMIN_USER="Username: $ADMIN_USER"
	ADMIN_PASSWD="Password: $ADMIN_PASSWD"
	echo $ADMIN_USER
	echo $ADMIN_PASSWD
	echo $LINE
	echo "[+] Script finished."
fi