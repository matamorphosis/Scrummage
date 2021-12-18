#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo "[-] This script must be run as root." 
    exit 0
else
    if [ -f /etc/redhat-release ]; then
        yum update
        yum install -y yum-utils python36-setuptools postgresql postgresql-contrib python3-psycopg2 wget unzip git openssl
        wget https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm
        yum install ./google-chrome-stable_current_*.rpm
        easy_install-3.6 pip
    fi

    if [ -e /etc/os-release ]; then
        . /etc/os-release
    else
        . /usr/lib/os-release
    fi

    if [ -f /etc/lsb-release ] || [ -f /etc/os-release ] || [ -f /usr/lib/os-release ]; then
        if [[ "$ID_LIKE" = *"suse"* ]]; then
            echo "[i] This installer does not currently support the installation of Google Chrome on SUSE systems. To enable screenshot functionality, please manually install Google Chrome on this system."
            zypper update
            zypper install -n python3 python3-pip python3-psycopg2 postgresql postgresql-contrib wget unzip git openssl
            zypper install -n -t pattern devel_basis
            systemctl start postgresql
        else
            apt update
            apt install -y python3 python3-pip python3-psycopg2 postgresql postgresql-contrib build-essential wget unzip git openssl
            service postgresql start
            wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
            apt install ./google-chrome-stable_current_amd64.deb -y
        fi
    fi

    LINE=`printf %"$COLUMNS"s |tr " " "-"`

    echo "[+] Creating protected directory."
    mkdir ../app/static/protected
    mkdir ../app/static/protected/output
    mkdir ../app/static/protected/screenshots
    echo "[+] Changing owner of protected directory to user $SUDO_USER."
    chown $SUDO_USER:$SUDO_USER ../app/static/protected
    chown $SUDO_USER:$SUDO_USER ../app/static/protected/output
    chown $SUDO_USER:$SUDO_USER ../app/static/protected/screenshots
    chmod -R 770 ../app/static/protected
    echo "[+] Obtaining Chrome Driver."
    mkdir chrome_dev
    cd ./chrome_dev
    LatestVersions=`curl -X GET "https://chromedriver.chromium.org/downloads" | grep -oP "(https\:\/\/chromedriver\.storage\.googleapis\.com\/index\.html\?path\=[0-9\.]+\/)" | sort -u | tail -n 3`
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
    python3 ./setup.py install
    cd ..
    pip3 uninstall requests
    pip3 install -r ./support_files/python_requirements.txt
    MODULELOC=`python3 -m site --user-site`
    mv ./support_files/site-packages/defectdojo.py $MODULELOC/defectdojo.py
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
    echo "{" > ./support_files/db.json
    echo "    \"postgresql\": {" >> ./support_files/db.json
    echo "        \"host\": \"127.0.0.1\"," >> ./support_files/db.json
    echo "        \"port\": 5432," >> ./support_files/db.json
    echo "        \"database\": \"$DATABASE\"," >> ./support_files/db.json
    echo "        \"user\": \"$USER\"," >> ./support_files/db.json
    echo "        \"password\": \"$PASSWD\"" >> ./support_files/db.json
    echo "    }" >> ./support_files/db.json
    echo "}" >> ./support_files/db.json
    chown $SUDO_USER:$SUDO_USER ./support_files/db.json
    chmod 770 ./support_files/db.json
    echo $LINE
    pushd support_files
    python3 ./Create_Tables.py
    popd
    echo $LINE
    PRIVATE_KEY="../certs/privateKey.key"
    CERTIFICATE_CRT="../certs/certificate.crt"
    API_SECRET=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-64} | head -n 1`
    echo "[+] Generating JSON configuration for the web application."
    printf "{\n  \"inputs\": {\n    \"bitcoinabuse\": {\n      \"api_key\": \"\"\n    },\n    \"craigslist\": {\n      \"city\": \"\"\n    },\n    \"ebay\": {\n      \"access_key\": \"\"\n    },\n    \"emailrep\": {\n      \"api_key\": \"\"\n    },\n    \"flickr\": {\n      \"api_key\": \"\",\n      \"api_secret\": \"\"\n    },\n    \"general\": {\n      \"location\": \"au\"\n    },\n    \"github\": {\n      \"username\": \"\",\n      \"token\": \"\"\n    },\n    \"google\": {\n      \"cx\": \"\",\n      \"application_name\": \"\",\n      \"application_version\": \"\",\n      \"developer_key\": \"\"\n    },\n    \"greynoisesearch\": {\n      \"api_key\": \"\"\n    },\n    \"haveibeenpwned\": {\n      \"api_key\": \"\"\n    },\n    \"hunter\": {\n      \"api_key\": \"\"\n    },\n    \"hybridanalysis\": {\n      \"api_key\": \"\"\n    },\n    \"intelligencex\": {\n      \"api_key\": \"\"\n    },\n    \"ipstack\": {\n      \"api_key\": \"\"\n    },\n    \"leaklookup\": {\n      \"api_key\": \"\"\n    },\n    \"nameapi\": {\n      \"api_key\": \"\"\n    },\n    \"naver\": {\n      \"client_id\": \"\",\n      \"client_secret\": \"\"\n    },\n    \"ok\": {\n      \"application_id\": \"\",\n      \"application_key\": \"\",\n      \"application_secret\": \"\",\n      \"access_token\": \"\",\n      \"session_secret\": \"\"\n    },\n    \"pinterest\": {\n      \"oauth_token\": \"\"\n    },\n    \"pulsedive\": {\n      \"api_key\": \"\"\n    },\n    \"reddit\": {\n      \"client_id\": \"\",\n      \"client_secret\": \"\",\n      \"user_agent\": \"\",\n      \"username\": \"\",\n      \"password\": \"\",\n      \"subreddits\": \"all\"\n    },\n    \"shodan\": {\n      \"api_key\": \"\"\n    },\n    \"sslmate\": {\n      \"search_subdomain\": true\n    },\n    \"tumblr\": {\n      \"consumer_key\": \"\",\n      \"consumer_secret\": \"\",\n      \"oauth_token\": \"\",\n      \"oauth_secret\": \"\"\n    },\n    \"twitter\": {\n      \"consumer_key\": \"\",\n      \"consumer_secret\": \"\",\n      \"access_key\": \"\",\n      \"access_secret\": \"\"\n    },\n    \"ukbusiness\": {\n      \"api_key\": \"\"\n    },\n    \"urlscan\": {\n      \"api_key\": \"\"\n    },\n    \"vkontakte\": {\n      \"access_token\": \"\"\n    },\n    \"virustotal\": {\n      \"api_key\": \"\"\n    },\n    \"vulners\": {\n      \"api_key\": \"\"\n    },\n    \"whatcms\": {\n      \"api_key\": \"\"\n    },\n    \"yandex\": {\n      \"username\": \"\",\n      \"api_key\": \"\"\n    },\n    \"youtube\": {\n      \"developer_key\": \"\",\n      \"application_name\": \"youtube\",\n      \"application_version\": \"v3\"\n    }\n  },\n  \"outputs\": {\n    \"csv\": {\n      \"use_csv\": false\n    },\n    \"docx_report\": {\n      \"use_docx\": false\n    },\n    \"defectdojo\": {\n      \"ssl\": false,\n      \"api_key\": \"\",\n      \"host\": \"host.com\",\n      \"user\": \"admin\",\n      \"engagement_id\": 1,\n      \"product_id\": 1,\n      \"test_id\": 1,\n      \"user_id\": 1\n    },\n    \"elasticsearch\": {\n      \"ssl\": false,\n      \"host\": \"\",\n      \"port\": 9200,\n      \"index\": \"Scrummage\",\n      \"use_timestamp\": true\n    },\n    \"email\": {\n      \"smtp_server\": \"\",\n      \"smtp_port\": 587,\n      \"from_address\": \"\",\n      \"from_password\": \"\",\n      \"to_address\": \"\"\n    },\n    \"jira\": {\n      \"project_key\": \"\",\n      \"address\": \"\",\n      \"username\": \"\",\n      \"password\": \"\",\n      \"ticket_type\": \"\"\n    },\n    \"postgresql\": {\n      \"host\": \"127.0.0.1\",\n      \"port\": 5432,\n      \"database\": \"$DATABASE\",\n      \"user\": \"$USER\",\n      \"password\": \"$PASSWD\"\n    },\n    \"rtir\": {\n      \"ssl\": false,\n      \"host\": \"\",\n      \"port\": 80,\n      \"user\": \"\",\n      \"password\": \"\",\n      \"authenticator\": \"\"\n    },\n    \"scumblr\": {\n      \"host\": \"\",\n      \"port\": 5432,\n      \"database\": \"\",\n      \"user\": \"\",\n      \"password\": \"\"\n    },\n    \"slack\": {\n      \"token\": \"\",\n      \"channel\": \"\"\n    }\n  },\n  \"core\": {\n    \"google_chrome\": {\n      \"application_path\": \"/usr/bin/google-chrome\",\n      \"chromedriver_path\": \"/usr/bin/chromedriver\"\n    },\n    \"organisation\": {\n      \"name\": \"\",\n      \"website\": \"\",\n      \"domain\": \"\",\n      \"subdomains\": [\n        \"domain.com\"\n      ]\n    },\n    \"proxy\": {\n      \"http\": \"\",\n      \"https\": \"\",\n      \"use_system_proxy\": false\n    },\n    \"web_app\": {\n      \"debug\": false,\n      \"host\": \"127.0.0.1\",\n      \"port\": 5000,\n      \"certificate_file\": \"$CERTIFICATE_CRT\",\n      \"key_file\": \"$PRIVATE_KEY\",\n      \"api_secret\": \"$API_SECRET\",\n      \"api_validity_minutes\": 60,\n      \"api_max_calls\": 10,\n      \"api_period_in_seconds\": 60\n    },\n    \"web_scraping\": {\n      \"automated_screenshots\": false,\n      \"risk_level\": 2\n    }\n  }\n}" > ../app/plugins/common/config/config.json
    chown $SUDO_USER:$SUDO_USER ../app/plugins/common/config/config.json
    chmod 770 ./app/plugins/common/config/config.json
    ADMIN_USER="admin"
    ADMIN_PASSWD=`tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1`

    echo "[+] Creating Admin user using Create_User.py"
    echo $LINE
    pushd support_files
    python3 ./Create_User.py -u $ADMIN_USER -p $ADMIN_PASSWD -a True -b False
    popd
    echo $LINE
    echo "[+] Admin user created, user details:"
    ADMIN_USER="Username: $ADMIN_USER"
    ADMIN_PASSWD="Password: $ADMIN_PASSWD"
    echo $ADMIN_USER
    echo $ADMIN_PASSWD
    echo $LINE
    echo "[+] Setting up Self-Signed Certificates. Creating Private Key: $PRIVATE_KEY and Certificate File: $CERTIFICATE_CRT. If you want to replace these, please do so in the ../certs directory"
    mkdir ../certs
    #Change to your company details
    country=AU
    state=NSW
    locality=Sydney
    commonname=`domainname`
    organization=Scrummage
    organizationalunit=Scrummage
    email=Scrummage@Scrummage.com

    if [ -z $commonname ]
    then
        commonname=Scrummage
    fi

    openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout $PRIVATE_KEY -out $CERTIFICATE_CRT -subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
    echo "[+] Script finished."
fi
