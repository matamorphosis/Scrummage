#!/bin/bash
# Supports installation via docker.
service postgresql start
if [ -f /FirstRun.txt ]; then
    DATABASE="scrummage"
    USER="scrummage"
    DB_PASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-64} | head -n 1)
    service postgresql start
    sudo -u postgres psql -c "CREATE DATABASE $DATABASE;"
    sudo -u postgres psql -c "CREATE USER $USER WITH ENCRYPTED PASSWORD '$DB_PASS';"
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DATABASE TO $USER;"
    echo "{" > /Scrummage/installation/support_files/db.json
    echo "    \"postgresql\": {" >> /Scrummage/installation/support_files/db.json
    echo "        \"host\": \"$POSTGRES_IP\"," >> /Scrummage/installation/support_files/db.json
    echo "        \"port\": $POSTGRES_PORT," >> /Scrummage/installation/support_files/db.json
    echo "        \"database\": \"$DATABASE\"," >> /Scrummage/installation/support_files/db.json
    echo "        \"user\": \"$USER\"," >> /Scrummage/installation/support_files/db.json
    echo "        \"password\": \"$DB_PASS\"" >> /Scrummage/installation/support_files/db.json
    echo "    }" >> /Scrummage/installation/support_files/db.json
    echo "}" >> /Scrummage/installation/support_files/db.json
    chown $SUDO_USER:$SUDO_USER /Scrummage/installation/support_files/db.json
    chmod 770 /Scrummage/installation/support_files/db.json
    sed s/db.json/\\/Scrummage\\/installation\\/support_files\\/db.json/ /Scrummage/installation/support_files/Create_Tables.py > /Scrummage/installation/support_files/Create_Tables_New.py
    sed s/db.json/\\/Scrummage\\/installation\\/support_files\\/db.json/ /Scrummage/installation/support_files/Create_User.py > /Scrummage/installation/support_files/Create_User_New.py
    python3 /Scrummage/installation/support_files/Create_Tables_New.py
    API_SECRET=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-64} | head -n 1)
    printf "{\n  \"inputs\": {\n    \"bitcoinabuse\": {\n      \"api_key\": \"\"\n    },\n    \"craigslist\": {\n      \"city\": \"\"\n    },\n    \"ebay\": {\n      \"access_key\": \"\"\n    },\n    \"emailrep\": {\n      \"api_key\": \"\"\n    },\n    \"flickr\": {\n      \"api_key\": \"\",\n      \"api_secret\": \"\"\n    },\n    \"general\": {\n      \"location\": \"au\"\n    },\n    \"github\": {\n      \"username\": \"\",\n      \"token\": \"\"\n    },\n    \"google\": {\n      \"cx\": \"\",\n      \"application_name\": \"\",\n      \"application_version\": \"\",\n      \"developer_key\": \"\"\n    },\n    \"greynoisesearch\": {\n      \"api_key\": \"\"\n    },\n    \"haveibeenpwned\": {\n      \"api_key\": \"\"\n    },\n    \"hunter\": {\n      \"api_key\": \"\"\n    },\n    \"hybridanalysis\": {\n      \"api_key\": \"\"\n    },\n    \"intelligencex\": {\n      \"api_key\": \"\"\n    },\n    \"ipstack\": {\n      \"api_key\": \"\"\n    },\n    \"leaklookup\": {\n      \"api_key\": \"\"\n    },\n    \"nameapi\": {\n      \"api_key\": \"\"\n    },\n    \"naver\": {\n      \"client_id\": \"\",\n      \"client_secret\": \"\"\n    },\n    \"ok\": {\n      \"application_id\": \"\",\n      \"application_key\": \"\",\n      \"application_secret\": \"\",\n      \"access_token\": \"\",\n      \"session_secret\": \"\"\n    },\n    \"pinterest\": {\n      \"oauth_token\": \"\"\n    },\n    \"pulsedive\": {\n      \"api_key\": \"\"\n    },\n    \"reddit\": {\n      \"client_id\": \"\",\n      \"client_secret\": \"\",\n      \"user_agent\": \"\",\n      \"username\": \"\",\n      \"password\": \"\",\n      \"subreddits\": \"all\"\n    },\n    \"shodan\": {\n      \"api_key\": \"\"\n    },\n    \"sslmate\": {\n      \"search_subdomain\": true\n    },\n    \"tumblr\": {\n      \"consumer_key\": \"\",\n      \"consumer_secret\": \"\",\n      \"oauth_token\": \"\",\n      \"oauth_secret\": \"\"\n    },\n    \"twitter\": {\n      \"consumer_key\": \"\",\n      \"consumer_secret\": \"\",\n      \"access_key\": \"\",\n      \"access_secret\": \"\"\n    },\n    \"ukbusiness\": {\n      \"api_key\": \"\"\n    },\n    \"urlscan\": {\n      \"api_key\": \"\"\n    },\n    \"vkontakte\": {\n      \"access_token\": \"\"\n    },\n    \"virustotal\": {\n      \"api_key\": \"\"\n    },\n    \"vulners\": {\n      \"api_key\": \"\"\n    },\n    \"whatcms\": {\n      \"api_key\": \"\"\n    },\n    \"yandex\": {\n      \"username\": \"\",\n      \"api_key\": \"\"\n    },\n    \"youtube\": {\n      \"developer_key\": \"\",\n      \"application_name\": \"youtube\",\n      \"application_version\": \"v3\"\n    }\n  },\n  \"outputs\": {\n    \"csv\": {\n      \"use_csv\": false\n    },\n    \"docx_report\": {\n      \"use_docx\": false\n    },\n    \"defectdojo\": {\n      \"ssl\": false,\n      \"api_key\": \"\",\n      \"host\": \"host.com\",\n      \"user\": \"admin\",\n      \"engagement_id\": 1,\n      \"product_id\": 1,\n      \"test_id\": 1,\n      \"user_id\": 1\n    },\n    \"elasticsearch\": {\n      \"ssl\": false,\n      \"host\": \"\",\n      \"port\": 9200,\n      \"index\": \"Scrummage\",\n      \"use_timestamp\": true\n    },\n    \"email\": {\n      \"smtp_server\": \"\",\n      \"smtp_port\": 587,\n      \"from_address\": \"\",\n      \"from_password\": \"\",\n      \"to_address\": \"\"\n    },\n    \"jira\": {\n      \"project_key\": \"\",\n      \"address\": \"\",\n      \"username\": \"\",\n      \"password\": \"\",\n      \"ticket_type\": \"\"\n    },\n    \"postgresql\": {\n      \"host\": \"$POSTGRES_IP\",\n      \"port\": $POSTGRES_PORT,\n      \"database\": \"$DATABASE\",\n      \"user\": \"$USER\",\n      \"password\": \"$DB_PASS\"\n    },\n    \"rtir\": {\n      \"ssl\": false,\n      \"host\": \"\",\n      \"port\": 80,\n      \"user\": \"\",\n      \"password\": \"\",\n      \"authenticator\": \"\"\n    },\n    \"scumblr\": {\n      \"host\": \"\",\n      \"port\": 5432,\n      \"database\": \"\",\n      \"user\": \"\",\n      \"password\": \"\"\n    },\n    \"slack\": {\n      \"token\": \"\",\n      \"channel\": \"\"\n    }\n  },\n  \"core\": {\n    \"google_chrome\": {\n      \"application_path\": \"/usr/bin/google-chrome\",\n      \"chromedriver_path\": \"/usr/bin/chromedriver\"\n    },\n    \"organisation\": {\n      \"name\": \"\",\n      \"website\": \"\",\n      \"domain\": \"\",\n      \"subdomains\": [\n        \"domain.com\"\n      ]\n    },\n    \"proxy\": {\n      \"http\": \"\",\n      \"https\": \"\",\n      \"use_system_proxy\": false\n    },\n    \"web_app\": {\n      \"debug\": false,\n      \"host\": \"$SCRUMMAGE_IP\",\n      \"port\": $SCRUMMAGE_PORT,\n      \"certificate_file\": \"$CERTIFICATE_CRT\",\n      \"key_file\": \"$PRIVATE_KEY\",\n      \"api_secret\": \"$API_SECRET\",\n      \"api_validity_minutes\": 60,\n      \"api_max_calls\": 10,\n      \"api_period_in_seconds\": 60\n    },\n    \"web_scraping\": {\n      \"automated_screenshots\": false,\n      \"risk_level\": 2\n    }\n  }\n}" > /Scrummage/app/plugins/common/config/config.json
    chown $SUDO_USER:$SUDO_USER /Scrummage/app/plugins/common/config/config.json
    chmod 770 /Scrummage/app/plugins/common/config/config.json
    ADMIN_USER="admin"
    ADMIN_PASSWD=$(tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1)
    python3 /Scrummage/installation/support_files/Create_User_New.py -u $ADMIN_USER -p $ADMIN_PASSWD -a True -b False
    echo -e "\n----------------------------------------------------------------------------------------------------\nThis is the admin password, this will only be displayed on the first run of Scrummage:\n$ADMIN_PASSWD\n----------------------------------------------------------------------------------------------------\n"
    rm /FirstRun.txt
fi
chmod +x /Scrummage/installation/support_files/Fix_ChromeDriver.sh

#-------------------------------------------------------------------------------------------
GoogleChromeVersion=`google-chrome --product-version | awk -F  "." '{print $1}'`
if [[ $GoogleChromeVersion =~ .+ ]]
then
    LatestVersions=`curl -X GET "https://chromedriver.chromium.org/downloads" | grep -oP "(https\:\/\/chromedriver\.storage\.googleapis\.com\/index\.html\?path\=[0-9\.]+\/)" | sort -u | tail -n 3`
    ChromeDriverVersion=""
    Linux64ChromeDriverZIP="chromedriver_linux64.zip"
    Linux64ChromeDriver="chromedriver"

    for lv in ${LatestVersions[$i]}
    do
        if [[ $lv == *"$GoogleChromeVersion"* ]]
        then
            ShortLV=`echo "$lv" | awk -F "=" '{print $2}' | awk -F "/" '{print $1}'`

            if [ -d "./chrome_dev" ]
            then
                echo "[i] Removing the existing chrome_dev directory."
                rm -r ./chrome_dev
            fi
            if [ -f "$Linux64ChromeDriverZIP" ]
            then
                echo "[i] Removing the existing $Linux64ChromeDriverZIP file in the current directory."
                rm ./$Linux64ChromeDriverZIP
            fi
            if [ -f "$Linux64ChromeDriver" ]
            then
                echo "[i] Removing the existing $Linux64ChromeDriver file in the current directory."
                rm ./$Linux64ChromeDriver
            fi
            echo "[+] Downloading Chrome Driver Version $ShortLV."
            wget "https://chromedriver.storage.googleapis.com/$ShortLV/chromedriver_linux64.zip"
            if [ -f "$Linux64ChromeDriverZIP" ]
            then
                echo "[+] Unzipping $Linux64ChromeDriverZIP."
                unzip "$Linux64ChromeDriverZIP"
                if [ -f "$Linux64ChromeDriver" ]
                then
                    echo "[+] Moving the unzipped chromedriver binary to the /usr/bin directory."
                    mv ./$Linux64ChromeDriver /usr/bin/chromedriver
                fi
            fi
            echo "[i] Cleaning up."
            rm ./$Linux64ChromeDriverZIP
        fi
    done
fi
#---------------------------------------------------------------------------------------------------

python3 /Scrummage/app/Scrummage.py