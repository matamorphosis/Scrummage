#!/bin/bash
# Supports installation via docker.
export DISK_UUID=$(blkid -s UUID -o value /dev/$(lsblk -io KNAME | grep "sd" | head -n 1))
service postgresql start
if [ -f /FirstRun.txt ]; then
    export DATABASE="scrummage"
    export USER="scrummage"
    export DB_PASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-64} | head -n 1)
    export API_SECRET=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-64} | head -n 1)
    poetry run python3 /Scrummage/installation/support_files/generate_configuration_files.py
    service postgresql start
    sudo -u postgres psql -c "CREATE DATABASE $DATABASE;"
    sudo -u postgres psql -c "CREATE USER $USER WITH ENCRYPTED PASSWORD '$DB_PASS';"
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DATABASE TO $USER;"
    chown $SUDO_USER:$SUDO_USER /Scrummage/app/plugins/common/config/db.config
    chmod 770 /Scrummage/app/plugins/common/config/db.config
    sed s/db.config/\\/Scrummage\\/installation\\/support_files\\/db.config/ /Scrummage/installation/support_files/Create_Tables.py > /Scrummage/installation/support_files/Create_Tables_New.py
    sed s/db.config/\\/Scrummage\\/installation\\/support_files\\/db.config/ /Scrummage/installation/support_files/Create_User.py > /Scrummage/installation/support_files/Create_User_New.py
    poetry run python3 /Scrummage/installation/support_files/Create_Tables_New.py
    chown $SUDO_USER:$SUDO_USER /Scrummage/app/plugins/common/config/config.config
    chmod 770 /Scrummage/app/plugins/common/config/config.config
    ADMIN_USER="admin"
    ADMIN_PASSWD=$(tr -cd '[:alnum:]' < /dev/urandom | fold -w 30 | head -n 1)
    poetry run python3 /Scrummage/installation/support_files/Create_User_New.py -u $ADMIN_USER -p $ADMIN_PASSWD -a True -b False
    echo -e "\n----------------------------------------------------------------------------------------------------\nThis is the admin password, this will only be displayed on the first run of Scrummage:\n$ADMIN_PASSWD\n----------------------------------------------------------------------------------------------------\n"
    rm /FirstRun.txt
    unset DATABASE
    unset USER
    unset DB_PASS
    unset API_SECRET
fi
chmod +x /Scrummage/installation/support_files/Fix_ChromeDriver.sh

#-------------------------------------------------------------------------------------------
GoogleChromeVersion=$(google-chrome --product-version | awk -F "." '{print $1}')
if [[ $GoogleChromeVersion =~ .+ ]]; then
    LatestVersions=$(curl -X GET "https://chromedriver.chromium.org/downloads" | grep -oP "(https\:\/\/chromedriver\.storage\.googleapis\.com\/index\.html\?path\=[0-9\.]+\/)" | sort -u)
    ChromeDriverVersion=""
    Linux64ChromeDriverZIP="./chromedriver_linux64.zip"
    Linux64ChromeDriver="chromedriver"
    ChromeDev="./chrome_dev"

    for lv in ${LatestVersions[$i]}; do
        if [[ $lv == *"$GoogleChromeVersion"* ]]; then
            ShortLV=$(echo "$lv" | awk -F "=" '{print $2}' | awk -F "/" '{print $1}')

            if [ -d "$ChromeDev" ]; then
                echo "[i] Removing the existing chrome_dev directory."
                rm -r $ChromeDev
            fi
            if [ -f "$Linux64ChromeDriverZIP" ]; then
                echo "[i] Removing the existing $Linux64ChromeDriverZIP file in the current directory."
                rm $Linux64ChromeDriverZIP
            fi
            if [ -f "$Linux64ChromeDriver" ]; then
                echo "[i] Removing the existing $Linux64ChromeDriver file in the current directory."
                rm $Linux64ChromeDriver
            fi
            echo "[+] Downloading Chrome Driver Version $ShortLV."
            wget "https://chromedriver.storage.googleapis.com/$ShortLV/chromedriver_linux64.zip"
            if [ -f "$Linux64ChromeDriverZIP" ]; then
                echo "[+] Unzipping $Linux64ChromeDriverZIP."
                unzip "$Linux64ChromeDriverZIP"
                if [ -f "$Linux64ChromeDriver" ]; then
                    echo "[+] Moving the unzipped chromedriver binary to the /usr/bin directory."
                    mv $Linux64ChromeDriver /usr/bin/chromedriver
                fi
            fi
            echo "[i] Cleaning up."
            rm $Linux64ChromeDriverZIP
            break
        fi
    done
fi
#---------------------------------------------------------------------------------------------------

poetry run python3 /Scrummage/app/Scrummage.py