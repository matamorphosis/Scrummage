#!/bin/bash

if ! command -v google-chrome &> /dev/null
then
    echo "[-] You need to install Google Chrome, before you can update the Chrome Driver."
    exit
fi
if [[ $EUID -ne 0 ]]
then
    echo "[-] This script must be run as root." 
    exit 0
else
    GoogleChromeVersion=$(google-chrome --product-version | awk -F  "." '{print $1}')
    if [[ $GoogleChromeVersion =~ .+ ]]; then
        LatestVersions=$(curl -X GET "https://chromedriver.chromium.org/downloads" | grep -oP "(https\:\/\/chromedriver\.storage\.googleapis\.com\/index\.html\?path\=[0-9\.]+\/)" | sort -u)
        ChromeDriverVersion=""
        Linux64ChromeDriverZIP="chromedriver_linux64.zip"
        Linux64ChromeDriver="chromedriver"

        for lv in ${LatestVersions[$i]}; do
            if [[ $lv == *"$GoogleChromeVersion"* ]]; then
                ShortLV=$(echo "$lv" | awk -F "=" '{print $2}' | awk -F "/" '{print $1}')
                read -p "[+] Based on the information gathered, $ShortLV is the version of Chrome Driver required. Would you like to proceed to download this and set it as your local Chrome Driver? (Y/N): " response
                case "$response" in
                    [yY])
                        if [ -d "./chrome_dev" ]; then
                            echo "[i] Removing the existing chrome_dev directory."
                            rm -r ./chrome_dev
                        fi
                        if [ -f "$Linux64ChromeDriverZIP" ]; then
                            echo "[i] Removing the existing $Linux64ChromeDriverZIP file in the current directory."
                            rm ./$Linux64ChromeDriverZIP
                        fi
                        if [ -f "$Linux64ChromeDriver" ]; then
                            echo "[i] Removing the existing $Linux64ChromeDriver file in the current directory."
                            rm ./$Linux64ChromeDriver
                        fi
                        echo "[+] Downloading Chrome Driver Version $ShortLV."
                        wget "https://chromedriver.storage.googleapis.com/$ShortLV/chromedriver_linux64.zip"
                        if [ -f "$Linux64ChromeDriverZIP" ]; then
                            echo "[+] Unzipping $Linux64ChromeDriverZIP."
                            unzip "$Linux64ChromeDriverZIP"
                            if [ -f "$Linux64ChromeDriver" ]; then
                                echo "[+] Moving the unzipped chromedriver binary to the /usr/bin directory."
                                mv ./$Linux64ChromeDriver /usr/bin/chromedriver
                            fi
                        fi
                        echo "[i] Cleaning up."
                        rm ./$Linux64ChromeDriverZIP
                        exit 0
                        ;;
                    *)
                        echo "[i] Terminating program."
                        exit 0
                        ;;
                esac
                break
            fi
        done
    fi
fi