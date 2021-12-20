#----------------------------------------------------------------------------------------------------
# Pull latest stable Ubuntu
#----------------------------------------------------------------------------------------------------
FROM ubuntu:20.04
LABEL org.opencontainers.image.source="https://github.com/matamorphosis/Scrummage"
#----------------------------------------------------------------------------------------------------

#----------------------------------------------------------------------------------------------------
# Update repos and install required packages
#----------------------------------------------------------------------------------------------------
RUN apt update
ARG DEBIAN_FRONTEND=noninteractive
#----------------------------------------------------------------------------------------------------

#----------------------------------------------------------------------------------------------------
# Change region as required and install packages
#----------------------------------------------------------------------------------------------------
ENV TZ=Australia/Sydney
RUN apt install -y tzdata python3 python3-pip python3-psycopg2 postgresql postgresql-contrib build-essential wget unzip git openssl curl sudo
RUN wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
RUN apt install -y ./google-chrome-stable_current_amd64.deb
#----------------------------------------------------------------------------------------------------

#----------------------------------------------------------------------------------------------------
# Clone repository and create necessary directories
#----------------------------------------------------------------------------------------------------
WORKDIR /
RUN git clone https://github.com/matamorphosis/Scrummage
RUN mkdir /Scrummage/app/static/protected/output
RUN mkdir /Scrummage/app/static/protected/screenshots
RUN chown $SUDO_USER:$SUDO_USER /Scrummage/app/static/protected
RUN chown $SUDO_USER:$SUDO_USER /Scrummage/app/static/protected/output
RUN chown $SUDO_USER:$SUDO_USER /Scrummage/app/static/protected/screenshots
RUN chmod -R 770 /Scrummage/app/static/protected
#----------------------------------------------------------------------------------------------------

#----------------------------------------------------------------------------------------------------
# Install ChromeDriver for Screenshotting Functionality to Work
#----------------------------------------------------------------------------------------------------
RUN echo "#!/bin/bash" > ./GetChromeDriver.sh
RUN echo "GoogleChromeVersion=\`google-chrome --product-version | awk -F  \".\" '/1/ {print \$1}'\`" >> ./GetChromeDriver.sh
RUN echo "LatestVersions=\`curl -X GET "https://chromedriver.chromium.org/downloads" | grep -oP \"(https\:\/\/chromedriver\.storage\.googleapis\.com\/index\.html\?path\=[0-9\.]+\/)\" | sort -u | tail -n 3\`" >> ./GetChromeDriver.sh
RUN echo "for lv in \${LatestVersions[\$i]}" >> ./GetChromeDriver.sh
RUN echo "do" >> ./GetChromeDriver.sh
RUN echo "	if [[ \$lv == *"\$GoogleChromeVersion"* ]]" >> ./GetChromeDriver.sh
RUN echo "	then" >> ./GetChromeDriver.sh
RUN echo "		ShortLV=\`echo \"\$lv\" | awk -F \"=\" '{print \$2}' | awk -F \"/\" '{print \$1}'\`" >> ./GetChromeDriver.sh
RUN echo "		wget \"https://chromedriver.storage.googleapis.com/\$ShortLV/chromedriver_linux64.zip\"" >> ./GetChromeDriver.sh
RUN echo "		if [ -f \"chromedriver_linux64.zip\" ]" >> ./GetChromeDriver.sh
RUN echo "		then" >> ./GetChromeDriver.sh
RUN echo "			unzip chromedriver_linux64.zip" >> ./GetChromeDriver.sh
RUN echo "			if [ -f \"chromedriver\" ]" >> ./GetChromeDriver.sh
RUN echo "			then" >> ./GetChromeDriver.sh
RUN echo "				mv ./chromedriver /usr/bin/chromedriver" >> ./GetChromeDriver.sh
RUN echo "			else" >> ./GetChromeDriver.sh
RUN echo "				exit 0" >> ./GetChromeDriver.sh
RUN echo "			fi" >> ./GetChromeDriver.sh
RUN echo "		else" >> ./GetChromeDriver.sh
RUN echo "			exit 0" >> ./GetChromeDriver.sh
RUN echo "		fi" >> ./GetChromeDriver.sh
RUN echo "		rm chromedriver_linux64.zip" >> ./GetChromeDriver.sh
RUN echo "	fi" >> ./GetChromeDriver.sh
RUN echo "done" >> ./GetChromeDriver.sh
RUN chmod +x ./GetChromeDriver.sh
RUN ./GetChromeDriver.sh
#----------------------------------------------------------------------------------------------------

#----------------------------------------------------------------------------------------------------
# Install below package through pip3 due to manual install woes
#----------------------------------------------------------------------------------------------------
RUN pip3 install pinterest-api
#----------------------------------------------------------------------------------------------------

#----------------------------------------------------------------------------------------------------
# Install below package from Scrummage repository due to a manual conversion from Python2 to Python3.
#----------------------------------------------------------------------------------------------------
RUN echo "#!/bin/bash" > ./InstallPyDDPackage.sh
RUN echo "MODULELOC=\`python3 -c 'import site; print(site.getsitepackages()[0])'\`" >> ./InstallPyDDPackage.sh
RUN echo "cp /Scrummage/installation/support_files/site-packages/defectdojo.py \$MODULELOC/defectdojo.py" >> ./InstallPyDDPackage.sh
RUN chmod +x ./InstallPyDDPackage.sh
RUN ./InstallPyDDPackage.sh
#----------------------------------------------------------------------------------------------------

#----------------------------------------------------------------------------------------------------
# Install online packages from requirements.txt file
#----------------------------------------------------------------------------------------------------
RUN pip3 install -r /Scrummage/installation/support_files/python_requirements.txt
#----------------------------------------------------------------------------------------------------

#----------------------------------------------------------------------------------------------------
# Change below to production for production environment
#----------------------------------------------------------------------------------------------------
ENV FLASK_ENVIRONMENT="development"
#----------------------------------------------------------------------------------------------------

#----------------------------------------------------------------------------------------------------
# Set IP and PORT Details, change if necessary
#----------------------------------------------------------------------------------------------------
ENV POSTGRES_IP="127.0.0.1"
ENV POSTGRES_PORT=5432
ENV SCRUMMAGE_IP="0.0.0.0"
ENV SCRUMMAGE_PORT=5000

#----------------------------------------------------------------------------------------------------
# Set up certificates
#----------------------------------------------------------------------------------------------------
RUN mkdir /Scrummage/certs
#----------------------------------------------------------------------------------------------------

#----------------------------------------------------------------------------------------------------
# To provide your own, uncomment the following lines, and provide .key and .crt file pair in the same directory as this dockerfile before running.
#----------------------------------------------------------------------------------------------------
# ADD ./privateKey.key /Scrummage/certs/privateKey.key
# ADD ./certificate.crt /Scrummage/certs/certificate.crt
#----------------------------------------------------------------------------------------------------

#----------------------------------------------------------------------------------------------------
# If using the above conditions to add custom a certificate pair, please ensure the names are correctly reflected below:
#----------------------------------------------------------------------------------------------------
ENV PRIVATE_KEY="/Scrummage/certs/privateKey.key"
ENV CERTIFICATE_CRT="/Scrummage/certs/certificate.crt"
#----------------------------------------------------------------------------------------------------

#----------------------------------------------------------------------------------------------------
# If using the above conditions to add custom a certificate pair, please comment out the below lines
#----------------------------------------------------------------------------------------------------
ENV country=AU
ENV state=NSW
ENV locality=Sydney
ENV commonname=Scrummage
ENV organization=Scrummage
ENV organizationalunit=Scrummage
ENV email=Scrummage@Scrummage.com
#----------------------------------------------------------------------------------------------------

RUN openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout $PRIVATE_KEY -out $CERTIFICATE_CRT -subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"

#----------------------------------------------------------------------------------------------------
# Create file to indicate whether it's the container's first run or not
#----------------------------------------------------------------------------------------------------
RUN touch /FirstRun.txt
#----------------------------------------------------------------------------------------------------

#----------------------------------------------------------------------------------------------------
# Expose TCP port 5000 from container to host, and ensure postgresql is started and start Scrummage.
#----------------------------------------------------------------------------------------------------
EXPOSE 5000
RUN chmod +x /Scrummage/installation/docker/start.sh
CMD /Scrummage/installation/docker/start.sh
#----------------------------------------------------------------------------------------------------