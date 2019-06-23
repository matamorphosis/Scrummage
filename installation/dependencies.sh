
if [ -f /etc/redhat-release ]; then
  yum update
  yum install python3 python3-pip postgresql-server postgresql-contrib python3-psycopg2 ruby rubygems build-essential wget unzip
fi

if [ -f /etc/lsb-release ]; then
  apt update
  apt install -y python3 python3-pip python3-psycopg2 postgresql postgresql-contrib ruby rubygems build-essential wget unzip
fi

mkdir ../bin/static/protected
mkdir ../bin/static/protected/output
mkdir ../bin/static/protected/screenshots
mkdir chrome_dev
cd chrome_dev
wget https://chromedriver.storage.googleapis.com/76.0.3809.12/chromedriver_linux64.zip
unzip chromedriver_linux64.zip
mv chromedriver /usr/bin/chromedriver
cd ..
pip3 uninstall requests
pip3 install -r python_requirements.txt
gem install brakeman
echo "[+] Installation Complete."

DATABASE="scrummage"
USER="scrummage"
PASSWD=`tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1`

sudo -u postgres psql -c "CREATE DATABASE $DATABASE;"
sudo -u postgres psql -c "CREATE USER $USER WITH ENCRYPTED PASSWORD '$PASSWD';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DATABASE TO $USER;"
echo "Database has been created with the following details, please retain these for later."

echo "{" > db.json
echo "    \"postgresql\": [" >> db.json
echo "        {" >> db.json
echo "            \"host\": \"127.0.0.1\"," >> db.json
echo "            \"port\": 5432," >> db.json
echo "            \"database\": \"$DATABASE\"," >> db.json
echo "            \"user\": \"$USER\"," >> db.json
echo "            \"password\": \"$PASSWD\"" >> db.json
echo "        }" >> db.json
echo "    ]" >> db.json
echo "}" >> db.json

DATABASE="Database: $DATABASE"
USER="Username: $USER"
PASSWD="Password: $PASSWD"
echo "Database Details:"
echo $DATABASE
echo $USER
echo $PASSWD
echo "[+] Database setup complete."

python3 Create_Tables.py
echo "[+] Scrummage tables created."

ADMIN_USER="admin"
ADMIN_PASSWD=`tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1`

python3 Create_User.py -u $ADMIN_USER -p $ADMIN_PASSWD -a True -b False
echo "[+] Admin user created, user details:"
ADMIN_USER="Username: $ADMIN_USER"
ADMIN_PASSWD="Password: $ADMIN_PASSWD"
echo $ADMIN_USER
echo $ADMIN_PASSWD
