if [ -f /etc/redhat-release ]; then
  yum update
  yum install python3 python3-pip postgresql-server postgresql-contrib python3-psycopg2 ruby rubygems build-essential wget unzip
fi

if [ -f /etc/lsb-release ]; then
  apt update
  apt install -y python3 python3-pip python3-psycopg2 postgresql postgresql-contrib ruby rubygems build-essential wget unzip
fi

mkdir chrome_dev
cd chrome_dev
wget https://chromedriver.storage.googleapis.com/76.0.3809.12/chromedriver_linux64.zip
unzip chromedriver_linux64.zip
mv chromedriver /usr/bin/chromedriver
cd ..
pip3 install -r python_requirements.txt
python3 Create_Tables.py
gem install brakeman
echo "[+] Installation Complete."

DATABASE="scrummage"
USER="scrummage"
PASSWD=`tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1`

sudo -u postgres psql
create database $DATABASE;
create user $USER with encrypted password $PASSWD;
grant all privileges on $DATABASE mydb to $USER;
\q
echo "Database has been created with the following details, please retain these for later."
$DATABASE="Database: $DATABASE"
$USER="Username: $USER"
$PASSWD="Password: $PASSWD"
echo $DATABASE
echo $USER
echo $PASSWD
echo "[+] Database setup complete."