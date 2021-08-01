#!/usr/bin/python3

if __name__ == "__main__":
    import psycopg2, datetime, argparse, sys, re, json
    from werkzeug.security import generate_password_hash

    Parser = argparse.ArgumentParser(description='To create users in Scrummage.')
    Parser.add_argument('-u', '--username', required=True, type=str)
    Parser.add_argument('-p', '--password', required=True, type=str)
    Parser.add_argument('-a', '--admin', default="False", required=True, type=str)
    Parser.add_argument('-b', '--blocked', default="False", required=True, type=str)
    Arguments = Parser.parse_args()
    Valid_Options = ["True", "False"]

    if not Arguments.admin in Valid_Options:
        sys.exit("Only booleans allowed for --admin option.")

    if not Arguments.blocked in Valid_Options:
        sys.exit("Only booleans allowed for --blocked option.")

    def Load_Main_Database():

        try:
            with open('db.json') as JSON_File:
                Configuration_Data = json.load(JSON_File)
                DB_Info = Configuration_Data['postgresql']
                DB_Host = DB_Info['host']
                DB_Port = str(int(DB_Info['port']))
                DB_Username = DB_Info['user']
                DB_Password = DB_Info['password']
                DB_Database = DB_Info['database']

        except:
            sys.exit(str(datetime.datetime.now()) + " Failed to load configuration file.")

        try:
            DB_Connection = psycopg2.connect(user=DB_Username,
                                          password=DB_Password,
                                          host=DB_Host,
                                          port=DB_Port,
                                          database=DB_Database)
            return DB_Connection

        except:
            sys.exit(str(datetime.datetime.now()) + " Failed to connect to database.")

    def check_security_requirements(Password):

        if len(Password) < 8:
            return False

        else:
            Lower = any(Letter.islower() for Letter in Password)
            Upper = any(Letter.isupper() for Letter in Password)
            Digit = any(Letter.isdigit() for Letter in Password)

            if not Upper or not Lower or not Digit:
                return False

            else:
                return True

    def check_safe_username(Username):
        
        if not Username.isalnum():
            return False

        return True

    connection = Load_Main_Database()
    cursor = connection.cursor()
    username = Arguments.username

    PSQL_Select_Query = 'SELECT * FROM users WHERE username = %s'
    cursor.execute(PSQL_Select_Query, (username,))
    User = cursor.fetchone()

    if User:
        sys.exit("[-] User already exists.")

    if check_security_requirements(Arguments.password) and check_safe_username(Arguments.username):
        password = generate_password_hash(Arguments.password)
        cursor.execute('INSERT INTO users (username, password, blocked, is_admin) VALUES (%s,%s,%s,%s)', (username, password, Arguments.blocked, Arguments.admin,))
        connection.commit()

    else:
        sys.exit("[-] Password did not meet security requirement.\nPlease make sure the password is longer than 8 digits.\nHas UPPER and lower case character\nHas at least 1 number and 1 special character.")