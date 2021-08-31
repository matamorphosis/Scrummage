#!/usr/bin/python3
import psycopg2, sys, json, datetime

def Update_Config():

    try:
        print(str(datetime.datetime.now()) + " Updating config.json file.")
        File = open("config.json", "r")
        JSON_Data = json.load(File)
        JSON_Data["core"]["organisation"] = {"name": "", "website": "", "domain": "", "subdomains": []}
        JSON_Data["inputs"]["github"] = {"username": "", "token": ""}
        New_File = open("config_new.json", "w")
        New_File.write(json.dumps(JSON_Data, indent=2))
        New_File.close()
        print(str(datetime.datetime.now()) + " Successfully updated config.json file.")

    except Exception as e:
        sys.exit(str(datetime.datetime.now()) + f" Failed to update config.json file. {str(e)}.")

def Load_Main_Database():

    try:

        with open('config.json', 'r') as JSON_File:
            Configuration_Data = json.load(JSON_File)
            DB_Info = Configuration_Data['outputs']['postgresql']
            DB_Host = DB_Info['host']
            DB_Port = str(int(DB_Info['port']))
            DB_Username = DB_Info['user']
            DB_Password = DB_Info['password']
            DB_Database = DB_Info['database']

    except Exception as e:
        sys.exit(str(datetime.datetime.now()) + f" Failed to load configuration file. {str(e)}.")        

    try:
        DB_Connection = psycopg2.connect(user=DB_Username,
                                      password=DB_Password,
                                      host=DB_Host,
                                      port=DB_Port,
                                      database=DB_Database)
        return DB_Connection

    except:
        sys.exit(str(datetime.datetime.now()) + f" Failed to connect to database.  {str(e)}.")

try:
    Update_Config()
    connection = Load_Main_Database()
    cursor = connection.cursor()

    create_org_query = '''CREATE TABLE IF NOT EXISTS org_identities
          (identity_id SERIAL PRIMARY KEY NOT NULL,
          firstname TEXT NOT NULL,
          middlename TEXT,
          surname TEXT NOT NULL,
          fullname TEXT NOT NULL,
          username TEXT,
          email TEXT NOT NULL,
          phone TEXT NOT NULL);'''
    
    cursor.execute(create_org_query)
    print(str(datetime.datetime.now()) + " Organisation Identities table created successfully in PostgreSQL.")
    cursor.execute("SELECT result_id FROM results WHERE result_type = 'Virus';")
    results = cursor.fetchall()

    for result in results:
        cursor.execute("UPDATE results SET result_type = %s WHERE result_id = %s;", ("Malware", result[0]))
    
    connection.commit()
    print(str(datetime.datetime.now()) + " Scrummage Database successfully updated in PostgreSQL.")

except (Exception, psycopg2.DatabaseError) as error :
    print (str(datetime.datetime.now()) + f" Error while creating PostgreSQL table. {str(error)}.")

finally:
    
    if(connection):
        cursor.close()
        connection.close()
        print("[i] PostgreSQL connection closed.")