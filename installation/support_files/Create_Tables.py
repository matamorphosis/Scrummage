#!/usr/bin/python3
import psycopg2, sys, json, datetime

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
        return psycopg2.connect(user=DB_Username,
                                      password=DB_Password,
                                      host=DB_Host,
                                      port=DB_Port,
                                      database=DB_Database)

    except:
        sys.exit(str(datetime.datetime.now()) + " Failed to connect to database.")

try:
    connection = Load_Main_Database()
    cursor = connection.cursor()

    create_users_query = '''CREATE TABLE IF NOT EXISTS users
          (user_id SERIAL PRIMARY KEY NOT NULL,
          username TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL,
          blocked BOOLEAN NOT NULL,
          is_admin BOOLEAN NOT NULL,
          api_key TEXT,
          api_generated_time TEXT,
          mfa_token TEXT,
          mfa_confirmed TEXT);'''

    create_events_query = '''CREATE TABLE IF NOT EXISTS events
          (event_id SERIAL PRIMARY KEY NOT NULL,
          description TEXT NOT NULL,
          created_at TEXT NOT NULL);'''

    create_results_query = '''CREATE TABLE IF NOT EXISTS results
          (result_id SERIAL PRIMARY KEY NOT NULL,
          task_id INT NOT NULL,
          title TEXT NOT NULL,
          plugin TEXT NOT NULL,
          status TEXT NOT NULL,
          domain TEXT NOT NULL,
          link TEXT UNIQUE NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          screenshot_url TEXT UNIQUE,
          output_file TEXT,
          result_type TEXT NOT NULL,
          screenshot_requested BOOLEAN);'''

    create_tasks_query = '''CREATE TABLE IF NOT EXISTS tasks
          (task_id SERIAL PRIMARY KEY NOT NULL,
          query TEXT NOT NULL,
          plugin TEXT NOT NULL,
          description TEXT NOT NULL,
          frequency TEXT NOT NULL,
          task_limit TEXT,
          status TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL);'''

    create_org_query = '''CREATE TABLE IF NOT EXISTS org_identities
          (identity_id SERIAL PRIMARY KEY NOT NULL,
          firstname TEXT NOT NULL,
          middlename TEXT,
          surname TEXT NOT NULL,
          fullname TEXT NOT NULL,
          username TEXT,
          email TEXT NOT NULL,
          phone TEXT NOT NULL);'''
    
    cursor.execute(create_users_query)
    print(str(datetime.datetime.now()) + " Users table created successfully in PostgreSQL.")
    cursor.execute(create_tasks_query)
    print(str(datetime.datetime.now()) + " Tasks table created successfully in PostgreSQL.")
    cursor.execute(create_results_query)
    print(str(datetime.datetime.now()) + " Results table created successfully in PostgreSQL.")
    cursor.execute(create_events_query)
    print(str(datetime.datetime.now()) + " Events table created successfully in PostgreSQL.")
    cursor.execute(create_org_query)
    print(str(datetime.datetime.now()) + " Organisation Identities table created successfully in PostgreSQL.")
    connection.commit()
    print(str(datetime.datetime.now()) + " Table created successfully in PostgreSQL.")

except (Exception, psycopg2.DatabaseError) as error:
    print (str(datetime.datetime.now()) + " Error while creating PostgreSQL table. ", error)

finally:
    
    if(connection):
        cursor.close()
        connection.close()
        print(str(datetime.datetime.now()) + " PostgreSQL connection closed.")