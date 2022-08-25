#!/usr/bin/python3
import psycopg2, sys, json, datetime

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

    except Exception as e:
        sys.exit(str(datetime.datetime.now()) + f" Failed to connect to database.  {str(e)}.")

if __name__ == "__main__":

    try:
        connection = Load_Main_Database()
        cursor = connection.cursor()
        update_users_query: str = '''ALTER TABLE users
        ADD COLUMN mfa_token TEXT,
        ADD COLUMN mfa_confirmed TEXT;
        '''
        cursor.execute(update_users_query)
        print(str(datetime.datetime.now()) + " Users table created updated in PostgreSQL.")    
        connection.commit()
        print(str(datetime.datetime.now()) + " Scrummage Database successfully updated in PostgreSQL.")

    except (Exception, psycopg2.DatabaseError) as error:
        print (str(datetime.datetime.now()) + f" Error while creating PostgreSQL table. {str(error)}.")

    finally:
        
        if(connection):
            cursor.close()
            connection.close()
            print("[i] PostgreSQL connection closed.")