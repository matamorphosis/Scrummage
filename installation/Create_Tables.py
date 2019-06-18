import psycopg2

try:
    connection = psycopg2.connect(user = "scrummage",
                                  password = "scrummage",
                                  host = "127.0.0.1",
                                  port = "5432",
                                  database = "scrummage")
    cursor = connection.cursor()

    create_users_query = '''CREATE TABLE users
          (user_id SERIAL PRIMARY KEY NOT NULL,
          username TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL,
          blocked BOOLEAN NOT NULL,
          is_admin BOOLEAN NOT NULL);'''

    create_events_query = '''CREATE TABLE events
          (event_id SERIAL PRIMARY KEY NOT NULL,
          description TEXT NOT NULL,
          created_at TEXT NOT NULL);'''

    create_results_query = '''CREATE TABLE results
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
          result_type TEXT NOT NULL);'''

    create_tasks_query = '''CREATE TABLE tasks
          (task_id SERIAL PRIMARY KEY NOT NULL,
          query TEXT NOT NULL,
          plugin TEXT NOT NULL,
          description TEXT NOT NULL,
          frequency TEXT NOT NULL,
          task_limit TEXT,
          status TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL);'''
    
    cursor.execute(create_users_query)
    print("[+] Users table created successfully in PostgreSQL.")
    cursor.execute(create_tasks_query)
    print("[+] Tasks table created successfully in PostgreSQL.")
    cursor.execute(create_results_query)
    print("[+] Results table created successfully in PostgreSQL.")
    cursor.execute(create_events_query)
    print("[+] Events table created successfully in PostgreSQL.")
    connection.commit()
    print("Table created successfully in PostgreSQL ")

except (Exception, psycopg2.DatabaseError) as error :
    print ("Error while creating PostgreSQL table. ", error)

finally:
    #closing database connection.
        if(connection):
            cursor.close()
            connection.close()
            print("PostgreSQL connection closed.")
