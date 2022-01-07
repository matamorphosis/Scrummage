import plugin_verifier, plugin_definitions, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Caller:

    def __init__(self, Result, Task_ID, Custom_Query=None):

        try:
            self.plugin_name = Result[2]
            self.query = Result[1]
            self.custom_query = Custom_Query
            self.limit = Result[5]
            self.task_id = Task_ID

        except Exception as e:
            print(f'{Common.Date()} - Plugin Caller - {e}')

    def Starter(self, Object):

        try:
            Connection = Object.Load_Configuration(Postgres_Database=True, Object="postgresql")
            Cursor = Connection.cursor()
            PSQL_Update_Query = 'UPDATE tasks SET status = %s WHERE task_id = %s'
            Cursor.execute(PSQL_Update_Query, ("Running", int(self.task_id),))
            Connection.commit()

        except Exception as e:
            print(f'{Common.Date()} - Plugin Caller - {e}')

    def Stopper(self, Object):

        try:
            Connection = Object.Load_Configuration(Postgres_Database=True, Object="postgresql")
            Cursor = Connection.cursor()
            PSQL_Update_Query = 'UPDATE tasks SET status = %s WHERE task_id = %s'
            Cursor.execute(PSQL_Update_Query, ("Stopped", int(self.task_id),))
            Connection.commit()

        except Exception as e:
            print(f'{Common.Date()} - Plugin Caller - {e}')

    def Call_Plugin(self, Scrummage_Working_Directory):

        try:
            Object = Common.Configuration(Output=True)
            self.Starter(Object)
            Plugin = plugin_verifier.Plugin_Verifier(self.plugin_name, self.task_id, self.query, self.limit, Custom_Query=self.custom_query).Verify_Plugin(Scrummage_Working_Directory)

            if Plugin and all(Item in Plugin for Item in ["Object", "Search Option", "Function Kwargs"]):
                getattr(Plugin["Object"], Plugin["Search Option"])(**Plugin["Function Kwargs"])

            else:
                print(f"{Common.Date()} - Plugin Caller - Failed to start plugin.")

        except Exception as e:
            print(f'{Common.Date()} - Plugin Caller - {e}')
        finally:
            self.Stopper(Object)
        
if __name__ == "__main__":

    try:
        import argparse, os, sys, pathlib
        Parser = argparse.ArgumentParser(description='Plugin Caller calls Scrummage plugins.')
        Parser.add_argument('-t', '--task', type=int, required=True, help='This option is used to specify a task ID to run. ./plugin_caller.py -t 1')
        Arguments = Parser.parse_args()
        Scrummage_Working_Directory = pathlib.Path(__file__).parent.absolute()
        os.chdir(Scrummage_Working_Directory)
        Task_ID = 0

        if str(Scrummage_Working_Directory) == str(os.getcwd()):

            try:
                Task_ID = int(Arguments.task)
                Valid_Plugins = plugin_definitions.Get(Scrummage_Working_Directory)
                Connection = Common.Configuration(Output=True).Load_Configuration(Postgres_Database=True, Object="postgresql")
                cursor = Connection.cursor()
                PSQL_Select_Query = 'SELECT * FROM tasks WHERE task_id = %s;'
                cursor.execute(PSQL_Select_Query, (Task_ID,))
                result = cursor.fetchone()

                if result:

                    if result[1] == "[IDENTITIES_DATABASE]":
                        ID_DB_Search_Type = Valid_Plugins[result[2]]["Organisation_Presets"]

                        if ID_DB_Search_Type == "identity_emails":
                            cursor.execute("SELECT email FROM org_identities;")
                            ID_DB_Results = cursor.fetchall()

                        elif ID_DB_Search_Type == "identity_phones":
                            cursor.execute("SELECT phone FROM org_identities;")
                            ID_DB_Results = cursor.fetchall()

                        elif ID_DB_Search_Type == "identity_usernames":
                            cursor.execute("SELECT username FROM org_identities;")
                            ID_DB_Results = cursor.fetchall()

                        Filtered_Data = [Row[0] for Row in ID_DB_Results]

                        Query = ", ".join(Filtered_Data)

                    else:
                        Query = None

                    Plugin_Caller(Result=result, Task_ID=Task_ID, Custom_Query=Query).Call_Plugin(Scrummage_Working_Directory)

            except:
                sys.exit("[-] Invalid Task ID.")

        else:
            sys.exit("[-] Failed to set working directory.")

    except Exception as e:
        print(f'{Common.Date()} - Plugin Caller - {e}')