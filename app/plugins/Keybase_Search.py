#!/usr/bin/env python3
import logging, os, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Limit=10):
        self.Plugin_Name = "Keybase"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "keybase.io"
        self.Result_Type = "Account"
        self.Limit = General.Get_Limit(Limit)

    def Search(self):

        try:
            Data_to_Cache = []
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler(os.path.join(Directory, General.Logging(Directory, self.Plugin_Name)), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:
                URL = f"https://{self.Domain}/_/api/1.0/user/user_search.json?q={Query}&num_wanted={str(self.Limit)}"
                Main_Response = Common.Request_Handler(URL)
                JSON_Object = Common.JSON_Handler(Main_Response)
                JSON_Response = JSON_Object.To_JSON_Loads()
                JSON_Output_Response = JSON_Object.Dump_JSON()
                Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                if JSON_Response.get('list') and len(JSON_Response['list']) > 0:

                    for Item_Link in JSON_Response['list']:
                        Username = Item_Link['keybase']['username']
                        Output_Files = [Main_File]
                        HTML_URL = f"https://{self.Domain}/{Username}"
                        Title = f"{self.Plugin_Name} | {Username}"

                        if HTML_URL not in Cached_Data and HTML_URL not in Data_to_Cache:
                            Item_Responses = Common.Request_Handler(HTML_URL, Filter=True, Host=f"https://www.{self.Domain}")
                            Item_Response = Item_Responses["Filtered"]
                            Output_Files.append(General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Item_Response, HTML_URL, self.The_File_Extensions["Query"]))

                            if Output_Files:
                                Output_Connections.Output(Output_Files, HTML_URL, Title, self.Plugin_Name.lower())
                                Data_to_Cache.append(HTML_URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - No results found.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")