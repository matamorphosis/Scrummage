#!/usr/bin/env python3
import logging, os, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str(), Limit: int = 10):
        self.Plugin_Name: str = "PSBDMP"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain: str = "psbdmp.cc"
        self.Result_Type: str = "Data Leakage"
        self.Limit = Limit

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Plugin_Name.lower(), Details_to_Load=["api_key"])

        if Result:
            return Result

        else:
            return None

    def Search(self):

        try:
            Data_to_Cache: list = list()
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler(os.path.join(Directory, General.Logging(Directory, self.Plugin_Name)), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            API_Key = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:
                URL = f"https://{self.Domain}/api/v3/search/{Query}"
                Main_Response = Common.Request_Handler(url=URL)
                JSON_Object = Common.JSON_Handler(Main_Response)
                JSON_Response = JSON_Object.To_JSON_Loads()
                JSON_Output_Response = JSON_Object.Dump_JSON()
                Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                if type(JSON_Response.get('count')) == int and JSON_Response['count'] > 0:
                    Current_Step = 0

                    for Item_Link in JSON_Response['data']:
                        Dump_ID = Item_Link['id']
                        Output_Files = [Main_File]
                        HTML_URL = f"https://{self.Domain}/dump/{Dump_ID}"
                        Title = f"{self.Plugin_Name} | {Dump_ID}"

                        if HTML_URL not in Cached_Data and HTML_URL not in Data_to_Cache and Current_Step < int(self.Limit):

                            if API_Key:
                                Item_JSON_Response = Common.Request_Handler(url=f"https://{self.Domain}/api/v3/dump/{Dump_ID}?key={API_Key}")
                                JSON_Object = Common.JSON_Handler(Item_JSON_Response).To_JSON_Loads()
                                JSON_Output_Response = JSON_Object.Dump_JSON()
                                Output_Files.append(General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Item_Response, f"https://{self.Domain}/api/v3/dump/{Dump_ID}", self.The_File_Extensions["Main"]))

                            Item_Responses = Common.Request_Handler(url=HTML_URL, Filter=True, Host=f"https://{self.Domain}")
                            Item_Response = Item_Responses["Filtered"]
                            Output_Files.append(General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Item_Response, HTML_URL, self.The_File_Extensions["Query"]))

                            if Output_Files:
                                Output_Connections.Output(Output_Files, HTML_URL, Title, self.Plugin_Name.lower())
                                Data_to_Cache.append(HTML_URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                            Current_Step += 1

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - No results found.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")