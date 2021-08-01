#!/usr/bin/env python3
import plugins.common.General as General, plugins.common.Common as Common, os, logging
from emailrep import EmailRep

class Plugin_Search:

    def __init__(self, Query_List, Task_ID):
        self.Plugin_Name = "Email Reputation"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Concat_Plugin_Name = "emailrep"
        self.Domain = "emailrep.io"
        self.Result_Type = "Email Information"

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Concat_Plugin_Name, Details_to_Load=["api_key"])

        if Result:
            return Result

        else:
            return None

    def Search(self):

        try:
            Data_to_Cache = []
            Directory = General.Make_Directory(self.Concat_Plugin_Name)
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            Log_File = General.Logging(Directory, self.Concat_Plugin_Name)
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter("%(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()
            Email_Rep_API_Key = self.Load_Configuration()

            for Query in self.Query_List:

                if Common.Regex_Handler(Query, Type="Email"):
                    API = EmailRep(Email_Rep_API_Key)
                    JSON_Output_Response = API.query(Query)
                    Link = f"https://{self.Domain}/{Query}"
                    JSON_Object = Common.JSON_Handler(JSON_Output_Response)
                    JSON_Output_Response = JSON_Object.Dump_JSON()
                    JSON_Response = JSON_Object.To_JSON_Loads()

                    if JSON_Response["reputation"] != "none":
                        Table_JSON = {}

                        for Key, Value in JSON_Response.items():

                            if Key != "details":
                                Table_JSON[Key] = Value

                            else:

                                for Det_Key, Det_Val in JSON_Response["details"].items():
                                    Table_JSON[Det_Key] = Det_Val

                        Filter_JSON = [Table_JSON]
                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Concat_Plugin_Name)

                        if Query not in Cached_Data and Query not in Data_to_Cache:
                            Responses = Common.Request_Handler(Link, Filter=True, Host=f"https://{self.Domain}")
                            Filtered_Response = Responses["Filtered"]
                            Title = f"Email Reputation | {Query}"
                            Main_File = General.Main_File_Create(Directory, self.Concat_Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Concat_Plugin_Name, Filtered_Response, Title, self.The_File_Extensions["Query"])

                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], Link, Title, self.Concat_Plugin_Name)
                                Data_to_Cache.append(Link)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")