#!/usr/bin/env python3
import logging, os, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Limit=10):
        self.Plugin_Name = "IntelligenceX"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "intelx.io"
        self.Result_Type = "Data Leakage"
        self.Limit = General.Get_Limit(Limit)

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Plugin_Name.lower(), Details_to_Load=["api_key"])

        if Result:
            return Result

        else:
            return None

    def Search(self):

        try:
            Data_to_Cache = []
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            Log_File = General.Logging(Directory, self.Plugin_Name.lower())
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter("%(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            IX_Access_Token = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:
                Data = {"term": Query, "buckets": [], "lookuplevel": 0, "maxresults": self.Limit, "timeout": 0, "datefrom": "", "dateto": "", "sort": 2, "media": 0, "terminate": []}
                IX_Response = Common.Request_Handler(f"https://2.{self.Domain}/intelligent/search?k={IX_Access_Token}", Method="POST", JSON_Data=Data)
                JSON_Object = Common.JSON_Handler(IX_Response)
                JSON_Response = JSON_Object.To_JSON_Loads()
                JSON_Output_Response = JSON_Object.Dump_JSON()
                Main_File_1 = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query + "-Request-1", self.The_File_Extensions["Main"])
                

                if "id" in JSON_Response:
                    Search_ID = JSON_Response["id"]
                    IX_Response = Common.Request_Handler(f"https://2.{self.Domain}/intelligent/search/result?k={IX_Access_Token}&id={Search_ID}")
                    JSON_Object = Common.JSON_Handler(IX_Response)
                    JSON_Response = JSON_Object.To_JSON_Loads()
                    JSON_Output_Response = JSON_Object.Dump_JSON()
                    Main_File_2 = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query + "-Request-2", self.The_File_Extensions["Main"])
                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                    if "records" in JSON_Response:

                        for IX_Item in JSON_Response["records"]:

                            if "systemid" in IX_Item and "name" in IX_Item:
                                IX_URL = f"https://{self.Domain}/?did=" + IX_Item['systemid']

                                if IX_Item["name"] != "":
                                    Title = f"IntelligenceX Data Leak | " + IX_Item["name"]

                                else:
                                    TItle = "IntelligenceX Data Leak | Untitled Document"

                                if IX_URL not in Cached_Data and IX_URL not in Data_to_Cache:
                                    IX_Item_Responses = Common.Request_Handler(IX_URL, Filter=True, Host=f"https://{self.Domain}")
                                    IX_Item_Response = IX_Item_Responses["Filtered"]
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, IX_Item_Response, IX_URL, self.The_File_Extensions["Query"])

                                    if Output_file:
                                        Output_Connections.Output([Main_File_1, Main_File_2, Output_file], IX_URL, Title, self.Plugin_Name.lower())
                                        Data_to_Cache.append(IX_URL)

                                    else:
                                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - No results found.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")