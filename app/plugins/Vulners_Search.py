#!/usr/bin/env python3
import plugins.common.General as General, plugins.common.Common as Common, vulners, os, logging

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Limit=10):
        self.Plugin_Name = "Vulners"
        self.Unacceptable_Bulletins = ["advertisement", "kitsploit"]
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "vulners.com"
        self.Result_Type = "Exploit"
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
            handler = logging.FileHandler(os.path.join(Directory, General.Logging(Directory, self.Plugin_Name)), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:
                vulners_api = vulners.Vulners(api_key=Load_Configuration())
                Search_Response = vulners_api.search(Query, limit=int(self.Limit))
                JSON_Response = Common.JSON_Handler(Search_Response).Dump_JSON()
                Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Response, Query, self.The_File_Extensions["Main"])
                Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                for Search_Result in Search_Response:

                    if Search_Result["bulletinFamily"] not in self.Unacceptable_Bulletins:
                        Result_Title = Search_Result["title"]
                        Result_URL = Search_Result["vhref"]
                        Search_Result_Responses = Common.Request_Handler(Result_URL, Filter=True, Host=f"https://{self.Domain}")
                        Search_Result_Response = Search_Result_Responses["Filtered"]

                        if Result_URL not in Cached_Data and Result_URL not in Data_to_Cache:
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Search_Result_Response, Result_Title, self.The_File_Extensions["Query"])

                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], Result_URL, Result_Title, self.Plugin_Name.lower())
                                Data_to_Cache.append(Result_URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                    else:
                        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Skipping as bulletin type is not supported.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")