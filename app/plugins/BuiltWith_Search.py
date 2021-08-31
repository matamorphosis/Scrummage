#!/usr/bin/env python3
import plugins.common.General as General, plugins.common.Common as Common, os, logging, json
from builtwith import builtwith

class Plugin_Search:

    def __init__(self, Query_List, Task_ID):
        self.Plugin_Name = "BuiltWith"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "builtwith.com"
        self.Result_Type = "Web Application Architecture"

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
                URL_Components = Common.Regex_Handler(Query, Type="URL", Get_URL_Components=True)

                if URL_Components:
                    BW_Info = builtwith(Query)

                    if BW_Info:
                        BW_JSON_Output = Common.JSON_Handler(BW_Info).Dump_JSON()
                        Query_Domain = URL_Components["Body"] + URL_Components["Extension"]
                        Title = f"{self.Plugin_Name} | {Query_Domain}"
                        Main_File = General.Main_File_Create(Directory, self.Plugin_Name, BW_JSON_Output, Query_Domain, self.The_File_Extensions["Main"])
                        BW_Search_URL = f"https://{self.Domain}/{Query_Domain}"
                        Responses = Common.Request_Handler(BW_Search_URL, Filter=True, Host=f"https://{self.Domain}")
                        Response = Responses["Filtered"]
                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                        if BW_Search_URL not in Cached_Data and BW_Search_URL not in Data_to_Cache:
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Response, Query, self.The_File_Extensions['Query'])

                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], BW_Search_URL, Title, self.Plugin_Name.lower())
                                Data_to_Cache.append(BW_Search_URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                    else:
                        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to get result for provided query.")

                else:
                    logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid query provided.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")