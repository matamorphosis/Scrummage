#!/usr/bin/env python3
import plugins.common.General as General, plugins.common.Common as Common, os, logging

class Plugin_Search:

    def __init__(self, Query_List, Task_ID):
        self.Plugin_Name = "Email Verification"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Main_Converted": ".html"}
        self.Concat_Plugin_Name = "emailverify"
        self.Domain = "verify-email.org"
        self.Result_Type = "Email Information"

    def Search(self):

        try:
            Data_to_Cache = []
            Directory = General.Make_Directory(self.Concat_Plugin_Name)
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler(os.path.join(Directory, General.Logging(Directory, self.Concat_Plugin_Name)), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                if Common.Regex_Handler(Query, Type="Email"):
                    Link = f"https://{self.Domain}/home/verify-as-guest/{Query}"
                    JSON_Response = Common.Request_Handler(Link)
                    JSON_Object = Common.JSON_Handler(JSON_Response)

                    if JSON_Object.Is_JSON():
                        JSON_Response = JSON_Object.To_JSON_Loads()
                        JSON_Output_Response = JSON_Object.Dump_JSON()
                        Table_JSON = {}

                        for Key, Value in JSON_Response.items():

                            if Key != "response":
                                Table_JSON[Key] = Value

                            else:

                                for Det_Key, Det_Val in JSON_Response["response"].items():
                                    Table_JSON[Det_Key] = Det_Val

                        Filter_JSON = [Table_JSON]
                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Concat_Plugin_Name)

                        if Query not in Cached_Data and Query not in Data_to_Cache:
                            Title = f"{self.Plugin_Name} | {Query}"
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Concat_Plugin_Name, JSON_Output_Response, Title, self.The_File_Extensions["Main"])
                            HTML_Output_File_Data = General.JSONDict_to_HTML(Filter_JSON, JSON_Output_Response, f"{self.Plugin_Name} Query {Query}")
                            HTML_Output_File = General.Create_Query_Results_Output_File(Directory, Query, self.Concat_Plugin_Name, HTML_Output_File_Data, Title, self.The_File_Extensions["Main_Converted"])

                            if Output_file and HTML_Output_File:
                                Output_Connections.Output([Output_file, HTML_Output_File], Link, Title, self.Concat_Plugin_Name)
                                Data_to_Cache.append(Link)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid response type.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regex.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")