#!/usr/bin/env python3
import plugins.common.General as General, plugins.common.Common as Common, os, logging

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str()):
        self.Plugin_Name: str = "IPStack"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Main_Converted": ".html"}
        self.Domain: str = "ipstack.com"
        self.Result_Type: str = "IP Address Information"

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
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                if Common.Regex_Handler(Query, Type="IP"):
                    API_Key = self.Load_Configuration()
                    Search_Response = Common.Request_Handler(url=f"http://api.{self.Domain}/{Query}?access_key={API_Key}")
                    JSON_Object = Common.JSON_Handler(Search_Response)
                    JSON_Response = JSON_Object.To_JSON_Loads()
                    JSON_Output_Response = JSON_Object.Dump_JSON()
                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                    if Query not in Cached_Data and Query not in Data_to_Cache:
                        Result_URL = f"https://{self.Domain}/?{Query}"
                        Title = f"{self.Plugin_Name} | {Common.Fang().Defang(Query)}"
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, JSON_Output_Response, Title, self.The_File_Extensions["Main"])
                        HTML_Output_File_Data = General.JSONDict_to_HTML(JSON_Response, JSON_Output_Response, f"{self.Plugin_Name} Query {Query}")
                        HTML_Output_File = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, HTML_Output_File_Data, Title.replace(" ", "-"), self.The_File_Extensions["Main_Converted"])

                        if Output_file:
                            Output_Connections.Output([Output_file, HTML_Output_File], Result_URL, Title, self.Plugin_Name.lower())
                            Data_to_Cache.append(Result_URL)

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regex.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")