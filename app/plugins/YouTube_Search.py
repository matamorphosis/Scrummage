#!/usr/bin/env python3
import plugins.common.General as General, plugins.common.Common as Common, os, logging
from googleapiclient import discovery

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Limit=10):
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Plugin_Name = "YouTube"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.Domain = "youtube.com"
        self.Result_Type = "Social Media - Media"
        self.Limit = General.Get_Limit(Limit)

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Plugin_Name.lower(), Details_to_Load=["developer_key", "application_name", "application_version"])

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
            YouTube_Details = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:
                YouTube_Handler = discovery.build(YouTube_Details[1], YouTube_Details[2], developerKey=YouTube_Details[0], cache_discovery=False)
                Search_Response = YouTube_Handler.search().list(q=Query, type='video', part='id,snippet', maxResults=self.Limit,).execute()
                JSON_Output_Response = Common.JSON_Handler(Search_Response.get('items', [])).Dump_JSON()
                Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                for Search_Result in Search_Response.get('items', []):
                    Full_Video_URL = f"https://www.{self.Domain}/watch?v=" + Search_Result['id']['videoId']
                    Search_Video_Responses = Common.Request_Handler(Full_Video_URL, Filter=True, Host=f"https://www.{self.Domain}")
                    Search_Video_Response = Search_Video_Responses["Filtered"]
                    Title = f"{self.Plugin_Name} | " + Search_Result['snippet']['title']

                    if Full_Video_URL not in Cached_Data and Full_Video_URL not in Data_to_Cache:
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Search_Video_Response, Search_Result['id']['videoId'], self.The_File_Extensions["Query"])

                        if Output_file:
                            Output_Connections.Output([Main_File, Output_file], Full_Video_URL, Title, self.Plugin_Name.lower())
                            Data_to_Cache.append(Full_Video_URL)

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")