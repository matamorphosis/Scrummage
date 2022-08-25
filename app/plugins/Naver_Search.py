#!/usr/bin/env python3
import logging, os, urllib.parse, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str(), Limit: int = 10):
        self.Plugin_Name: str = "Naver"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain: str = "naver.com"
        self.Result_Type: str = "Search Result"
        self.Limit = General.Get_Limit(Limit)

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Plugin_Name.lower(), Details_to_Load=["client_id", "client_secret"])

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
            Naver_Details = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            if int(self.Limit) > 100:
                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - This plugin does not support limits over 100, setting limit to 100.")
                self.Limit = 100

            for Query in self.Query_List:
                URL_Query = urllib.parse.quote(Query)
                URL = f"https://openapi.{self.Domain}/v1/search/webkr.json?query={URL_Query}&display={str(self.Limit)}&sort=sim"
                Headers = {"X-Naver-Client-Id": Naver_Details[0], "X-Naver-Client-Secret": Naver_Details[1]}
                Naver_Response = Common.Request_Handler(url=URL, Optional_Headers=Headers)
                JSON_Object = Common.JSON_Handler(Naver_Response)
                JSON_Response = JSON_Object.To_JSON_Loads()
                JSON_Output_Response = JSON_Object.Dump_JSON()
                Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                if JSON_Response.get('items'):

                    for Naver_Item_Link in JSON_Response['items']:

                        try:

                            if 'title' in Naver_Item_Link and 'link' in Naver_Item_Link:
                                Naver_URL = Naver_Item_Link['link']
                                Title = f"{self.Plugin_Name} | {Naver_Item_Link['title']}"

                                if Naver_URL not in Cached_Data and Naver_URL not in Data_to_Cache:
                                    Naver_Item_Responses = Common.Request_Handler(url=Naver_URL, Filter=True, Host=f"https://www.{self.Domain}")
                                    Naver_Item_Response = Naver_Item_Responses["Filtered"]
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Naver_Item_Response, Naver_URL, self.The_File_Extensions["Query"])

                                    if Output_file:
                                        Output_Connections.Output([Main_File, Output_file], Naver_URL, Title, self.Plugin_Name.lower())
                                        Data_to_Cache.append(Naver_URL)

                                    else:
                                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        except Exception as e:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - No results found.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")