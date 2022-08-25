#!/usr/bin/env python3
import logging, os, plugins.common.General as General, plugins.common.Common as Common, json
from ebaysdk.finding import Connection

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str(), Limit: int = 10):
        self.Plugin_Name: str = "Ebay"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain: str = "ebay.com"
        self.Result_Type: str = "Search Result"
        self.Limit = General.Get_Limit(Limit)

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Plugin_Name.lower(), Details_to_Load=["access_key"])

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
            Ebay_API_Key = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                try:
                    API_Request = Connection(appid=Ebay_API_Key, config_file=None)
                    API_Response = API_Request.execute('findItemsAdvanced', {'keywords': Query})
                    JSON_Output_Response = Common.JSON_Handler(API_Response.dict()).Dump_JSON()
                    JSON_Object = Common.JSON_Handler(API_Response.dict())
                    JSON_Response = JSON_Object.Dump_JSON(Indentation=0, Sort=False)
                    JSON_Response = JSON_Object.To_JSON_Loads()
                    Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])

                    if JSON_Response["ack"] == "Success":
                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())
                        Current_Step = 0

                        for JSON_Line in JSON_Response['searchResult']['item']:
                            Ebay_Item_URL = JSON_Line['viewItemURL']
                            Title: str = "Ebay | " + General.Get_Title(Ebay_Item_URL)

                            if Ebay_Item_URL not in Cached_Data and Ebay_Item_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                                Ebay_Item_Regex = Common.Regex_Handler(Ebay_Item_URL, Custom_Regex=r"https\:\/\/www\.ebay\.com\/itm\/([\w\d\-]+)\-\/\d+")
                                Ebay_Item_Responses = Common.Request_Handler(url=Ebay_Item_URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{self.Domain}")
                                Ebay_Item_Response = Ebay_Item_Responses["Filtered"]
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Ebay_Item_Response, Ebay_Item_Regex.group(1).rstrip("-"), self.The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections.Output([Main_File, Output_file], Ebay_Item_URL, Title, self.Plugin_Name.lower())
                                    Data_to_Cache.append(Ebay_Item_URL)

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                Current_Step += 1

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - No results found.")

                except:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to make API call.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")