#!/usr/bin/env python3
import logging, os, urllib.parse, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str(), Limit: int = 10):
        self.Plugin_Name: str = "Apple Store"
        self.Concat_Plugin_Name: str = "applestore"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain: str = "itunes.apple.com"
        self.Result_Type: str = "Application"
        self.Limit = General.Get_Limit(Limit)

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Location=True, Object="general", Details_to_Load=["location"])

        if Result:
            return Result

        else:
            return None

    def Search(self):

        try:
            Data_to_Cache: list = list()
            Directory = General.Make_Directory(self.Concat_Plugin_Name)
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler(os.path.join(Directory, General.Logging(Directory, self.Plugin_Name)), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Location = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                try:
                    Request_Query = urllib.parse.quote(Query)
                    Main_URL = f"http://{self.Domain}/search?term={Request_Query}&country={Location}&entity=software&limit={str(self.Limit)}"
                    Response = Common.Request_Handler(url=Main_URL)

                except:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to make request, are you connected to the internet?")
                    break

                JSON_Object = Common.JSON_Handler(Response)
                JSON_Response = JSON_Object.To_JSON_Loads()
                Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Object.Dump_JSON(), Query, self.The_File_Extensions["Main"])

                if 'resultCount' in JSON_Response:

                    if JSON_Response['resultCount'] > 0:
                        Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Concat_Plugin_Name)

                        for JSON_Resp_Item in JSON_Response['results']:
                            JSON_Object_Responses = Common.Request_Handler(url=JSON_Resp_Item['artistViewUrl'], Filter=True, Host=f"https://{self.Domain}")
                            JSON_Object_Response = JSON_Object_Responses["Filtered"]

                            if JSON_Resp_Item['artistViewUrl'] not in Cached_Data and JSON_Resp_Item['artistViewUrl'] not in Data_to_Cache:
                                Apple_Store_Regex = Common.Regex_Handler(JSON_Resp_Item['artistViewUrl'], Custom_Regex=r"https\:\/\/apps\.apple\.com\/" + rf"{Location}" + r"\/developer\/[\w\d\-]+\/(id[\d]{9,10})\?.+")

                                if Apple_Store_Regex:
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, JSON_Object_Response, Apple_Store_Regex.group(1), self.The_File_Extensions["Query"])

                                    if Output_file:
                                        Output_Connections.Output([Main_File, Output_file], JSON_Resp_Item['artistViewUrl'], General.Get_Title(JSON_Resp_Item['artistViewUrl']), self.Concat_Plugin_Name)
                                        Data_to_Cache.append(JSON_Resp_Item['artistViewUrl'])

                                    else:
                                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid value provided, value not greater than 0.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid value.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")