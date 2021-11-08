#!/usr/bin/env python3
import logging, os, plugins.common.General as General, plugins.common.Common as Common
from googleapiclient.discovery import build

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Limit=10):
        self.Plugin_Name = "Google"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "google.com"
        self.Result_Type = "Search Result"
        self.Limit = General.Get_Limit(Limit)

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Plugin_Name.lower(), Details_to_Load=["cx", "application_name", "application_version", "developer_key"])

        if Result:
            return Result

        else:
            return None

    def Search(self):

        try:

            def Recursive_Dict_Check(Items, Dict_to_Check):

                try:

                    for Item in Items:

                        if Item in Dict_to_Check:
                            Dict_to_Check = Dict_to_Check[Item]

                        else:
                            return False

                    return Dict_to_Check

                except:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")

            Data_to_Cache = []
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler(os.path.join(Directory, General.Logging(Directory, self.Plugin_Name)), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Google_Details = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            if int(self.Limit) > 100:
                logging.fatal(f"{Common.Date()} - {self.Logging_Plugin_Name} - This plugin does not support limits over 100.")
                return None

            for Query in self.Query_List:
                Current_Start = 1
                Current_Step = 0

                while Current_Start <= int(self.Limit):
                    Service = build("customsearch", Google_Details[2], developerKey=Google_Details[3], cache_discovery=False)
                    CSE_Response = Service.cse().list(q=Query, cx=Google_Details[0], start=Current_Start, num=10).execute()
                    JSON_Object = Common.JSON_Handler(CSE_Response)
                    CSE_JSON_Output_Response = JSON_Object.Dump_JSON()
                    CSE_JSON_Response = JSON_Object.To_JSON_Loads()
                    Output_Name = f"{Query}-{str(Current_Start)}"
                    Main_File = General.Main_File_Create(Directory, self.Plugin_Name, CSE_JSON_Output_Response, Output_Name, self.The_File_Extensions["Main"])
                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())

                    if 'items' in CSE_JSON_Response:

                        for Google_Item_Line in CSE_JSON_Response['items']:

                            try:

                                if 'link' in Google_Item_Line and 'title' in Google_Item_Line:
                                    Google_Item_URL = Google_Item_Line['link']
                                    Title = f"{self.Plugin_Name} | " + Google_Item_Line['title']

                                    if Google_Item_URL not in Cached_Data and Google_Item_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                                        Path_Regex = Common.Regex_Handler(Google_Item_URL, Type="URL_Wild")

                                        if Path_Regex:
                                            Google_Item_Response = Common.Request_Handler(Google_Item_URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True)

                                            for Number in reversed(range(2, 7)):

                                                if Path_Regex.group(Number):
                                                    Output_Path = str(Path_Regex.group(Number).replace("/", "-"))
                                                    break

                                            Output_file = General.Create_Query_Results_Output_File(Directory, Output_Name, self.Plugin_Name, Google_Item_Response, Output_Path, self.The_File_Extensions["Query"])

                                            if Output_file:
                                                Output_Connections.Output([Main_File, Output_file], Google_Item_URL, Title, self.Plugin_Name.lower())
                                                Data_to_Cache.append(Google_Item_URL)

                                            else:
                                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                            Current_Step += 1

                                        else:
                                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regular expression.")

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid response.")

                            except Exception as e:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")

                        Current_Start += 10

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - No results found.")
                        break

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")
