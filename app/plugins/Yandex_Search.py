#!/usr/bin/env python3
import logging, os, xmltodict, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Limit=10):
        self.Plugin_Name = "Yandex"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "yandex.com"
        self.Result_Type = "Search Result"
        self.Limit = General.Get_Limit(Limit)

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Plugin_Name.lower(), Details_to_Load=["username", "api_key"])

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
            Log_File = General.Logging(Directory, self.Plugin_Name.lower())
            handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter("%(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            Yandex_Details = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:
                Yandex_Response = Common.Request_Handler(f"https://{self.Domain}/search/xml?user={Yandex_Details[0]}&key={Yandex_Details[1]}&query={Query}&l10n=en&sortby=rlv&filter=none&maxpassages=five&groupby=attr% 3D% 22% 22.mode% 3Dflat.groups-on-page% 3D{str(self.Limit)}.docs-in-group% 3D1")
                JSON_Response = xmltodict.parse(Yandex_Response)
                JSON_Output_Response = Common.JSON_Handler(JSON_Response).Dump_JSON()
                Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())
                New_JSON_Response = Recursive_Dict_Check(["yandexsearch", "response", "results", "grouping", "group"], JSON_Response)
                print(JSON_Response)

                if New_JSON_Response:

                    for Yandex_Item_Line in New_JSON_Response:

                        try:

                            if Recursive_Dict_Check(["doc", "url"], Yandex_Item_Line):
                                Yandex_Item_Line = Yandex_Item_Line['doc']
                                Yandex_URL = Yandex_Item_Line['url']
                                Title = Recursive_Dict_Check(["title", "#text"], JSON_Response)

                                if Title:
                                    Title = f"Yandex | {Title}"

                                else:
                                    Title = General.Get_Title(Yandex_URL)
                                    Title = f"Yandex | {Title}"

                                if Yandex_URL not in Cached_Data and Yandex_URL not in Data_to_Cache:
                                    Yandex_Item_Responses = Common.Request_Handler(Yandex_URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://{self.Domain}")
                                    Yandex_Item_Response = Yandex_Item_Responses["Filtered"]
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Yandex_Item_Response, Yandex_URL, self.The_File_Extensions["Query"])

                                    if Output_file:
                                        Output_Connections.Output([Main_File, Output_file], Yandex_URL, Title, self.Plugin_Name.lower())
                                        Data_to_Cache.append(Yandex_URL)

                                    else:
                                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                        except Exception as e:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - No results found.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")