#!/usr/bin/env python3
import os, logging, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List: list = list(), Task_ID: str = str(), Limit: int = 10):
        self.Plugin_Name: str = "Google Play Store"
        self.Concat_Plugin_Name: str = "playstore"
        self.Logging_Plugin_Name: str = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain: str = "play.google.com"
        self.Result_Type: str = "Application"
        self.Limit = General.Get_Limit(Limit)

    def Search(self):

        try:
            Data_to_Cache: list = list()
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

                try:
                    body = {"f.req": f'''[[["lGYRle","[[[],[[10,[10,50]],true,null,[96,27,4,8,57,30,110,11,16,49,1,3,9,12,104,55,56,51,10,34,31,77,145],[null,null,null,[[[[7,31],[[1,52,43,112,92,58,69,31,19,96,103]]]]]]],[\\"{Query}\\"],7,[null,1]]]",null,"2"]]]'''}
                    Play_Store_Response = Common.Request_Handler(url=f"https://{self.Domain}/_/PlayStoreUi/data/batchexecute", method="POST", Data=body)
                    Play_Store_Response = Play_Store_Response.replace(')]}\'\n\n', "").replace("\\\\u003d", "=")
                    JSON_Object = Common.JSON_Handler(Play_Store_Response)
                    Play_Store_Response_JSON = JSON_Object.To_JSON_Loads()
                    Play_Store_Response_JSON = JSON_Object.Dump_JSON()
                    Main_File = General.Main_File_Create(Directory, self.Plugin_Name, Play_Store_Response_JSON, Query, self.The_File_Extensions["Main"])
                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Concat_Plugin_Name)
                    Win_Store_Regex = Common.Regex_Handler(Play_Store_Response, Custom_Regex=r"(\/store\/apps\/details\?id\\\\([\w\d\.]+))\\\"", Findall=True)
                    Current_Step = 0

                    for Result, Item in Win_Store_Regex:
                        Result = Result.replace("\\\\u003d", "=")
                        Result_URL = f"https://{self.Domain}{Result}"
                        Item = Item.replace("u003d", str())
                        Title = f"Play Store | {Item}"
                        
                        if Result_URL not in Cached_Data and Result_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                            Play_Store_Responses = Common.Request_Handler(url=Result_URL, Filter=True, Host=f"https://{self.Domain}")
                            Play_Store_Response = Play_Store_Responses["Filtered"]
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Play_Store_Response, Item, self.The_File_Extensions["Query"])

                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], Result_URL, Title, self.Concat_Plugin_Name)
                                Data_to_Cache.append(Result_URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                            Current_Step += 1

                except:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to get results, this may be due to the query provided.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")