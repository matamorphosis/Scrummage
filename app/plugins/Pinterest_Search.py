#!/usr/bin/env python3
import plugins.common.General as General, plugins.common.Common as Common, logging, os

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Type, Limit=10):
        self.Plugin_Name = "Pinterest"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "pinterest.com"
        self.Type = Type
        self.Limit = General.Get_Limit(Limit)

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")

        try:

            with open(Common.Set_Configuration_File()) as JSON_File:
                Configuration_Data = Common.JSON_Handler(JSON_File).To_JSON_Load()
                Pinterest_Details = Configuration_Data["inputs"][self.Plugin_Name.lower()]

                if Pinterest_Details['oauth_token']:
                    return Pinterest_Details['oauth_token']

                else:
                    return None

        except:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to load location details.")

    def Search(self):

        try:
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
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                if self.Type == "pin":
                    Local_Plugin_Name = self.Plugin_Name + " " + self.Type
                    Request_URL = f"https://api.{self.Domain}/v1/pins/{Query}/?access_token=" + Load_Configuration() + "&fields=id%2Clink%2Cnote%2Curl%2Ccreated_at%2Cmedia%2Coriginal_link%2Cmetadata%2Ccounts%2Ccolor%2Cboard%2Cattribution"
                    Search_Response = Common.Request_Handler(Request_URL)
                    JSON_Object = Common.JSON_Handler(Search_Response)
                    Search_Response = JSON_Object.To_JSON_Loads()

                    if Search_Response.get('message') != "You have exceeded your rate limit. Try again later.":
                        JSON_Response = JSON_Object.Dump_JSON()
                        Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Response, Query, self.The_File_Extensions["Main"])
                        Result_Title = "Pinterest | " + Search_Response["data"]["metadata"]["link"]["title"]
                        Result_URL = Search_Response["data"]["url"]
                        Search_Result_Response = Common.Request_Handler(Result_URL)

                        if Result_URL not in Cached_Data and Result_URL not in Data_to_Cache:
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Search_Result_Response, Result_Title, self.The_File_Extensions["Query"])

                            if Output_file:
                                Output_Connections = General.Connections(Query, Local_Plugin_Name, self.Domain, "Social Media - Media", self.Task_ID, Local_Plugin_Name.lower())
                                Output_Connections.Output([Main_File, Output_file], Result_URL, Result_Title, self.Plugin_Name.lower())
                                Data_to_Cache.append(Result_URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                elif self.Type == "board":
                    Local_Plugin_Name = self.Plugin_Name + " " + self.Type
                    Request_URL = "https://api.pinterest.com/v1/boards/" + Query + "/pins/?access_token=" + Load_Configuration() + "&fields=id%2Clink%2Cnote%2Curl%2Coriginal_link%2Cmetadata%2Cmedia%2Cimage%2Ccreator%2Ccreated_at%2Ccounts%2Ccolor%2Cboard%2Cattribution&limit=" + str(self.Limit) + ""
                    Search_Response = Common.Request_Handler(Request_URL)
                    JSON_Object = Common.JSON_Handler(Search_Response)
                    Search_Response = JSON_Object.To_JSON_Loads()
                    
                    if Search_Response.get('message') != "You have exceeded your rate limit. Try again later.":
                        JSON_Response = JSON_Object.Dump_JSON()
                        Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Response, Query, self.The_File_Extensions["Main"])
                        Output_Connections = General.Connections(Query, Local_Plugin_Name, "pinterest.com", "Social Media - Page", self.Task_ID, Local_Plugin_Name.lower())
                        Current_Step = 0

                        for Response in Search_Response["data"]:
                            Result_Title = "Pinterest | " + Response["note"]
                            Result_URL = Response["url"]
                            Search_Result_Response = Common.Request_Handler(Result_URL)

                            if Result_URL not in Cached_Data and Result_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Search_Result_Response, Result_Title, self.The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections.Output([Main_File, Output_file], Result_URL, Result_Title, self.Plugin_Name.lower())
                                    Data_to_Cache.append(Result_URL)
                                    Current_Step += 1

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                    else:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")