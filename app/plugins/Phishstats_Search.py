#!/usr/bin/env python3
import logging, os, socket, plugins.common.General as General, plugins.common.Common as Common
from urllib.parse import urlparse

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Limit=10):
        self.Plugin_Name = "Phishstats"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "phishstats.info"
        self.Result_Type = "Phishing"
        self.Limit = General.Get_Limit(Limit)

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
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                try:
                    Pull_URL = f"https://{self.Domain}:2096/api/phishing?_where=(url,like,~{Query}~)&_sort=-id&_size={self.Limit}"
                    JSON_Object = Common.JSON_Handler(Common.Request_Handler(Pull_URL))
                    Results = JSON_Object.To_JSON_Loads()
                    Indented_Results = JSON_Object.Dump_JSON()
                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Plugin_Name.lower())
                    Main_File = General.Main_File_Create(Directory, self.Plugin_Name, Indented_Results, Query, self.The_File_Extensions["Main"])

                    for Result in Results:
                        Current_Link = Result["url"]
                        Current_Domain = urlparse(Current_Link).netloc
                        Current_Title = Result["title"]

                        try:
                            Response = socket.gethostbyname(Current_Domain)

                        except:
                            logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to resolve hostname {Current_Domain} to an IP address. Skipping.")
                            Response = None

                        if Response:
                            Current_Result = Common.Request_Handler(Current_Link, Filter=True, Risky_Plugin=True, Host=Current_Link, Certificate_Verification=False)
                            Current_Result_Filtered = Current_Result["Filtered"]
                            Response_Regex = Common.Regex_Handler(Current_Result, Custom_Regex=r"\<title\>([^\<\>]+)\<\/title\>")
                            Output_file_Query = Query.replace(" ", "-")

                            if Current_Link not in Cached_Data and Current_Link not in Data_to_Cache:
                                Output_file = General.Create_Query_Results_Output_File(Directory, Output_file_Query, self.Plugin_Name, Current_Result_Filtered, Current_Domain, self.The_File_Extensions["Query"])

                                if Output_file:

                                    if Response_Regex:
                                        Current_Title = Response_Regex.group(1)
                                        Current_Title = Current_Title.strip()
                                        Output_Connections.Output([Main_File, Output_file], Current_Link, Current_Title, self.Plugin_Name.lower())

                                    else:

                                        if not "Phishstats" in Current_Title:
                                            Output_Connections.Output([Main_File, Output_file], Current_Link, Current_Title, self.Plugin_Name.lower())

                                        else:
                                            Output_Connections.Output([Main_File, Output_file], Current_Link, General.Get_Title(Current_Link), self.Plugin_Name.lower())

                                    Data_to_Cache.append(Current_Link)

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to resolve DNS, this link probably isn't live.")

                except:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to make request.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")