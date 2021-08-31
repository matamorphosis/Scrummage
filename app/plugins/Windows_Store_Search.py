#!/usr/bin/env python3
import logging, os, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Limit=10):
        self.Plugin_Name = "Windows Store"
        self.Concat_Plugin_Name = "windowsstore"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extension = ".html"
        self.Domain = "microsoft.com"
        self.Result_Type = "Application"
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
            Data_to_Cache = []
            Directory = General.Make_Directory(self.Concat_Plugin_Name)
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler(os.path.join(Directory, General.Logging(Directory, self.Concat_Plugin_Name)), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            Location = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:
                Main_URL = f"https://www.{self.Domain}/en-{Location}/search?q={Query}"
                Win_Store_Response = Common.Request_Handler(Main_URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True)
                Main_File = General.Main_File_Create(Directory, self.Plugin_Name, Win_Store_Response, Query, self.The_File_Extension)
                Win_Store_Regex = Common.Regex_Handler(Win_Store_Response, Custom_Regex=r"\/en\-au\/p\/([\w\-]+)\/([\w\d]+)", Findall=True)
                Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, self.Result_Type, self.Task_ID, self.Concat_Plugin_Name)

                if Win_Store_Regex:
                    Current_Step = 0

                    for Regex_Group_1, Regex_Group_2 in Win_Store_Regex:
                        Item_URL = f"https://www.microsoft.com/en-au/p/{Regex_Group_1}/{Regex_Group_2}"
                        Win_Store_Responses = Common.Request_Handler(Item_URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{self.Domain}")
                        Win_Store_Response = Win_Store_Responses["Filtered"]
                        Title = f"{self.Plugin_Name} | " + General.Get_Title(Item_URL)

                        if Item_URL not in Cached_Data and Item_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Win_Store_Response, Regex_Group_1, self.The_File_Extension)

                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], Item_URL, Title, self.Concat_Plugin_Name)
                                Data_to_Cache.append(Item_URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                            Current_Step += 1

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to match regular expression.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")