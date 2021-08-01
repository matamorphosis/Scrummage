#!/usr/bin/env python3
import requests, logging, os, plugins.common.General as General, plugins.common.Common as Common, flickr_api

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Limit=10):
        self.Plugin_Name = "Flickr"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "flickr.com"
        self.Limit = General.Get_Limit(Limit)

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Plugin_Name.lower(), Details_to_Load=["api_key", "api_secret"])

        if Result:
            return Result

        else:
            return None

    def Search(self):

        try:

            def Convert_to_JSON(Data):
                Data = str(Data)
                Flickr_Regex = Common.Regex_Handler(Data, Custom_Regex=r"\[(.+)\]")

                if Flickr_Regex:
                    New_Data = Flickr_Regex.group(1).replace("...", "").replace("id=b", "'id': ").replace("title=b", "'title': ").replace("(", "{").replace(")", "}").replace("\'}", "}").replace("}", "\'}")
                    New_Data = New_Data.replace("Photo", "")
                    New_Data = New_Data.replace("\'", "\"")
                    New_Data = f"[{New_Data}]"
                    JSON_Object = Common.JSON_Handler(New_Data)
                    New_Data = JSON_Object.To_JSON_Loads()
                    New_Data = JSON_Object.Dump_JSON()
                    return New_Data

                else:
                    return None

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

            try:
                Flickr_Details = self.Load_Configuration()
                flickr_api.set_keys(api_key=Flickr_Details[0], api_secret=Flickr_Details[1])

            except:
                logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to establish API identity.")

            for Query in self.Query_List:
                Email_Regex = Common.Regex_Handler(Query, Type="Email")

                if Email_Regex:

                    try:
                        User = flickr_api.Person.findByEmail(Query)
                        Photos = User.getPhotos()

                        if Photos:
                            Main_File = General.Main_File_Create(Directory, self.Plugin_Name, Convert_to_JSON(Photos), Query, self.The_File_Extensions["Main"])
                            Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, "Social Media - Media", self.Task_ID, self.Plugin_Name.lower())
                            Current_Step = 0

                            for Photo in Photos:
                                Photo_URL = f"https://www.{self.Domain}/photos/{Query}/{Photo['id']}"

                                if Photo_URL not in Cached_Data and Photo_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                                    Photo_Response = Common.Request_Handler(Photo_URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True)
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Photo_Response, Photo, self.The_File_Extensions["Query"])

                                    if Output_file:
                                        Output_Connections.Output([Main_File, Output_file], Photo_URL, General.Get_Title(Photo_URL), self.Plugin_Name.lower())
                                        Data_to_Cache.append(Photo_URL)

                                    else:
                                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                    Current_Step += 1

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - No photos found.")

                    except:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to make API call.")

                else:

                    try:
                        User = flickr_api.Person.findByUserName(Query)
                        Photos = User.getPhotos()

                        if Photos:
                            Main_File = General.Main_File_Create(Directory, self.Plugin_Name, Convert_to_JSON(Photos), Query, self.The_File_Extensions["Main"])
                            Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, "Data Leakage", self.Task_ID, self.Plugin_Name.lower())
                            Current_Step = 0

                            for Photo in Photos:
                                Photo_URL = f"https://www.{self.Domain}/photos/{Query}/{Photo['id']}"

                                if Photo_URL not in Cached_Data and Photo_URL not in Data_to_Cache and Current_Step < int(self.Limit):
                                    Photo_Response = Common.Request_Handler(Photo_URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True)
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, Photo_Response, str(Photo['id']), self.The_File_Extensions["Query"])

                                    if Output_file:
                                        Output_Connections.Output([Main_File, Output_file], Photo_URL, General.Get_Title(Photo_URL), self.Plugin_Name.lower())
                                        Data_to_Cache.append(Photo_URL)

                                    else:
                                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                    Current_Step += 1

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - No photos found.")

                    except:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to make API call.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")