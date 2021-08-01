#!/usr/bin/env python3
# Version 2 - Moved away from instagram_explore library onto the intragramy library
import requests, os, logging, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Type, Limit=10):
        self.Plugin_Name = "Instagram"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "instagram.com"
        self.Type = Type
        self.Limit = General.Get_Limit(Limit)

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

                if self.Type == "User":
                    from instagramy import InstagramUser
                    Local_Plugin_Name = self.Plugin_Name + " " + self.Type
                    CSE_Response = InstagramUser(Query)
                    CSE_JSON_Output_Response = Common.JSON_Handler(vars(CSE_Response)).Dump_JSON()
                    Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, CSE_JSON_Output_Response, Query, self.The_File_Extensions["Main"])

                    if not CSE_Response.is_private:
                        Posts = CSE_Response.posts
                        Output_Connections = General.Connections(Query, Local_Plugin_Name, self.Domain, "Social Media - Person", self.Task_ID, Local_Plugin_Name.lower())
                        Current_Step = 0

                        for Post in Posts:
                            URL = Post['post_url']
                            Shortcode = URL.replace(f"https://www.{self.Domain}/p/", "").replace("/", "")
                            Title = "IG | " + General.Get_Title(URL, Requests=True)

                            if URL not in Cached_Data and URL not in Data_to_Cache and Current_Step < int(self.Limit):
                                Responses = Common.Request_Handler(URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{self.Domain}")
                                Response = Responses["Filtered"]
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Response, Shortcode, self.The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections.Output([Main_File, Output_file], URL, Title, self.Plugin_Name.lower())
                                    Data_to_Cache.append(URL)

                                else:
                                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                                Current_Step += 1

                    else:
                        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - The provided user's profile is private and cannot be scraped.")

                elif self.Type == "Tag":
                    from instagramy import InstagramHashTag
                    Local_Plugin_Name = self.Plugin_Name + " " + self.Type
                    CSE_Response = InstagramHashTag(Query)
                    CSE_JSON_Output_Response = Common.JSON_Handler(vars(CSE_Response)).Dump_JSON()
                    Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, CSE_JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                    Posts = vars(CSE_Response)['tag_data']['edge_hashtag_to_media']['edges']
                    Output_Connections = General.Connections(Query, Local_Plugin_Name, self.Domain, "Social Media - Person", self.Task_ID, Local_Plugin_Name.lower())
                    Current_Step = 0

                    for Post in Posts:
                        Shortcode = Post['node']['shortcode']
                        URL = f"https://www.{self.Domain}/p/{Shortcode}/"
                        Title = "IG | " + General.Get_Title(URL, Requests=True)

                        if URL not in Cached_Data and URL not in Data_to_Cache and Current_Step < int(self.Limit):
                            Responses = Common.Request_Handler(URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{self.Domain}")
                            Response = Responses["Filtered"]
                            Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Response, Shortcode, self.The_File_Extensions["Query"])

                            if Output_file:
                                Output_Connections.Output([Main_File, Output_file], URL, Title, self.Plugin_Name.lower())
                                Data_to_Cache.append(URL)

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                            Current_Step += 1

                elif self.Type == "Post":
                    from instagramy import InstagramPost
                    Local_Plugin_Name = self.Plugin_Name + " " + self.Type
                    CSE_Response = InstagramPost(Query)
                    CSE_JSON_Output_Response = Common.JSON_Handler(vars(CSE_Response)).Dump_JSON()
                    Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, CSE_JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                    Output_Connections = General.Connections(Query, Local_Plugin_Name, self.Domain, "Social Media - Place", self.Task_ID, Local_Plugin_Name.lower())
                    URL = CSE_Response.url
                    Shortcode = URL.replace(f"https://www.{self.Domain}/p/", "").replace("/", "")
                    Title = "IG | " + General.Get_Title(URL, Requests=True)

                    if URL not in Cached_Data and URL not in Data_to_Cache:
                        Responses = Common.Request_Handler(URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{self.Domain}")
                        Response = Responses["Filtered"]
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Response, Shortcode, self.The_File_Extensions["Query"])

                        if Output_file:
                            Output_Connections.Output([Main_File, Output_file], URL, Title, self.Plugin_Name.lower())
                            Data_to_Cache.append(URL)

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid Type provided.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")