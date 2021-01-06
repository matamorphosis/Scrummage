#!/usr/bin/env python3
# Version 2 - Moved away from instagram_explore library onto the intragramy library
import json, requests, os, logging, plugins.common.General as General
from collections import namedtuple

Plugin_Name = "Instagram"
The_File_Extensions = {"Main": ".json", "Query": ".html"}
InstagramExploreResponse = namedtuple('InstagramExploreResponse', 'data cursor')
Domain = "instagram.com"

def Search(Query_List, Task_ID, Type, **kwargs):

    # try:
    Data_to_Cache = []
    Directory = General.Make_Directory(Plugin_Name.lower())
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    Log_File = General.Logging(Directory, Plugin_Name.lower())
    handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    Cached_Data = General.Get_Cache(Directory, Plugin_Name)
    Query_List = General.Convert_to_List(Query_List)
    Limit = General.Get_Limit(kwargs)

    for Query in Query_List:

        if Type == "User":
            from instagramy import InstagramUser
            Local_Plugin_Name = Plugin_Name + "-" + Type
            CSE_Response = InstagramUser(Query)
            CSE_JSON_Output_Response = json.dumps(vars(CSE_Response), indent=4, sort_keys=True)
            Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, CSE_JSON_Output_Response, Query, The_File_Extensions["Main"])

            if not CSE_Response.is_private:
                Posts = CSE_Response.posts
                Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Social Media - Person", Task_ID, Local_Plugin_Name.lower())
                Current_Step = 0

                for Post in Posts:
                    URL = Post['post_url']
                    Shortcode = URL.replace(f"https://www.{Domain}/p/", "").replace("/", "")
                    Title = "IG | " + General.Get_Title(URL, Requests=True)

                    if URL not in Cached_Data and URL not in Data_to_Cache and Current_Step < int(Limit):
                        Responses = General.Request_Handler(URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{Domain}")
                        Response = Responses["Filtered"]
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Response, Shortcode, The_File_Extensions["Query"])

                        if Output_file:
                            Output_Connections.Output([Main_File, Output_file], URL, Title, Plugin_Name.lower())
                            Data_to_Cache.append(URL)

                        else:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                        Current_Step += 1

            else:
                logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - The provided user's profile is private and cannot be scraped.")

        elif Type == "Tag":
            from instagramy import InstagramHashTag
            Local_Plugin_Name = Plugin_Name + "-" + Type
            CSE_Response = InstagramHashTag(Query)
            CSE_JSON_Output_Response = json.dumps(vars(CSE_Response), indent=4, sort_keys=True)
            Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, CSE_JSON_Output_Response, Query, The_File_Extensions["Main"])
            Posts = vars(CSE_Response)['tag_data']['edge_hashtag_to_media']['edges']
            Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Social Media - Person", Task_ID, Local_Plugin_Name.lower())
            Current_Step = 0

            for Post in Posts:
                Shortcode = Post['node']['shortcode']
                URL = f"https://www.{Domain}/p/{Shortcode}/"
                Title = "IG | " + General.Get_Title(URL, Requests=True)

                if URL not in Cached_Data and URL not in Data_to_Cache and Current_Step < int(Limit):
                    Responses = General.Request_Handler(URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{Domain}")
                    Response = Responses["Filtered"]
                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Response, Shortcode, The_File_Extensions["Query"])

                    if Output_file:
                        Output_Connections.Output([Main_File, Output_file], URL, Title, Plugin_Name.lower())
                        Data_to_Cache.append(URL)

                    else:
                        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                    Current_Step += 1

        elif Type == "Post":
            from instagramy import InstagramPost
            Local_Plugin_Name = Plugin_Name + "-" + Type
            CSE_Response = InstagramPost(Query)
            CSE_JSON_Output_Response = json.dumps(vars(CSE_Response), indent=4, sort_keys=True)
            Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, CSE_JSON_Output_Response, Query, The_File_Extensions["Main"])
            Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Social Media - Place", Task_ID, Local_Plugin_Name.lower())
            URL = CSE_Response.url
            Shortcode = URL.replace(f"https://www.{Domain}/p/", "").replace("/", "")
            Title = "IG | " + General.Get_Title(URL, Requests=True)

            if URL not in Cached_Data and URL not in Data_to_Cache:
                Responses = General.Request_Handler(URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{Domain}")
                Response = Responses["Filtered"]
                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Response, Shortcode, The_File_Extensions["Query"])

                if Output_file:
                    Output_Connections.Output([Main_File, Output_file], URL, Title, Plugin_Name.lower())
                    Data_to_Cache.append(URL)

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

        else:
            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid type provided.")

    General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    # except Exception as e:
    #     logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")