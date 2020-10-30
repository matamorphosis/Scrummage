#!/usr/bin/env python3
import json, requests, os, logging, instagram_explore, plugins.common.General as General
from collections import namedtuple

Plugin_Name = "Instagram"
The_File_Extensions = {"Main": ".json", "Query": ".html"}
InstagramExploreResponse = namedtuple('InstagramExploreResponse', 'data cursor')
Domain = "instagram.com"

def location(location_id, max_id=None):

    # The Instagram Explore libraries location function has an issue, this is a temporary work around.

    url = f"https://www.instagram.com/explore/locations/{location_id}/"
    payload = {'__a': '1'}

    if max_id is not None:
        payload['max_id'] = max_id

    try:
        res = requests.get(url, params=payload).json()
        body = res['graphql']['location']
        cursor = res['graphql']['location']['edge_location_to_media']['page_info']['end_cursor']

    except:
        raise

    return InstagramExploreResponse(data=body, cursor=cursor)

def Search(Query_List, Task_ID, Type, **kwargs):

    try:
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
                Local_Plugin_Name = Plugin_Name + "-" + Type
                CSE_Response = instagram_explore.user(Query)
                CSE_JSON_Output_Response = json.dumps(CSE_Response, indent=4, sort_keys=True)
                Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, CSE_JSON_Output_Response, Query, The_File_Extensions["Main"])
                Posts = CSE_Response[0]["edge_owner_to_timeline_media"]["edges"]
                Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Social Media - Person", Task_ID, Local_Plugin_Name.lower())
                Current_Step = 0

                for Post in Posts:
                    Shortcode = Post["node"]["shortcode"]
                    URL = f"https://www.{Domain}/p/{Shortcode}/"
                    Title = "IG | " + General.Get_Title(URL)

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

            elif Type == "Tag":
                Local_Plugin_Name = Plugin_Name + "-" + Type
                CSE_Response = instagram_explore.tag(Query)
                CSE_JSON_Output_Response = json.dumps(CSE_Response, indent=4, sort_keys=True)
                Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, CSE_JSON_Output_Response, Query, The_File_Extensions["Main"])
                Posts = CSE_Response[0]["edge_hashtag_to_media"]["edges"]
                Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Social Media - Person", Task_ID, Local_Plugin_Name.lower())
                Current_Step = 0

                for Post in Posts:
                    Shortcode = Post["node"]["shortcode"]
                    URL = f"https://www.{Domain}/p/{Shortcode}/"
                    Title = "IG | " + General.Get_Title(URL)

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

            elif Type == "Location":
                Local_Plugin_Name = Plugin_Name + "-" + Type
                CSE_Response = location(Query)
                CSE_JSON_Output_Response = json.dumps(CSE_Response, indent=4, sort_keys=True)
                Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, CSE_JSON_Output_Response, Query, The_File_Extensions["Main"])
                Posts = CSE_Response[0]["edge_location_to_media"]["edges"]
                Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Social Media - Place", Task_ID, Local_Plugin_Name.lower())
                Current_Step = 0

                for Post in Posts:
                    Shortcode = Post["node"]["shortcode"]
                    URL = f"https://www.{Domain}/p/{Shortcode}/"
                    Title = "IG | " + General.Get_Title(URL)

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

            elif Type == "Media":
                Local_Plugin_Name = Plugin_Name + "-" + Type
                CSE_Response = instagram_explore.media(Query)

                if CSE_Response:
                    CSE_JSON_Output_Response = json.dumps(CSE_Response, indent=4, sort_keys=True)
                    Main_File = General.Main_File_Create(Directory, Local_Plugin_Name, CSE_JSON_Output_Response, Query, The_File_Extensions["Main"])
                    URL = f"https://www.{Domain}/p/{Query}/"
                    Title = "IG | " + General.Get_Title(URL)

                    if URL not in Cached_Data and URL not in Data_to_Cache:
                        Responses = General.Request_Handler(URL, Application_JSON_CT=True, Accept_XML=True, Accept_Language_EN_US=True, Filter=True, Host=f"https://www.{Domain}")
                        Response = Responses["Filtered"]
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Local_Plugin_Name, Response, Shortcode, The_File_Extensions["Query"])

                        if Output_file:
                            Output_Connections = General.Connections(Query, Local_Plugin_Name, Domain, "Social Media - Media", Task_ID, Local_Plugin_Name.lower())
                            Output_Connections.Output([Main_File, Output_file], URL, Title, Plugin_Name.lower())
                            Data_to_Cache.append(URL)

                        else:
                            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid response.")

            else:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid type provided.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")