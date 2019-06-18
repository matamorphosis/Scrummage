#!/usr/bin/env python3
import json, requests, instagram_explore, plugins.common.General as General
from collections import namedtuple

Plugin_Name = "Instagram"
The_File_Extension = ".html"
InstagramExploreResponse = namedtuple('InstagramExploreResponse', 'data cursor')

def location(location_id, max_id=None):

    # The Instagram Explore libraries location function has an issue, this is a temporary work around.

    url = "https://www.instagram.com/explore/locations/" + location_id + "/"
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
    Data_to_Cache = []
    Cached_Data = []

    if "Limit" in kwargs:

        if int(kwargs["Limit"]) > 0:
            Limit = kwargs["Limit"]

    else:
        Limit = 10

    Directory = General.Make_Directory(Plugin_Name.lower())
    General.Logging(Directory, Plugin_Name)
    Cached_Data = General.Get_Cache(Directory, Plugin_Name)

    if not Cached_Data:
        Cached_Data = []

    Query_List = General.Convert_to_List(Query_List)

    for Query in Query_List:

        if Type == "User":
            Local_Plugin_Name = Plugin_Name + "-" + Type
            CSE_Response = instagram_explore.user(Query)
            CSE_JSON_Output_Response = json.dumps(CSE_Response, indent=4, sort_keys=True)
            Output_file = General.Main_File_Create(Directory, Local_Plugin_Name, CSE_JSON_Output_Response, Query, ".json")
            Posts = CSE_Response[0]["edge_owner_to_timeline_media"]["edges"]
            Current_Step = 0

            for Post in Posts:
                Shortcode = Post["node"]["shortcode"]
                URL = "https://www.instagram.com/p/" + Shortcode + "/"

                if URL not in Cached_Data and URL not in Data_to_Cache and Current_Step < Limit:

                    if Output_file:
                        General.Connections(Output_file, Query, Plugin_Name, URL, "instagram.com", "Data Leakage", Task_ID, General.Get_Title(URL))

                Data_to_Cache.append(URL)
                Current_Step += 1

        elif Type == "Tag":
            Local_Plugin_Name = Plugin_Name + "-" + Type
            CSE_Response = instagram_explore.tag(Query)
            CSE_JSON_Output_Response = json.dumps(CSE_Response, indent=4, sort_keys=True)
            Output_file = General.Main_File_Create(Directory, Local_Plugin_Name, CSE_JSON_Output_Response, Query, ".json")
            Posts = CSE_Response[0]["edge_hashtag_to_media"]["edges"]
            Current_Step = 0

            for Post in Posts:
                Shortcode = Post["node"]["shortcode"]
                URL = "https://www.instagram.com/p/" + Shortcode + "/"

                if URL not in Cached_Data and URL not in Data_to_Cache and Current_Step < Limit:

                    if Output_file:
                        General.Connections(Output_file, Query, Plugin_Name, URL, "instagram.com", "Data Leakage", Task_ID, General.Get_Title(URL))

                Data_to_Cache.append(URL)
                Current_Step += 1

        elif Type == "Location":
            Local_Plugin_Name = Plugin_Name + "-" + Type
            CSE_Response = location(Query)
            CSE_JSON_Output_Response = json.dumps(CSE_Response, indent=4, sort_keys=True)
            Output_file = General.Main_File_Create(Directory, Local_Plugin_Name, CSE_JSON_Output_Response, Query, ".json")
            Posts = CSE_Response[0]["edge_location_to_media"]["edges"]
            Current_Step = 0

            for Post in Posts:
                Shortcode = Post["node"]["shortcode"]
                URL = "https://www.instagram.com/p/" + Shortcode + "/"

                if URL not in Cached_Data and URL not in Data_to_Cache and Current_Step < Limit:

                    if Output_file:
                        General.Connections(Output_file, Query, Plugin_Name, URL, "instagram.com", "Data Leakage", Task_ID, General.Get_Title(URL))

                Data_to_Cache.append(URL)
                Current_Step += 1

        elif Type == "Media":
            Local_Plugin_Name = Plugin_Name + "-" + Type
            CSE_Response = instagram_explore.media(Query)

            if CSE_Response:
                CSE_JSON_Output_Response = json.dumps(CSE_Response, indent=4, sort_keys=True)
                Output_file = General.Main_File_Create(Directory, Local_Plugin_Name, CSE_JSON_Output_Response, Query, ".json")
                URL = "https://www.instagram.com/p/" + Query + "/"

                if URL not in Cached_Data and URL not in Data_to_Cache:

                    if Output_file:
                        General.Connections(Output_file, Query, Plugin_Name, URL, "instagram.com", "Data Leakage", Task_ID, General.Get_Title(URL))

                Data_to_Cache.append(URL)

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")