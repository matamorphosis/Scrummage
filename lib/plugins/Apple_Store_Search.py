#!/usr/bin/env python3
import requests, logging, json, re, os, urllib.parse, plugins.common.General as General

Plugin_Name = "iTunes-App-Store"
Concat_Plugin_Name = "itunesappstore"
The_File_Extensions = {"Main": ".json", "Query": ".html"}
Domain = "itunes.apple.com"

def Search(Query_List, Task_ID, **kwargs):

    try:
        Data_to_Cache = []
        Directory = General.Make_Directory(Concat_Plugin_Name)
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        Log_File = General.Logging(Directory, Plugin_Name.lower())
        handler = logging.FileHandler(os.path.join(Directory, Log_File), "w")
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        Location = General.Load_Location_Configuration()
        Cached_Data = General.Get_Cache(Directory, Plugin_Name)
        Query_List = General.Convert_to_List(Query_List)
        Limit = General.Get_Limit(kwargs)

        for Query in Query_List:

            try:
                Request_Query = urllib.parse.quote(Query)
                Main_URL = f"http://{Domain}/search?term={Request_Query}&country={Location}&entity=software&limit={str(Limit)}"
                Response = General.Request_Handler(Main_URL)

            except:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to make request, are you connected to the internet?")
                break

            JSON_Response = json.loads(Response)
            Main_File = General.Main_File_Create(Directory, "iTunes", json.dumps(JSON_Response, indent=4, sort_keys=True), Query, The_File_Extensions["Main"])

            if 'resultCount' in JSON_Response:

                if JSON_Response['resultCount'] > 0:
                    Output_Connections = General.Connections(Query, Plugin_Name, Domain, "Application", Task_ID, Concat_Plugin_Name)

                    for JSON_Object in JSON_Response['results']:
                        JSON_Object_Responses = General.Request_Handler(JSON_Object['artistViewUrl'], Filter=True, Host=f"https://{Domain}")
                        JSON_Object_Response = JSON_Object_Responses["Filtered"]

                        if JSON_Object['artistViewUrl'] not in Cached_Data and JSON_Object['artistViewUrl'] not in Data_to_Cache:
                            iTunes_Regex = re.search(r"https\:\/\/apps\.apple\.com\/" + rf"{Location}" + r"\/developer\/[\w\d\-]+\/(id[\d]{9,10})\?.+", JSON_Object['artistViewUrl'])

                            if iTunes_Regex:
                                Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, JSON_Object_Response, iTunes_Regex.group(1), The_File_Extensions["Query"])

                                if Output_file:
                                    Output_Connections.Output([Main_File, Output_file], JSON_Object['artistViewUrl'], General.Get_Title(JSON_Object['artistViewUrl']), Concat_Plugin_Name)
                                    Data_to_Cache.append(JSON_Object['artistViewUrl'])

                                else:
                                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                else:
                    logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid value provided, value not greater than 0.")

            else:
                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Invalid value.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")