#!/usr/bin/python3
# -*- coding: utf-8 -*-

import json, sys, os, tweepy, datetime, plugins.common.General as General

Plugin_Name = "Twitter"
The_File_Extension = ".txt"

def Load_Configuration():
    File_Dir = os.path.dirname(os.path.realpath('__file__'))
    Configuration_File = os.path.join(File_Dir, 'plugins/common/configuration/config.json')
    print(str(datetime.datetime.now()) + " Loading configuration data.")

    try:

        with open(Configuration_File) as JSON_File:  
            Configuration_Data = json.load(JSON_File)
            Twitter_Credentials = Configuration_Data[Plugin_Name.lower()]
            return Twitter_Credentials

    except:
        sys.exit(str(datetime.datetime.now()) + " Failed to load Twitter details.")

def General_Pull(Handle, Limit, Directory, API, Task_ID):
    Data_to_Cache = []
    Cached_Data = []
    JSON_Response = []
    Cached_Data = General.Get_Cache(Directory, Plugin_Name)

    if not Cached_Data:
        Cached_Data = []

    Latest_Tweets = API.user_timeline(screen_name=Handle, count=Limit)

    for Tweet in Latest_Tweets:
        Link = ""

        try:
            print(str(datetime.datetime.now()) + Tweet.entities['urls'][0])
            JSON_Response.append({
                'text': Tweet.text,
                'author_name': Tweet.user.screen_name,
                'url': Tweet.entities['urls'][0]["expanded_url"]
            })
            Link = Tweet.entities['urls'][0]["expanded_url"]

        except:
            JSON_Response.append({
                'text': Tweet.text,
                'author_name': Tweet.user.screen_name
            })

        JSON_Output = json.dumps(JSON_Response, indent=4, sort_keys=True)

        if Link not in Cached_Data and Link not in Data_to_Cache:
            Output_file = General.Main_File_Create(Directory, Plugin_Name, JSON_Output, Handle, ".json")

            if Output_file:

                for JSON_Tweet in JSON_Response:
                    print(JSON_Tweet)

                    if 'url' in JSON_Tweet:
                        Link = JSON_Tweet['url']
                        print(str(datetime.datetime.now()) + Link)
                        General.Connections(Output_file, Handle, Plugin_Name, Link, "twitter.com", "Data Leakage", Task_ID, General.Get_Title(Link))

            Data_to_Cache.append(Link)

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")

def Search(Query_List, Task_ID, **kwargs):

    if int(kwargs["Limit"]) > 0:
        Limit = kwargs["Limit"]

    else:
        Limit = 10

    Directory = General.Make_Directory(Plugin_Name.lower())
    General.Logging(Directory, Plugin_Name)
    Twitter_Credentials = Load_Configuration()
    Query_List = General.Convert_to_List(Query_List)

    for Query in Query_List:

        try:
            Authentication = tweepy.OAuthHandler(Twitter_Credentials[0]["CONSUMER_KEY"], Twitter_Credentials[0]["CONSUMER_SECRET"])
            Authentication.set_access_token(Twitter_Credentials[0]["ACCESS_KEY"], Twitter_Credentials[0]["ACCESS_SECRET"])
            API = tweepy.API(Authentication)
            General_Pull(Query, Limit, Directory, API, Task_ID)

        except:
            print(str(datetime.datetime.now()) + " Failed to get results. Are you connected to the internet?")