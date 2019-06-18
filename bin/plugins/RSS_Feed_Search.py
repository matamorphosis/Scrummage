#!/usr/bin/env python3
import os, sys, feedparser, datetime, plugins.common.General as General

The_File_Extension = ".html"
Plugin_Name = "RSS"

def Search(Query_List, Task_ID, **kwargs):
    Data_to_Cache = []
    Cached_Data = []

    if "Limit" in kwargs:

        if int(kwargs["Limit"]) > 0:
            Limit = kwargs["Limit"]

    else:
        Limit = 10

    try:
        File_Dir = os.path.dirname(os.path.realpath('__file__'))
        Configuration_File = os.path.join(File_Dir, 'plugins/common/configuration/RSS_Feeds.txt')
        Current_File = open(Configuration_File, "r") # Open the provided file and retrieve each client to test.
        URLs = Current_File.read().splitlines()
        Current_File.close()

    except:
        sys.exit(str(datetime.datetime.now()) + " Please provide a valid file, failed to open the file which contains the data to search for.")

    Directory = General.Make_Directory(Plugin_Name.lower())
    General.Logging(Directory, Plugin_Name)
    Cached_Data = General.Get_Cache(Directory, Plugin_Name)

    if not Cached_Data:
        Cached_Data = []

    Query_List = General.Convert_to_List(Query_List)

    for Query in Query_List:

        for URL in URLs: # URLs to be controlled by the web app.
            RSS = feedparser.parse(URL)
            Current_Step = 0

            for Feed in RSS.entries:

                if Query in Feed.description:
                    Dump_Types = General.Data_Type_Discovery(Feed.description)
                    File_Link = Feed.link.replace("https://", "")
                    File_Link = File_Link.replace("http://", "")
                    File_Link = File_Link.replace("www.", "")
                    File_Link = File_Link.replace("/", "-")
                    Domain = URL.replace("https://", "")
                    Domain = Domain.replace("http://", "")
                    Domain = Domain.replace("www.", "")

                    if Feed.link not in Cached_Data and Feed.link not in Data_to_Cache and Current_Step < int(Limit):
                        Output_file = General.Create_Query_Results_Output_File(Directory, Query, Plugin_Name, Feed.description, File_Link, The_File_Extension)

                        if Output_file:
                            General.Connections(Output_file, Query, Plugin_Name, Feed.link, Domain, "Data Leakage", Task_ID, General.Get_Title(Feed.link), Dump_Types=Dump_Types)

                        Data_to_Cache.append(Feed.link)
                        Current_Step += 1

    if Cached_Data:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "a")

    else:
        General.Write_Cache(Directory, Data_to_Cache, Plugin_Name, "w")