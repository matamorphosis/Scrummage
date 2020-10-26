#!/usr/bin/env python3
import os, feedparser, logging, plugins.common.General as General

The_File_Extension = ".html"
Plugin_Name = "RSS"

def Search(Query_List, Task_ID, **kwargs):

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

        try:
            File_Dir = os.path.dirname(os.path.realpath('__file__'))
            Configuration_File = os.path.join(File_Dir, 'plugins/common/config/RSS_Feeds.txt')
            Current_File = open(Configuration_File, "r") # Open the provided file and retrieve each client to test.
            URLs = Current_File.read().splitlines()
            Current_File.close()

        except:
            logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Please provide a valid file, failed to open the file which contains the data to search for.")

        Cached_Data = General.Get_Cache(Directory, Plugin_Name)
        Query_List = General.Convert_to_List(Query_List)
        Limit = General.Get_Limit(kwargs)

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
                            Title = "RSS Feed | " + General.Get_Title(Feed.link)

                            if Output_file:
                                Output_Connections = General.Connections(Query, Plugin_Name, Domain, "News Report", Task_ID, Plugin_Name.lower())
                                Output_Connections.Output([Output_file], Feed.link, Title, Plugin_Name.lower(), Dump_Types=Dump_Types)
                                Data_to_Cache.append(Feed.link)

                            else:
                                logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - Failed to create output file. File may already exist.")

                            Current_Step += 1

                    else:
                        logging.info(f"{General.Date()} - {__name__.strip('plugins.')} - Query not found.")

        General.Write_Cache(Directory, Cached_Data, Data_to_Cache, Plugin_Name)

    except Exception as e:
        logging.warning(f"{General.Date()} - {__name__.strip('plugins.')} - {str(e)}")