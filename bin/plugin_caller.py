import threading, os, plugins.common.Connectors as Connectors

def Starter(Task_ID):
    Connection = Connectors.Load_Main_Database()
    Cursor = Connection.cursor()
    PSQL_Update_Query = 'UPDATE tasks SET status = %s WHERE task_id = %s'
    Cursor.execute(PSQL_Update_Query, ("Running", int(Task_ID),))
    Connection.commit()

def Stopper(Task_ID):
    Connection = Connectors.Load_Main_Database()
    Cursor = Connection.cursor()
    PSQL_Update_Query = 'UPDATE tasks SET status = %s WHERE task_id = %s'
    Cursor.execute(PSQL_Update_Query, ("Stopped", int(Task_ID),))
    Connection.commit()

def Call_Plugin(**kwargs):

    if kwargs["Plugin_Name"] == "YouTube Search":
        import plugins.YouTube_Search as YT_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=YT_Search.Search, args=(kwargs["Query"], kwargs["Task_ID"],), kwargs={"Limit": kwargs["Limit"],})
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Windows Store Search":
        import plugins.Windows_Store_Search as WS_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=WS_Search.Search, args=(kwargs["Query"], kwargs["Task_ID"],), kwargs={"Limit": kwargs["Limit"],})
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Vulners Search":
        import plugins.Vulners_Search as Vulners_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Vulners_Search.Search, args=(kwargs["Query"], kwargs["Task_ID"],), kwargs={"Limit": kwargs["Limit"],})
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Twitter Scraper":
        import plugins.Twitter_Scraper as Twitter_Scrape
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Twitter_Scrape.Search, args=(kwargs["Query"], kwargs["Task_ID"],), kwargs={"Limit": kwargs["Limit"],})
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "RSS Feed Search":
        import plugins.RSS_Feed_Search as RSS_Feed_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=RSS_Feed_Search.Search, args=(kwargs["Query"], kwargs["Task_ID"],), kwargs={"Limit": kwargs["Limit"],})
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Reddit Search":
        import plugins.Reddit_Search as Reddit_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Reddit_Search.Search, args=(kwargs["Query"], kwargs["Task_ID"],), kwargs={"Limit": kwargs["Limit"],})
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "PhishTank Search":
        import plugins.Phishtank_Search as Phishtank_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Phishtank_Search.Search, args=(kwargs["Query"], kwargs["Task_ID"],), kwargs={"Limit": kwargs["Limit"],})
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "iTunes Store Search":
        import plugins.ITunes_Store_Search as ITunes_Store_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=ITunes_Store_Search.Search, args=(kwargs["Query"], kwargs["Task_ID"],), kwargs={"Limit": kwargs["Limit"],})
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Instagram User Search":
        import plugins.Instagram_Search as Instagram_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Instagram_Search.Search, args=(kwargs["Query"], kwargs["Task_ID"], "User"))
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Instagram Tag Search":
        import plugins.Instagram_Search as Instagram_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Instagram_Search.Search, args=(kwargs["Query"], kwargs["Task_ID"], "Tag"))
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Instagram Media Search":
        import plugins.Instagram_Search as Instagram_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Instagram_Search.Search, args=(kwargs["Query"], kwargs["Task_ID"], "Media"))
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Instagram Location Search":
        import plugins.Instagram_Search as Instagram_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Instagram_Search.Search, args=(kwargs["Query"], kwargs["Task_ID"], "Location"))
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Have I Been Pwned - Password Search":
        import plugins.Have_I_Been_Pwned as Have_I_Been_Pwned
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Have_I_Been_Pwned.Search, args=(kwargs["Query"], kwargs["Task_ID"], "password"))
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Have I Been Pwned - Email Search":
        import plugins.Have_I_Been_Pwned as Have_I_Been_Pwned
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Have_I_Been_Pwned.Search, args=(kwargs["Query"], kwargs["Task_ID"], "email"))
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Have I Been Pwned - Breach Search":
        import plugins.Have_I_Been_Pwned as Have_I_Been_Pwned
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Have_I_Been_Pwned.Search, args=(kwargs["Query"], kwargs["Task_ID"], "breach"))
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Have I Been Pwned - Account Search":
        import plugins.Have_I_Been_Pwned as Have_I_Been_Pwned
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Have_I_Been_Pwned.Search, args=(kwargs["Query"], kwargs["Task_ID"], "account"))
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Google Search":
        import plugins.Google_Search as Google_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Google_Search.Search, args=(kwargs["Query"], kwargs["Task_ID"],), kwargs={"Limit": kwargs["Limit"],})
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Google Play Store Search":
        import plugins.Google_Play_Store_Search as Google_Play_Store_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Google_Play_Store_Search.Search, args=(kwargs["Query"], kwargs["Task_ID"],), kwargs={"Limit": kwargs["Limit"],})
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Ebay Search":
        import plugins.Ebay_Search as Ebay_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Ebay_Search.Search, args=(kwargs["Query"], kwargs["Task_ID"],), kwargs={"Limit": kwargs["Limit"],})
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Domain Fuzzer - Regular Domain Suffixes":
        import plugins.Domain_Fuzzer as Domain_Fuzzer
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target= Domain_Fuzzer.Regular_Extensions, args=(kwargs["Query"], kwargs["Task_ID"],))
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Domain Fuzzer - Global Domain Suffixes":
        import plugins.Domain_Fuzzer as Domain_Fuzzer
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target= Domain_Fuzzer.Global_Extensions, args=(kwargs["Query"], kwargs["Task_ID"],))
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Domain Fuzzer - Alpha-Linguistic Character Switcher":
        import plugins.Domain_Fuzzer as Domain_Fuzzer
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target= Domain_Fuzzer.Character_Switch, args=(kwargs["Query"], kwargs["Task_ID"],))
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Domain Fuzzer - All Extensions":
        import plugins.Domain_Fuzzer as Domain_Fuzzer
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target= Domain_Fuzzer.All_Extensions, args=(kwargs["Query"], kwargs["Task_ID"],))
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Ahmia Darkweb Search":
        import plugins.Ahmia_Darkweb_Search as Ahmia_Darkweb_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target= Ahmia_Darkweb_Search.Search, args=(kwargs["Query"], kwargs["Task_ID"],), kwargs={"Limit": kwargs["Limit"],})
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Craigslist Search":
        import plugins.Craigslist_Search as Craigslist_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Craigslist_Search.Search, args=(kwargs["Query"], kwargs["Task_ID"],), kwargs={"Limit": kwargs["Limit"],})
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Certificate Transparency":
        import plugins.Certificate_Transparency as Certificate_Transparency
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Certificate_Transparency.Search, args=(kwargs["Query"], kwargs["Task_ID"],))
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Blockchain Ethereum Transaction Search":
        import plugins.Blockchain_Search as Blockchain_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Blockchain_Search.Transaction_Search, args=(kwargs["Query"], kwargs["Task_ID"], "eth",))
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Blockchain Bitcoin Cash Transaction Search":
        import plugins.Blockchain_Search as Blockchain_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Blockchain_Search.Transaction_Search, args=(kwargs["Query"], kwargs["Task_ID"], "bch",))
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Blockchain Bitcoin Transaction Search":
        import plugins.Blockchain_Search as Blockchain_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Blockchain_Search.Transaction_Search, args=(kwargs["Query"], kwargs["Task_ID"], "btc",))
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Blockchain Ethereum Address Search":
        import plugins.Blockchain_Search as Blockchain_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Blockchain_Search.Address_Search, args=(kwargs["Query"], kwargs["Task_ID"], "eth",))
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Blockchain Bitcoin Cash Address Search":
        import plugins.Blockchain_Search as Blockchain_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Blockchain_Search.Address_Search, args=(kwargs["Query"], kwargs["Task_ID"], "bch",))
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()

    elif kwargs["Plugin_Name"] == "Blockchain Bitcoin Address Search":
        import plugins.Blockchain_Search as Blockchain_Search
        Thread_0 = threading.Thread(target=Starter, args=[kwargs["Task_ID"]])
        Thread_0.start()
        Thread_0.join()
        Thread_1 = threading.Thread(target=Blockchain_Search.Address_Search, args=(kwargs["Query"], kwargs["Task_ID"], "btc",))
        Thread_1.start()
        Thread_1.join()
        Thread_2 = threading.Thread(target=Stopper, args=[kwargs["Task_ID"]])
        Thread_2.start()
        
if __name__ == "__main__":
    import argparse, sys, plugins.common.General as General
    Parser = argparse.ArgumentParser(description='Plugin Caller calls Scrummage plugins.')
    Parser.add_argument('-t', '--task', help='This option is used to specify a task ID to run. ./plugin_caller.py -t 1')
    Arguments = Parser.parse_args()

    Task_ID = 0

    if Arguments.task:

        try:
	        Task_ID = int(Arguments.task)
	        Connection = Connectors.Load_Main_Database()
	        cursor = Connection.cursor()
	        PSQL_Select_Query = 'SELECT * FROM tasks WHERE task_id = %s;'
	        cursor.execute(PSQL_Select_Query, (Task_ID,))
	        result = cursor.fetchone()

	        if result:
	            print(result[2])
	            print(result[5])
	            Call_Plugin(Plugin_Name=result[2], Limit=result[5], Task_ID=Task_ID, Query=result[1])

        except:
            sys.exit("[-] Invalid Task ID, please provide a valid Task ID")
