import importlib, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Verifier:

    def __init__(self, Plugin_Name, Task_ID, Query, Limit):
        self.plugin_name = Plugin_Name
        self.query = Query
        self.limit = Limit
        self.task_id = Task_ID

    def Verify_Plugin(self, Load_Config_Only=False):
    
        try:
            Object = Common.Configuration(Output=True)
            Configuration_Dependant_Plugins = {"Apple Store Search": "plugins.Apple_Store_Search","Business Search - United Kingdom Business Number": "plugins.UK_Business_Search",
                           "Business Search - United Kingdom Company Name": "plugins.UK_Business_Search", "Certificate Transparency - SSLMate": "plugins.Certificate_Transparency_SSLMate",
                           "Craigslist Search": "plugins.Craigslist_Search", "Ebay Search": "plugins.Ebay_Search", "Email Reputation Search": "plugins.Email_Reputation_Search", "Flickr Search": "plugins.Flickr_Search",
                           "Google Search": "plugins.Google_Search", "Have I Been Pwned - Password Search": "plugins.Have_I_Been_Pwned", "Have I Been Pwned - Email Search": "plugins.Have_I_Been_Pwned",
                             "Have I Been Pwned - Breach Search": "plugins.Have_I_Been_Pwned", "Have I Been Pwned - Account Search": "plugins.Have_I_Been_Pwned", "Hunter Search - Domain": "plugins.Hunter_Search", "Hunter Search - Email": "plugins.Hunter_Search", "Naver Search": "plugins.Naver_Search", "OK Search - User": "plugins.OK_Search", "OK Search - Group": "plugins.OK_Search",
                           "Pinterest - Board Search": "plugins.Pinterest_Search", "Pinterest - Pin Search": "plugins.Pinterest_Search", "IntelligenceX Search": "plugins.IntelligenceX_Search",
                           "Reddit Search": "plugins.Reddit_Search", "Shodan Search - IP Address": "plugins.Shodan_Search", "Shodan Search - Query": "plugins.Shodan_Search",
                           "Twitter Search": "plugins.Twitter_Search", "Virus Total Search - Domain": "plugins.Virus_Total_Search", "Virus Total Search - URL": "plugins.Virus_Total_Search", "Virus Total Search - IP Address": "plugins.Virus_Total_Search", "Virus Total Search - File Hash": "plugins.Virus_Total_Search",
                           "Vulners Search": "plugins.Vulners_Search", "Windows Store Search": "plugins.Windows_Store_Search", "Yandex Search": "plugins.Yandex_Search", "YouTube Search": "plugins.YouTube_Search", "IP Stack Search": "plugins.IPStack_Search", "Tumblr Search": "plugins.Tumblr_Search"}
            Plugins_Dictionary = {"YouTube Search": {"Module": "plugins.YouTube_Search", "Limit": True},
            "Yandex Search": {"Module": "plugins.Yandex_Search", "Limit": True},
            "Windows Store Search": {"Module": "plugins.Windows_Store_Search", "Limit": True},
            "Vulners Search": {"Module": "plugins.Vulners_Search", "Limit": True},
            "Virus Total Search - Domain": {"Module": "plugins.Virus_Total_Search", "Type": "Domain"},
            "Virus Total Search - URL": {"Module": "plugins.Virus_Total_Search", "Type": "URL"},
            "Virus Total Search - IP Address": {"Module": "plugins.Virus_Total_Search", "Type": "IP"},
            "Virus Total Search - File Hash": {"Module": "plugins.Virus_Total_Search", "Type": "Hash"},
            "Vkontakte - User Search": {"Module": "plugins.Vkontakte_Search", "Type": "User", "Limit": True},
            "Vkontakte - Group Search": {"Module": "plugins.Vkontakte_Search", "Type": "Group", "Limit": True},
            "Vehicle Registration Search": {"Module": "plugins.Vehicle_Registration_Search"},
            "Username Search": {"Module": "plugins.Username_Search"},
            "Twitter Search": {"Module": "plugins.Twitter_Search", "Limit": True},
            "Tumblr Search": {"Module": "plugins.Tumblr_Search"},
            "Torrent Search": {"Module": "plugins.Torrent_Search", "Limit": True},
            "Threat Crowd - Virus Report Search": {"Module": "plugins.Threat_Crowd_Search", "Type": "Virus Report"},
            "Threat Crowd - IP Address Search": {"Module": "plugins.Threat_Crowd_Search", "Type": "IP Address"},
            "Threat Crowd - Email Search": {"Module": "plugins.Threat_Crowd_Search", "Type": "Email"},
            "Threat Crowd - Domain Search": {"Module": "plugins.Threat_Crowd_Search", "Type": "Domain"},
            "Threat Crowd - Antivirus Search": {"Module": "plugins.Threat_Crowd_Search", "Type": "AV"},
            "Shodan Search - Query": {"Module": "plugins.Shodan_Search", "Type": "Search", "Limit": True},
            "Shodan Search - IP Address": {"Module": "plugins.Shodan_Search", "Type": "Host"},
            "RSS Feed Search": {"Module": "plugins.RSS_Feed_Search", "Limit": True},
            "Reddit Search": {"Module": "plugins.Reddit_Search", "Limit": True},
            "Phone Search - SIM Number": {"Module": "plugins.Phone_Search", "Type": "SIM"},
            "Phone Search - ISPC Number": {"Module": "plugins.Phone_Search", "Type": "ISPC"},
            "Phone Search - IMSI Number": {"Module": "plugins.Phone_Search", "Type": "IMSI"},
            "Phone Search - IMEI Number": {"Module": "plugins.Phone_Search", "Type": "IMEI"},
            "Phone Search - Cellular Number": {"Module": "plugins.Phone_Search", "Type": "Number"},
            "Phishstats Search": {"Module": "plugins.Phishstats_Search", "Limit": True},
            "Pinterest - Pin Search": {"Module": "plugins.Pinterest_Search", "Type": "pin", "Limit": True},
            "Pinterest - Board Search": {"Module": "plugins.Pinterest_Search", "Type": "board", "Limit": True},
            "OK Search - User": {"Module": "plugins.OK_Search", "Type": "User"},
            "OK Search - Group": {"Module": "plugins.OK_Search", "Type": "Group"},
            "Naver Search": {"Module": "plugins.Naver_Search", "Limit": True},
            "Library Genesis Search": {"Module": "plugins.Library_Genesis_Search", "Limit": True},
            "Kik Search": {"Module": "plugins.Kik_Search"},
            "IP Stack Search": {"Module": "plugins.IPStack_Search"},
            "IntelligenceX Search": {"Module": "plugins.IntelligenceX_Search", "Limit": True},
            "Instagram - User Search": {"Module": "plugins.Instagram_Search", "Type": "User", "Limit": True},
            "Instagram - Tag Search": {"Module": "plugins.Instagram_Search", "Type": "Tag", "Limit": True},
            "Instagram - Post Search": {"Module": "plugins.Instagram_Search", "Type": "Post", "Limit": True},
            "Hunter Search - Email": {"Module": "plugins.Hunter_Search", "Type": "Email", "Limit": True},
            "Hunter Search - Domain": {"Module": "plugins.Hunter_Search", "Type": "Domain", "Limit": True},
            "Have I Been Pwned - Password Search": {"Module": "plugins.Have_I_Been_Pwned", "Type": "password"},
            "Have I Been Pwned - Email Search": {"Module": "plugins.Have_I_Been_Pwned", "Type": "email"},
            "Have I Been Pwned - Breach Search": {"Module": "plugins.Have_I_Been_Pwned", "Type": "breach"},
            "Have I Been Pwned - Account Search": {"Module": "plugins.Have_I_Been_Pwned", "Type": "account"},
            "Greynoise IP Search": {"Module": "plugins.Greynoise_IP_Search"},
            "Google Search": {"Module": "plugins.Google_Search", "Limit": True},
            "Google Play Store Search": {"Module": "plugins.Google_Play_Store_Search", "Limit": True},
            "Flickr Search": {"Module": "plugins.Flickr_Search", "Limit": True},
            "Email Verification Search": {"Module": "plugins.Email_Verification_Search"},
            "Email Reputation Search": {"Module": "plugins.Email_Reputation_Search"},
            "Ebay Search": {"Module": "plugins.Ebay_Search", "Limit": True},
            "Domain Fuzzer - Regular Domain Suffixes": {"Module": "plugins.Domain_Fuzzer", "Custom_Search": "Regular_Extensions"},
            "Domain Fuzzer - Global Domain Suffixes": {"Module": "plugins.Domain_Fuzzer", "Custom_Search": "Global_Extensions"},
            "Domain Fuzzer - Punycode (Latin Comprehensive)": {"Module": "plugins.Domain_Fuzzer", "Custom_Search": "Character_Switch", "Alphabets": "Latin", "Comprehensive": True},
            "Domain Fuzzer - Punycode (Latin Condensed)": {"Module": "plugins.Domain_Fuzzer", "Custom_Search": "Character_Switch", "Alphabets": "Latin"},
            "Domain Fuzzer - Punycode (Asian)": {"Module": "plugins.Domain_Fuzzer", "Custom_Search": "Character_Switch", "Alphabets": "Asian"},
            "Domain Fuzzer - Punycode (Middle Eastern)": {"Module": "plugins.Domain_Fuzzer", "Custom_Search": "Character_Switch", "Alphabets": "Middle Eastern"},
            "Domain Fuzzer - Punycode (North African)": {"Module": "plugins.Domain_Fuzzer", "Custom_Search": "Character_Switch", "Alphabets": "North African"},
            "Domain Fuzzer - Punycode (Native American)": {"Module": "plugins.Domain_Fuzzer", "Custom_Search": "Character_Switch", "Alphabets": "Native American"},
            "Domain Fuzzer - All Extensions": {"Module": "plugins.Domain_Fuzzer", "Custom_Search": "All_Extensions"},
            "Doing Business Search": {"Module": "plugins.Doing_Business_Search"},
            "DNS Reconnaissance Search": {"Module": "plugins.DNS_Recon_Search"},
            "Default Password Search": {"Module": "plugins.Default_Password_Search", "Limit": True},
            "DuckDuckGo Search": {"Module": "plugins.DuckDuckGo_Search", "Limit": True},
            "Craigslist Search": {"Module": "plugins.Craigslist_Search", "Limit": True},
            "Certificate Transparency - SSLMate": {"Module": "plugins.Certificate_Transparency_SSLMate"},
            "Certificate Transparency - CRT.sh": {"Module": "plugins.Certificate_Transparency_CRT"},
            "Builtwith Search": {"Module": "plugins.BuiltWith_Search"},
            "Business Search - United Kingdom Business Number": {"Module": "plugins.UK_Business_Search", "Type": "UKBN", "Limit": True},
            "Business Search - United Kingdom Company Name": {"Module": "plugins.UK_Business_Search", "Type": "UKCN", "Limit": True},
            "Business Search - New Zealand Business Number": {"Module": "plugins.NZ_Business_Search", "Type": "NZBN", "Limit": True},
            "Business Search - New Zealand Company Name": {"Module": "plugins.NZ_Business_Search", "Type": "NZCN", "Limit": True},
            "Business Search - Canadian Business Number": {"Module": "plugins.Canadian_Business_Search", "Type": "CBN", "Limit": True},
            "Business Search - Canadian Company Name": {"Module": "plugins.Canadian_Business_Search", "Type": "CCN", "Limit": True},
            "Business Search - Australian Business Number": {"Module": "plugins.Australian_Business_Search", "Type": "ABN", "Limit": True},
            "Business Search - Australian Company Name": {"Module": "plugins.Australian_Business_Search", "Type": "ACN", "Limit": True},
            "Business Search - American Central Index Key": {"Module": "plugins.American_Business_Search", "Type": "CIK", "Limit": True},
            "Business Search - American Company Name": {"Module": "plugins.American_Business_Search", "Type": "ACN", "Limit": True},
            "BSB Search": {"Module": "plugins.BSB_Search"},
            "Blockchain - Monero Transaction Search": {"Module": "plugins.Blockchain_Search", "Custom_Search": "Transaction_Search", "Type": "monero", "Limit": True},
            "Blockchain - Ethereum Transaction Search": {"Module": "plugins.Blockchain_Search", "Custom_Search": "Transaction_Search", "Type": "eth", "Limit": True},
            "Blockchain - Bitcoin Cash Transaction Search": {"Module": "plugins.Blockchain_Search", "Custom_Search": "Transaction_Search", "Type": "bch", "Limit": True},
            "Blockchain - Bitcoin Transaction Search": {"Module": "plugins.Blockchain_Search", "Custom_Search": "Transaction_Search", "Type": "btc", "Limit": True},
            "Blockchain - Ethereum Address Search": {"Module": "plugins.Blockchain_Search", "Custom_Search": "Address_Search", "Type": "eth", "Limit": True},
            "Blockchain - Bitcoin Cash Address Search": {"Module": "plugins.Blockchain_Search", "Custom_Search": "Address_Search", "Type": "bch", "Limit": True},
            "Blockchain - Bitcoin Address Search": {"Module": "plugins.Blockchain_Search", "Custom_Search": "Address_Search", "Type": "btc", "Limit": True},
            "Apple Store Search": {"Module": "plugins.Apple_Store_Search", "Limit": True},
            "Ahmia Tor Darkweb Search": {"Module": "plugins.Ahmia_Darkweb_Search", "Type": "Tor", "Limit": True},
            "Ahmia I2P Darkweb Search": {"Module": "plugins.Ahmia_Darkweb_Search", "Type": "I2P", "Limit": True}}

            try:

                def Output_API_Checker(Plugin_Object, Plugin_Name):
                    In_Dict = False
                    Result = None

                    for API_Key, API_Value in Configuration_Dependant_Plugins.items():

                        if Plugin_Name != "":

                            if Plugin_Name == API_Key:
                                In_Dict = True
                                Result = Plugin_Object.Load_Configuration()

                    if In_Dict:
                        return Result

                    else:
                        return True

                if Load_Config_Only:

                    if self.plugin_name in Plugins_Dictionary:
                        Dict_Item = Plugins_Dictionary[self.plugin_name]
                        Kwargs = {}
                        Func_Kwargs = {}

                        for Key in ["Limit", "Type", "Alphabets", "Comprehensive"]:

                            if Key in Dict_Item and Key == "Type":
                                Kwargs[Key] = Dict_Item[Key]

                            elif Key in Dict_Item and Key == "Limit":
                                Kwargs[Key] = self.limit

                            elif Key in Dict_Item:
                                Func_Kwargs[Key] = Dict_Item[Key]

                        if "Custom_Search" in Dict_Item:
                            Search_Option = Dict_Item["Custom_Search"]
                            
                        else:
                            Search_Option = "Search"

                        Class = importlib.import_module(Dict_Item["Module"])
                        Plugin_Object = Class.Plugin_Search(self.query, self.task_id, **Kwargs)
                        Result = Output_API_Checker(Plugin_Object, self.plugin_name)

                        if Result:
                            return True

                        else:
                            return False

                    else:
                        print(f"{Common.Date()} - Plugin Verifier - Invalid plugin provided.")

                else:

                    if self.plugin_name in Plugins_Dictionary:
                        Dict_Item = Plugins_Dictionary[self.plugin_name]
                        Kwargs = {}
                        Func_Kwargs = {}

                        for Key in ["Limit", "Type", "Alphabets", "Comprehensive"]:

                            if Key in Dict_Item and Key == "Type":
                                Kwargs[Key] = Dict_Item[Key]

                            elif Key in Dict_Item and Key == "Limit":
                                Kwargs[Key] = self.limit

                            elif Key in Dict_Item:
                                Func_Kwargs[Key] = Dict_Item[Key]

                        if "Custom_Search" in Dict_Item:
                            Search_Option = Dict_Item["Custom_Search"]
                            
                        else:
                            Search_Option = "Search"

                        Class = importlib.import_module(Dict_Item["Module"])
                        Plugin_Object = Class.Plugin_Search(self.query, self.task_id, **Kwargs)
                        Result = Output_API_Checker(Plugin_Object, self.plugin_name)

                        if Result:
                            return {"Object": Plugin_Object, "Search Option": Search_Option, "Function Kwargs": Func_Kwargs}

                        else:
                            return False

                    else:
                        print(f"{Common.Date()} - Plugin Verifier - Invalid plugin provided.")

            except Exception as e:
                print(f"{Common.Date()} - Plugin Verifier - {str(e)}")
                
        except Exception as e:
            print(f"{Common.Date()} - Plugin Verifier - {str(e)}")