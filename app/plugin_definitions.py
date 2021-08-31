Valid_Plugins = {'Abuse IP Database Search - Domain': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.AbuseIPDB_Search', "Type": "Domain", 'Organisation_Presets': 'domain'},
'Abuse IP Database Search - IP': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.AbuseIPDB_Search', "Type": "IP"},
'Ahmia I2P Darkweb Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Ahmia_Darkweb_Search', 'Type': 'I2P'},
'Ahmia Tor Darkweb Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Ahmia_Darkweb_Search', 'Type': 'Tor'},
'Alienvault OTX Search - IP': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Alienvault_OTX_Search', 'Type': 'IP'},
'Alienvault OTX Search - Domain': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Alienvault_OTX_Search', 'Type': 'Domain', 'Organisation_Presets': 'domain'},
'Apple Store Search': {'Requires_Configuration': True, 'Requires_Limit': True, 'Module': 'plugins.Apple_Store_Search'},
'Blockchain - Bitcoin Address Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Blockchain_Search', 'Type': 'BTC', 'Custom_Search': 'Address_Search'},
'Blockchain - Bitcoin Address Abuse Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Blockchain_Search', 'Type': 'NA', 'Custom_Search': 'Address_Abuse_Search'},
'Blockchain - Bitcoin Cash Address Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Blockchain_Search', 'Type': 'BCH', 'Custom_Search': 'Address_Search'},
'Blockchain - Bitcoin Cash Transaction Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Blockchain_Search', 'Type': 'BCH', 'Custom_Search': 'Transaction_Search'},
'Blockchain - Bitcoin Transaction Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Blockchain_Search', 'Type': 'BTC', 'Custom_Search': 'Transaction_Search'},
'Blockchain - Ethereum Address Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Blockchain_Search', 'Type': 'ETH', 'Custom_Search': 'Address_Search'},
'Blockchain - Ethereum Transaction Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Blockchain_Search', 'Type': 'ETH', 'Custom_Search': 'Transaction_Search'},
'Blockchain - Monero Transaction Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Blockchain_Search', 'Type': 'Monero', 'Custom_Search': 'Transaction_Search'},
'Blocklist Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Blocklist_Search'},
'Botscout Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Botscout_Search'},
'BSB Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.BSB_Search'},
'Builtwith Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.BuiltWith_Search', 'Organisation_Presets': 'website'},
'Business Search - American Central Index Key': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.American_Business_Search', 'Type': 'CIK'},
'Business Search - American Company Name': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.American_Business_Search', 'Organisation_Presets': 'name', 'Type': 'ACN'},
'Business Search - Australian Business Number': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Australian_Business_Search', 'Type': 'ABN'},
'Business Search - Australian Company Name': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Australian_Business_Search', 'Organisation_Presets': 'name', 'Type': 'ACN'},
'Business Search - Canadian Business Number': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Canadian_Business_Search', 'Type': 'CBN'},
'Business Search - Canadian Company Name': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Canadian_Business_Search', 'Organisation_Presets': 'name', 'Type': 'CCN'},
'Business Search - New Zealand Business Number': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.NZ_Business_Search', 'Type': 'NZBN'},
'Business Search - New Zealand Company Name': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.NZ_Business_Search', 'Organisation_Presets': 'name', 'Type': 'NZCN'},
'Business Search - United Kingdom Business Number': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.UK_Business_Search', 'Type': 'UKBN'},
'Business Search - United Kingdom Company Name': {'Requires_Configuration': True, 'Requires_Limit': True, 'Module': 'plugins.UK_Business_Search', 'Organisation_Presets': 'name', 'Type': 'UKCN'},
'Callername Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Callername_Search'},
'Certificate Transparency - CRT.sh': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Certificate_Transparency_CRT', 'Organisation_Presets': 'domain'},
'Certificate Transparency - SSLMate': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Certificate_Transparency_SSLMate', 'Organisation_Presets': 'domain'},
'Craigslist Search': {'Requires_Configuration': True, 'Requires_Limit': True, 'Module': 'plugins.Craigslist_Search'},
'Darksearch Tor Darkweb Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Darksearch_Tor_Search', 'Organisation_Presets': 'name'},
'Default Password Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Default_Password_Search'},
'DNS Reconnaissance Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.DNS_Recon_Search', 'Organisation_Presets': 'domain'},
'Doing Business Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Doing_Business_Search'},
'Domain Fuzzer - All Extensions': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Domain_Fuzzer', 'Organisation_Presets': 'domain', 'Custom_Search': 'All_Extensions'},
'Domain Fuzzer - Expired Global Domain Suffixes': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Domain_Fuzzer', 'Organisation_Presets': 'domain', 'Custom_Search': 'Expired_Global_Extensions'},
'Domain Fuzzer - Global Domain Suffixes': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Domain_Fuzzer', 'Organisation_Presets': 'domain', 'Custom_Search': 'Global_Extensions'},
'Domain Fuzzer - Punycode (Asian)': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Domain_Fuzzer', 'Organisation_Presets': 'domain', 'Alphabets': 'Asian', 'Custom_Search': 'Character_Switch'},
'Domain Fuzzer - Punycode (Latin Comprehensive)': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Domain_Fuzzer', 'Organisation_Presets': 'domain', 'Alphabets': 'Latin', 'Comprehensive': True, 'Custom_Search': 'Character_Switch'},
'Domain Fuzzer - Punycode (Latin Condensed)': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Domain_Fuzzer', 'Organisation_Presets': 'domain', 'Alphabets': 'Latin', 'Custom_Search': 'Character_Switch'},
'Domain Fuzzer - Punycode (Middle Eastern)': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Domain_Fuzzer', 'Organisation_Presets': 'domain', 'Alphabets': 'Middle Eastern', 'Custom_Search': 'Character_Switch'},
'Domain Fuzzer - Punycode (Native American)': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Domain_Fuzzer', 'Organisation_Presets': 'domain', 'Alphabets': 'Native American', 'Custom_Search': 'Character_Switch'},
'Domain Fuzzer - Punycode (North African)': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Domain_Fuzzer', 'Organisation_Presets': 'domain', 'Alphabets': 'North African', 'Custom_Search': 'Character_Switch'},
'Domain Fuzzer - Regular Domain Suffixes': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Domain_Fuzzer', 'Organisation_Presets': 'domain', 'Custom_Search': 'Regular_Extensions'},
'DuckDuckGo Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.DuckDuckGo_Search'},
'Ebay Search': {'Requires_Configuration': True, 'Requires_Limit': True, 'Module': 'plugins.Ebay_Search'},
'Email Reputation Search': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Email_Reputation_Search', 'Organisation_Presets': 'identity_emails'},
'Email Verification Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Email_Verification_Search', 'Organisation_Presets': 'identity_emails'},
'Flickr Search': {'Requires_Configuration': True, 'Requires_Limit': True, 'Module': 'plugins.Flickr_Search'},
'Fringe Project Search - Domain': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.FringeProject_Search', 'Organisation_Presets': 'domain', 'Type': 'Domain'},
'Fringe Project Search - IP Address': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.FringeProject_Search', 'Type': 'IP'},
'GitHub Repository Search': {'Requires_Configuration': True, 'Requires_Limit': True, 'Module': 'plugins.GitHub_Search', 'Safe_Characters': ['+']},
'Google Play Store Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Google_Play_Store_Search'},
'Google Search': {'Requires_Configuration': True, 'Requires_Limit': True, 'Module': 'plugins.Google_Search'},
'Gravatar Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Gravatar_Search'},
'Greynoise IP Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Greynoise_IP_Search'},
'Have I Been Pwned - Account Search': {'Requires_Configuration': True, 'Requires_Limit': True, 'Module': 'plugins.Have_I_Been_Pwned', 'Type': 'Account'},
'Have I Been Pwned - Breach Search': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Have_I_Been_Pwned', 'Type': 'Breach'},
'Have I Been Pwned - Email Search': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Have_I_Been_Pwned', 'Organisation_Presets': 'identity_emails', 'Type': 'Email'},
'Have I Been Pwned - Password Search': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Have_I_Been_Pwned', 'Type': 'Password'},
'Hunter Search - Domain': {'Requires_Configuration': True, 'Requires_Limit': True, 'Module': 'plugins.Hunter_Search', 'Organisation_Presets': 'domain', 'Type': 'Domain'},
'Hunter Search - Email': {'Requires_Configuration': True, 'Requires_Limit': True, 'Module': 'plugins.Hunter_Search', 'Organisation_Presets': 'identity_emails', 'Type': 'Email'},
'Hybrid Analysis Search - URL': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Hybrid_Analysis_Search', 'Organisation_Presets': 'website'},
'IP Stack Search': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.IPStack_Search'},
'Instagram - Post Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Instagram_Search', 'Type': 'Post'},
'Instagram - Tag Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Instagram_Search', 'Type': 'Tag'},
'Instagram - User Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Instagram_Search', 'Type': 'User'},
'IntelligenceX Search': {'Requires_Configuration': True, 'Requires_Limit': True, 'Module': 'plugins.IntelligenceX_Search', 'Organisation_Presets': 'domain'},
'Keybase Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Keybase_Search'},
'Kik Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Kik_Search'},
'Koodous Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Koodous_Search'},
'LeakIX Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.LeakIX_Search'},
'Leak Lookup Search - Email': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Leak_Lookup_Search', 'Organisation_Presets': 'identity_emails', 'Type': 'Email'},
'Leak Lookup Search - Username': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Leak_Lookup_Search', 'Type': 'Username'},
'Leak Lookup Search - IP Address': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Leak_Lookup_Search', 'Type': 'IP'},
'Leak Lookup Search - Domain': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Leak_Lookup_Search', 'Organisation_Presets': 'domain', 'Type': 'Domain'},
'Leak Lookup Search - Hash': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Leak_Lookup_Search', 'Type': 'Hash'},
'Library Genesis Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Library_Genesis_Search'},
'Malware Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Malware_Search_Abuse'},
'Naver Search': {'Requires_Configuration': True, 'Requires_Limit': True, 'Module': 'plugins.Naver_Search'},
'OK Search - Group': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.OK_Search', 'Type': 'Group'},
'OK Search - User': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.OK_Search', 'Type': 'User'},
'Phishstats Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Phishstats_Search', 'Organisation_Presets': 'domain'},
'Phone Search - Cellular Number': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Phone_Search', 'Organisation_Presets': 'identity_phones', 'Type': 'Number', 'Safe_Characters': ['+']},
'Phone Search - IMEI Number': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Phone_Search', 'Type': 'IMEI'},
'Phone Search - IMSI Number': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Phone_Search', 'Type': 'IMSI'},
'Phone Search - ISPC Number': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Phone_Search', 'Type': 'ISPC'},
'Phone Search - SIM Number': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Phone_Search', 'Type': 'SIM'},
'Pinterest - Board Search': {'Requires_Configuration': True, 'Requires_Limit': True, 'Module': 'plugins.Pinterest_Search', 'Type': 'Board'},
'Pinterest - Pin Search': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Pinterest_Search', 'Type': 'Pin'},
'PSB Dump Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.PSBDump_Search'},
'Pulsedive Search': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Pulsedive_Search'},
'RSS Feed Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.RSS_Feed_Search', 'Organisation_Presets': 'name'},
'Reddit Search': {'Requires_Configuration': True, 'Requires_Limit': True, 'Module': 'plugins.Reddit_Search'},
'Shodan Search - IP Address': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Shodan_Search', 'Type': 'Host'},
'Shodan Search - Query': {'Requires_Configuration': True, 'Requires_Limit': True, 'Module': 'plugins.Shodan_Search', 'Type': 'Search'},
'Spamcop Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Spamcop_Search'},
'Threat Crowd - Antivirus Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Threat_Crowd_Search', 'Type': 'AV'},
'Threat Crowd - Domain Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Threat_Crowd_Search', 'Organisation_Presets': 'domain', 'Type': 'Domain'},
'Threat Crowd - Email Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Threat_Crowd_Search', 'Organisation_Presets': 'identity_emails', 'Type': 'Email'},
'Threat Crowd - IP Address Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Threat_Crowd_Search', 'Type': 'IP Address'},
'Threat Crowd - Virus Report Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Threat_Crowd_Search', 'Type': 'Virus Report'},
'Torrent Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Torrent_Search'},
'Tumblr Search': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Tumblr_Search'},
'Trumail Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Trumail_Search'},
'Twitter Search': {'Requires_Configuration': True, 'Requires_Limit': True, 'Module': 'plugins.Twitter_Search'},
'URLScan Search': {'Requires_Configuration': True, 'Requires_Limit': True, 'Module': 'plugins.URLScan_Search', 'Organisation_Presets': 'domain'},
'Username Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Username_Search', 'Organisation_Presets': 'identity_usernames'},
'User Search - Get Gender from Fullname (ML)': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Username_NameAPI_Search', 'Type': 'Gender'},
'User Search - Get Name from Email (ML)': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Username_NameAPI_Search', 'Type': 'Name', 'Organisation_Presets': 'identity_emails'},
'User Search - Determine if Email is Disposable (ML)': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Username_NameAPI_Search', 'Type': 'Disposable', 'Organisation_Presets': 'identity_emails'},
'Vehicle Registration Search (Australia)': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Vehicle_Registration_Search'},
'Virus Total Search - Domain': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Virus_Total_Search', 'Organisation_Presets': 'domain', 'Type': 'Domain'},
'Virus Total Search - File Hash': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Virus_Total_Search', 'Type': 'Hash'},
'Virus Total Search - IP Address': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Virus_Total_Search', 'Type': 'IP'},
'Virus Total Search - URL': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.Virus_Total_Search', 'Organisation_Presets': 'website', 'Type': 'URL'},
'Vkontakte - Group Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Vkontakte_Search', 'Type': 'Group'},
'Vkontakte - User Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Vkontakte_Search', 'Type': 'User'},
'Vulners Search': {'Requires_Configuration': True, 'Requires_Limit': True, 'Module': 'plugins.Vulners_Search'},
'WhatCMS Search': {'Requires_Configuration': True, 'Requires_Limit': False, 'Module': 'plugins.WhatCMS_Search', 'Organisation_Presets': 'domain'},
'Wikipedia Search': {'Requires_Configuration': False, 'Requires_Limit': True, 'Module': 'plugins.Wikipedia_Search'},
'Windows Store Search': {'Requires_Configuration': True, 'Requires_Limit': True, 'Module': 'plugins.Windows_Store_Search'},
'Yandex Search': {'Requires_Configuration': True, 'Requires_Limit': True, 'Module': 'plugins.Yandex_Search'},
'YouTube Search': {'Requires_Configuration': True, 'Requires_Limit': True, 'Module': 'plugins.YouTube_Search'},
'Zone-H Search': {'Requires_Configuration': False, 'Requires_Limit': False, 'Module': 'plugins.Zone-H_Search'}}