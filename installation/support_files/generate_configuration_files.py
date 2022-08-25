import os, sys, Common

if __name__ == "__main__":
    Empty_String: str = str()
    Empty_Bool: bool = bool()
    Temporary_DB_File: dict = {
        "postgresql": {
            "host": os.environ["POSTGRES_IP"],
            "port": os.environ["POSTGRES_PORT"],
            "database": os.environ["DATABASE"],
            "user": os.environ["USER"],
            "password": os.environ["DB_PASS"]
        }
    }
    Configuration_Data: dict = {
        "inputs": {
            "bitcoinabuse": {
                "api_key": Empty_String
            },
            "craigslist": {
                "city": Empty_String
            },
            "ebay": {
                "access_key": Empty_String
            },
            "emailrep": {
                "api_key": Empty_String
            },
            "flickr": {
                "api_key": Empty_String,
                "api_secret": Empty_String
            },
            "general": {
                "location": "au"
            },
            "github": {
                "username": Empty_String,
                "token": Empty_String
            },
            "google": {
                "cx": Empty_String,
                "application_name": Empty_String,
                "application_version": Empty_String,
                "developer_key": Empty_String
            },
            "greynoisesearch": {
                "api_key": Empty_String
            },
            "haveibeenpwned": {
                "api_key": Empty_String
            },
            "hunter": {
                "api_key": Empty_String
            },
            "hybridanalysis": {
                "api_key": Empty_String
            },
            "intelligencex": {
                "api_key": Empty_String
            },
            "ipstack": {
                "api_key": Empty_String
            },
            "leaklookup": {
                "api_key": Empty_String
            },
            "nameapi": {
                "api_key": Empty_String
            },
            "naver": {
                "client_id": Empty_String,
                "client_secret": Empty_String
            },
            "ok": {
                "application_id": Empty_String,
                "application_key": Empty_String,
                "application_secret": Empty_String,
                "access_token": Empty_String,
                "session_secret": Empty_String
            },
            "pinterest": {
                "oauth_token": Empty_String
            },
            "pulsedive": {
                "api_key": Empty_String
            },
            "reddit": {
                "client_id": Empty_String,
                "client_secret": Empty_String,
                "user_agent": Empty_String,
                "username": Empty_String,
                "password": Empty_String,
                "subreddits": "all"
            },
            "shodan": {
                "api_key": Empty_String
            },
            "sslmate": {
                "search_subdomain": True
            },
            "tumblr": {
                "consumer_key": Empty_String,
                "consumer_secret": Empty_String
            },
            "twitter": {
                "consumer_key": Empty_String,
                "consumer_secret": Empty_String,
                "access_key": Empty_String,
                "access_secret": Empty_String
            },
            "ukbusiness": {
                "api_key": Empty_String
            },
            "urlscan": {
                "api_key": Empty_String
            },
            "vkontakte": {
                "access_token": Empty_String
            },
            "virustotal": {
                "api_key": Empty_String
            },
            "vulners": {
                "api_key": Empty_String
            },
            "whatcms": {
                "api_key": Empty_String
            },
            "yandex": {
                "username": Empty_String,
                "api_key": Empty_String
            },
            "youtube": {
                "developer_key": Empty_String,
                "application_name": "youtube",
                "application_version": "v3"
            }
        },
        "outputs": {
            "csv": {
                "use_csv": Empty_Bool
            },
            "docx_report": {
                "use_docx": Empty_Bool
            },
            "defectdojo": {
                "ssl": Empty_Bool,
                "api_key": Empty_String,
                "host": "host.com",
                "user": "admin",
                "engagement_id": 1,
                "product_id": 1,
                "test_id": 1,
                "user_id": 1
            },
            "elasticsearch": {
                "ssl": Empty_Bool,
                "host": Empty_String,
                "port": 9200,
                "index": "Scrummage",
                "use_timestamp": True
            },
            "email": {
                "smtp_server": Empty_String,
                "smtp_port": 587,
                "from_address": Empty_String,
                "from_password": Empty_String,
                "to_address": Empty_String
            },
            "jira": {
                "project_key": Empty_String,
                "address": Empty_String,
                "username": Empty_String,
                "password": Empty_String,
                "ticket_type": Empty_String
            },
            "postgresql": {
                "host": os.environ["POSTGRES_IP"],
                "port": os.environ["POSTGRES_PORT"],
                "database": os.environ["DATABASE"],
                "user": os.environ["USER"],
                "password": os.environ["DB_PASS"]
            },
            "rtir": {
                "ssl": Empty_Bool,
                "host": Empty_String,
                "port": 80,
                "user": Empty_String,
                "password": Empty_String,
                "authenticator": Empty_String
            },
            "scumblr": {
                "host": Empty_String,
                "port": 5432,
                "database": Empty_String,
                "user": Empty_String,
                "password": Empty_String
            },
            "slack": {
                "token": Empty_String,
                "channel": Empty_String
            }
        },
        "core": {
            "google_chrome": {
                "application_path": "/usr/bin/google-chrome",
                "chromedriver_path": "/usr/bin/chromedriver"
            },
            "organisation": {
                "name": Empty_String,
                "website": Empty_String,
                "domain": Empty_String,
                "subdomains": [
                    "domain.com"
                ]
            },
            "proxy": {
                "http": Empty_String,
                "https": Empty_String,
                "use_system_proxy": Empty_Bool
            },
            "web_app": {
                "debug": Empty_Bool,
                "host": os.environ["SCRUMMAGE_IP"],
                "port": os.environ["SCRUMMAGE_PORT"],
                "certificate_file": os.environ["CERTIFICATE_CRT"],
                "key_file": os.environ["PRIVATE_KEY"],
                "api_secret": os.environ["API_SECRET"],
                "api_validity_minutes": 60,
                "api_max_calls": 10,
                "api_period_in_seconds": 60
            },
            "web_scraping": {
                "automated_screenshots": Empty_Bool,
                "risk_level": 2
            }
        }
    }
    Configuration_File, DB_File = Common.Get_Relative_Configuration()
    JSON_File = open(Configuration_File, "w")
    JSON_File.write(Common.Cryptography().configuration_encrypt(Common.JSON_Handler(Configuration_Data).Dump_JSON()))
    JSON_File.close()
    JSON_File = open(DB_File, "w")
    JSON_File.write(Common.Cryptography().configuration_encrypt(Common.JSON_Handler(Temporary_DB_File).Dump_JSON()))
    JSON_File.close()
