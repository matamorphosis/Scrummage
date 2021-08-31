#!/usr/bin/env python3
import logging, os, hashlib, plugins.common.General as General, plugins.common.Common as Common

class Plugin_Search:

    def __init__(self, Query_List, Task_ID, Type):
        self.Plugin_Name = "OK"
        self.Logging_Plugin_Name = General.Get_Plugin_Logging_Name(self.Plugin_Name)
        self.Task_ID = Task_ID
        self.Query_List = General.Convert_to_List(Query_List)
        self.The_File_Extensions = {"Main": ".json", "Query": ".html"}
        self.Domain = "ok.ru"
        self.Type = Type

    def Load_Configuration(self):
        logging.info(f"{Common.Date()} - {self.Logging_Plugin_Name} - Loading configuration data.")
        Result = Common.Configuration(Input=True).Load_Configuration(Object=self.Plugin_Name.lower(), Details_to_Load=["application_id", "application_key", "application_secret", "access_token", "session_secret"])

        if Result:
            return Result

        else:
            return None

    def Search(self):

        try:
            Data_to_Cache = []
            Directory = General.Make_Directory(self.Plugin_Name.lower())
            logger = logging.getLogger()
            logger.setLevel(logging.INFO)
            handler = logging.FileHandler(os.path.join(Directory, General.Logging(Directory, self.Plugin_Name)), "w")
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
            logger.addHandler(handler)
            OK_API_Details = self.Load_Configuration()
            Cached_Data_Object = General.Cache(Directory, self.Plugin_Name)
            Cached_Data = Cached_Data_Object.Get_Cache()

            for Query in self.Query_List:

                if self.Type == "User":
                    Query = str(int(Query))
                    String_to_Hash = f"application_key={OK_API_Details[1]}fields=ACCESSIBLE,AGE,ALLOWS_ANONYM_ACCESS,ALLOWS_MESSAGING_ONLY_FOR_FRIENDS,ALLOW_ADD_TO_FRIEND,BECOME_VIP_ALLOWED,BIRTHDAY,BLOCKED,BLOCKS,BUSINESS,CAN_USE_REFERRAL_INVITE,CAN_VCALL,CAN_VMAIL,CITY_OF_BIRTH,CLOSE_COMMENTS_ALLOWED,COMMON_FRIENDS_COUNT,CURRENT_LOCATION,CURRENT_STATUS,CURRENT_STATUS_DATE,CURRENT_STATUS_DATE_MS,CURRENT_STATUS_ID,CURRENT_STATUS_MOOD,CURRENT_STATUS_TRACK_ID,EMAIL,EXECUTOR,FIRST_NAME,FIRST_NAME_INSTRUMENTAL,FOLLOWERS_COUNT,FORBIDS_MENTIONING,FRIEND,FRIENDS_COUNT,FRIEND_INVITATION,FRIEND_INVITE_ALLOWED,GENDER,GROUP_INVITE_ALLOWED,HAS_DAILY_PHOTO,HAS_EMAIL,HAS_GROUPS_TO_COMMENT,HAS_PHONE,HAS_PRODUCTS,HAS_SERVICE_INVISIBLE,INTERNAL_PIC_ALLOW_EMPTY,INVITED_BY_FRIEND,IS_MERCHANT,LAST_NAME,LAST_NAME_INSTRUMENTAL,LAST_ONLINE,LAST_ONLINE_MS,LOCALE,LOCATION,LOCATION_OF_BIRTH,MODIFIED_MS,NAME,NAME_INSTRUMENTAL,ODKL_BLOCK_REASON,ODKL_EMAIL,ODKL_LOGIN,ODKL_MOBILE,ODKL_MOBILE_ACTIVATION_DATE,ODKL_MOBILE_STATUS,ODKL_USER_OPTIONS,ODKL_USER_STATUS,ODKL_VOTING,ONLINE,PHOTO_ID,PIC1024X768,PIC128MAX,PIC128X128,PIC180MIN,PIC190X190,PIC224X224,PIC240MIN,PIC288X288,PIC320MIN,PIC50X50,PIC600X600,PIC640X480,PIC_1,PIC_2,PIC_3,PIC_4,PIC_5,PIC_BASE,PIC_FULL,PIC_MAX,POSSIBLE_RELATIONS,PREMIUM,PRESENTS,PRIVATE,PROFILE_BUTTONS,PROFILE_COVER,PROFILE_PHOTO_SUGGEST_ALLOWED,PYMK_PIC224X224,PYMK_PIC288X288,PYMK_PIC600X600,PYMK_PIC_FULL,REF,REGISTERED_DATE,REGISTERED_DATE_MS,RELATIONS,RELATIONSHIP,SEND_MESSAGE_ALLOWED,SHORTNAME,SHOW_LOCK,STATUS,TOTAL_PHOTOS_COUNT,UID,URL_CHAT,URL_CHAT_MOBILE,URL_PROFILE,URL_PROFILE_MOBILE,VIPformat=jsonmethod=users.getInfouids={Query}{OK_API_Details[4]}"
                    Signature = hashlib.md5(String_to_Hash.encode()).hexdigest()
                    OK_Response = Common.Request_Handler(f"https://api.{self.Domain}/fb.do?application_key={OK_API_Details[1]}&fields=ACCESSIBLE%2CAGE%2CALLOWS_ANONYM_ACCESS%2CALLOWS_MESSAGING_ONLY_FOR_FRIENDS%2CALLOW_ADD_TO_FRIEND%2CBECOME_VIP_ALLOWED%2CBIRTHDAY%2CBLOCKED%2CBLOCKS%2CBUSINESS%2CCAN_USE_REFERRAL_INVITE%2CCAN_VCALL%2CCAN_VMAIL%2CCITY_OF_BIRTH%2CCLOSE_COMMENTS_ALLOWED%2CCOMMON_FRIENDS_COUNT%2CCURRENT_LOCATION%2CCURRENT_STATUS%2CCURRENT_STATUS_DATE%2CCURRENT_STATUS_DATE_MS%2CCURRENT_STATUS_ID%2CCURRENT_STATUS_MOOD%2CCURRENT_STATUS_TRACK_ID%2CEMAIL%2CEXECUTOR%2CFIRST_NAME%2CFIRST_NAME_INSTRUMENTAL%2CFOLLOWERS_COUNT%2CFORBIDS_MENTIONING%2CFRIEND%2CFRIENDS_COUNT%2CFRIEND_INVITATION%2CFRIEND_INVITE_ALLOWED%2CGENDER%2CGROUP_INVITE_ALLOWED%2CHAS_DAILY_PHOTO%2CHAS_EMAIL%2CHAS_GROUPS_TO_COMMENT%2CHAS_PHONE%2CHAS_PRODUCTS%2CHAS_SERVICE_INVISIBLE%2CINTERNAL_PIC_ALLOW_EMPTY%2CINVITED_BY_FRIEND%2CIS_MERCHANT%2CLAST_NAME%2CLAST_NAME_INSTRUMENTAL%2CLAST_ONLINE%2CLAST_ONLINE_MS%2CLOCALE%2CLOCATION%2CLOCATION_OF_BIRTH%2CMODIFIED_MS%2CNAME%2CNAME_INSTRUMENTAL%2CODKL_BLOCK_REASON%2CODKL_EMAIL%2CODKL_LOGIN%2CODKL_MOBILE%2CODKL_MOBILE_ACTIVATION_DATE%2CODKL_MOBILE_STATUS%2CODKL_USER_OPTIONS%2CODKL_USER_STATUS%2CODKL_VOTING%2CONLINE%2CPHOTO_ID%2CPIC1024X768%2CPIC128MAX%2CPIC128X128%2CPIC180MIN%2CPIC190X190%2CPIC224X224%2CPIC240MIN%2CPIC288X288%2CPIC320MIN%2CPIC50X50%2CPIC600X600%2CPIC640X480%2CPIC_1%2CPIC_2%2CPIC_3%2CPIC_4%2CPIC_5%2CPIC_BASE%2CPIC_FULL%2CPIC_MAX%2CPOSSIBLE_RELATIONS%2CPREMIUM%2CPRESENTS%2CPRIVATE%2CPROFILE_BUTTONS%2CPROFILE_COVER%2CPROFILE_PHOTO_SUGGEST_ALLOWED%2CPYMK_PIC224X224%2CPYMK_PIC288X288%2CPYMK_PIC600X600%2CPYMK_PIC_FULL%2CREF%2CREGISTERED_DATE%2CREGISTERED_DATE_MS%2CRELATIONS%2CRELATIONSHIP%2CSEND_MESSAGE_ALLOWED%2CSHORTNAME%2CSHOW_LOCK%2CSTATUS%2CTOTAL_PHOTOS_COUNT%2CUID%2CURL_CHAT%2CURL_CHAT_MOBILE%2CURL_PROFILE%2CURL_PROFILE_MOBILE%2CVIP&format=json&method=users.getInfo&uids={Query}&sig={Signature}&access_token={OK_API_Details[3]}")
                    JSON_Object = Common.JSON_Handler(OK_Response)
                    JSON_Response = JSON_Object.To_JSON_Loads()
                    JSON_Output_Response = JSON_Object.Dump_JSON()
                    Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, "Social Media - Person", self.Task_ID, self.Plugin_Name.lower())

                    try:

                        if "error_code" not in JSON_Response and self.Type(JSON_Response) == list:
                            # These conditions could be so much simpler if the API returned a response code other than 200 for both successful requests and errors.
                            OK_Item = JSON_Response[0]

                            if all(Item in OK_Item for Item in ["first_name", "last_name"]):
                                OK_URL = f"https://{self.Domain}/profile/{Query}"

                                if OK_Item["last_name"] not in ["", " "]:
                                    Full_Name = OK_Item["first_name"] + " " + OK_Item["last_name"]

                                else:
                                    Full_Name = OK_Item["first_name"]

                                Title = f"{self.Plugin_Name} User | {Full_Name}"

                                if OK_URL not in Cached_Data and OK_URL not in Data_to_Cache:
                                    OK_Item_Responses = Common.Request_Handler(OK_URL, Filter=True, Host=f"https://{self.Domain}")
                                    OK_Item_Response = OK_Item_Responses["Filtered"]
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, OK_Item_Response, OK_URL, self.The_File_Extensions["Query"])

                                    if Output_file:
                                        Output_Connections.Output([Main_File, Output_file], OK_URL, Title, self.Plugin_Name.lower())
                                        Data_to_Cache.append(OK_URL)

                                    else:
                                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid response.")

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid query provided, the user ID provided possibly doesn't exist.")

                    except Exception as e:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")

                elif self.Type == "Group":
                    Query = str(int(Query))
                    String_to_Hash = f"application_key={OK_API_Details[1]}fields=ABBREVIATION,ACCESS_TYPE,ADDRESS,ADD_CHANNEL_ALLOWED,ADD_PAID_THEME_ALLOWED,ADD_PHOTOALBUM_ALLOWED,ADD_THEME_ALLOWED,ADD_VIDEO_ALLOWED,ADMIN_ID,ADS_MANAGER_ALLOWED,ADVANCED_PUBLICATION_ALLOWED,AGE_RESTRICTED,BLOCKED,BUSINESS,CALL_ALLOWED,CATALOG_CREATE_ALLOWED,CATEGORY,CHANGE_AVATAR_ALLOWED,CHANGE_TYPE_ALLOWED,CITY,COMMENT_AS_OFFICIAL,COMMUNITY,CONTENT_AS_OFFICIAL,COUNTRY,COVER,COVER_BUTTONS,COVER_SERIES,CREATED_MS,CREATE_ADS_ALLOWED,DELETE_ALLOWED,DESCRIPTION,DISABLE_PHOTO_UPLOAD,EDIT_ALLOWED,EDIT_APPS_ALLOWED,END_DATE,FEED_SUBSCRIPTION,FOLLOWERS_COUNT,FOLLOW_ALLOWED,FRIENDS_COUNT,GRADUATE_YEAR,GROUP_CHALLENGE_CREATE_ALLOWED,GROUP_JOURNAL_ALLOWED,GROUP_NEWS,HOMEPAGE_NAME,HOMEPAGE_URL,INVITATIONS_COUNT,INVITATION_SENT,INVITE_ALLOWED,INVITE_FREE_ALLOWED,JOIN_ALLOWED,JOIN_REQUESTS_COUNT,LEAVE_ALLOWED,LINK_CAROUSEL_ALLOWED,LINK_POSTING_ALLOWED,LOCATION_ID,LOCATION_LATITUDE,LOCATION_LONGITUDE,LOCATION_ZOOM,MAIN_PAGE_TAB,MAIN_PHOTO,MANAGE_MEMBERS,MANAGE_MESSAGING_ALLOWED,MEMBERS_COUNT,MEMBER_STATUS,MENTIONS_SUBSCRIPTION,MENTIONS_SUBSCRIPTION_ALLOWED,MESSAGES_ALLOWED,MESSAGING_ALLOWED,MESSAGING_ENABLED,MIN_AGE,MOBILE_COVER,NAME,NEW_CHATS_COUNT,NOTIFICATIONS_SUBSCRIPTION,ONLINE_PAYMENT_ALLOWED,PAID_ACCESS,PAID_ACCESS_DESCRIPTION,PAID_ACCESS_PRICE,PAID_CONTENT,PAID_CONTENT_DESCRIPTION,PAID_CONTENT_PRICE,PARTNER_PROGRAM_ALLOWED,PARTNER_PROGRAM_STATUS,PENALTY_POINTS_ALLOWED,PHONE,PHOTOS_TAB_HIDDEN,PHOTO_ID,PIC_AVATAR,PIN_NOTIFICATIONS_OFF,POSSIBLE_MEMBERS_COUNT,PREMIUM,PRIVATE,PRODUCTS_TAB_HIDDEN,PRODUCT_CREATE_ALLOWED,PRODUCT_CREATE_SUGGESTED_ALLOWED,PRODUCT_CREATE_ZERO_LIFETIME_ALLOWED,PROFILE_BUTTONS,PROMO_THEME_ALLOWED,PUBLISH_DELAYED_THEME_ALLOWED,REF,REQUEST_SENT,REQUEST_SENT_DATE,RESHARE_ALLOWED,ROLE,SCOPE_ID,SHOP_VISIBLE_ADMIN,SHOP_VISIBLE_PUBLIC,SHORTNAME,START_DATE,STATS_ALLOWED,STATUS,SUBCATEGORY_ID,SUGGEST_THEME_ALLOWED,TAGS,TRANSFERS_ALLOWED,UID,UNFOLLOW_ALLOWED,USER_PAID_ACCESS,USER_PAID_ACCESS_TILL,USER_PAID_CONTENT,USER_PAID_CONTENT_TILL,VIDEO_TAB_HIDDEN,VIEW_MEMBERS_ALLOWED,VIEW_MODERATORS_ALLOWED,VIEW_PAID_THEMES_ALLOWED,YEAR_FROM,YEAR_TOformat=jsonmethod=group.getInfouids={Query}{OK_API_Details[4]}"
                    Signature = hashlib.md5(String_to_Hash.encode()).hexdigest()
                    OK_Response = Common.Request_Handler(f"https://api.{self.Domain}/fb.do?application_key={OK_API_Details[1]}&fields=ABBREVIATION%2CACCESS_TYPE%2CADDRESS%2CADD_CHANNEL_ALLOWED%2CADD_PAID_THEME_ALLOWED%2CADD_PHOTOALBUM_ALLOWED%2CADD_THEME_ALLOWED%2CADD_VIDEO_ALLOWED%2CADMIN_ID%2CADS_MANAGER_ALLOWED%2CADVANCED_PUBLICATION_ALLOWED%2CAGE_RESTRICTED%2CBLOCKED%2CBUSINESS%2CCALL_ALLOWED%2CCATALOG_CREATE_ALLOWED%2CCATEGORY%2CCHANGE_AVATAR_ALLOWED%2CCHANGE_TYPE_ALLOWED%2CCITY%2CCOMMENT_AS_OFFICIAL%2CCOMMUNITY%2CCONTENT_AS_OFFICIAL%2CCOUNTRY%2CCOVER%2CCOVER_BUTTONS%2CCOVER_SERIES%2CCREATED_MS%2CCREATE_ADS_ALLOWED%2CDELETE_ALLOWED%2CDESCRIPTION%2CDISABLE_PHOTO_UPLOAD%2CEDIT_ALLOWED%2CEDIT_APPS_ALLOWED%2CEND_DATE%2CFEED_SUBSCRIPTION%2CFOLLOWERS_COUNT%2CFOLLOW_ALLOWED%2CFRIENDS_COUNT%2CGRADUATE_YEAR%2CGROUP_CHALLENGE_CREATE_ALLOWED%2CGROUP_JOURNAL_ALLOWED%2CGROUP_NEWS%2CHOMEPAGE_NAME%2CHOMEPAGE_URL%2CINVITATIONS_COUNT%2CINVITATION_SENT%2CINVITE_ALLOWED%2CINVITE_FREE_ALLOWED%2CJOIN_ALLOWED%2CJOIN_REQUESTS_COUNT%2CLEAVE_ALLOWED%2CLINK_CAROUSEL_ALLOWED%2CLINK_POSTING_ALLOWED%2CLOCATION_ID%2CLOCATION_LATITUDE%2CLOCATION_LONGITUDE%2CLOCATION_ZOOM%2CMAIN_PAGE_TAB%2CMAIN_PHOTO%2CMANAGE_MEMBERS%2CMANAGE_MESSAGING_ALLOWED%2CMEMBERS_COUNT%2CMEMBER_STATUS%2CMENTIONS_SUBSCRIPTION%2CMENTIONS_SUBSCRIPTION_ALLOWED%2CMESSAGES_ALLOWED%2CMESSAGING_ALLOWED%2CMESSAGING_ENABLED%2CMIN_AGE%2CMOBILE_COVER%2CNAME%2CNEW_CHATS_COUNT%2CNOTIFICATIONS_SUBSCRIPTION%2CONLINE_PAYMENT_ALLOWED%2CPAID_ACCESS%2CPAID_ACCESS_DESCRIPTION%2CPAID_ACCESS_PRICE%2CPAID_CONTENT%2CPAID_CONTENT_DESCRIPTION%2CPAID_CONTENT_PRICE%2CPARTNER_PROGRAM_ALLOWED%2CPARTNER_PROGRAM_STATUS%2CPENALTY_POINTS_ALLOWED%2CPHONE%2CPHOTOS_TAB_HIDDEN%2CPHOTO_ID%2CPIC_AVATAR%2CPIN_NOTIFICATIONS_OFF%2CPOSSIBLE_MEMBERS_COUNT%2CPREMIUM%2CPRIVATE%2CPRODUCTS_TAB_HIDDEN%2CPRODUCT_CREATE_ALLOWED%2CPRODUCT_CREATE_SUGGESTED_ALLOWED%2CPRODUCT_CREATE_ZERO_LIFETIME_ALLOWED%2CPROFILE_BUTTONS%2CPROMO_THEME_ALLOWED%2CPUBLISH_DELAYED_THEME_ALLOWED%2CREF%2CREQUEST_SENT%2CREQUEST_SENT_DATE%2CRESHARE_ALLOWED%2CROLE%2CSCOPE_ID%2CSHOP_VISIBLE_ADMIN%2CSHOP_VISIBLE_PUBLIC%2CSHORTNAME%2CSTART_DATE%2CSTATS_ALLOWED%2CSTATUS%2CSUBCATEGORY_ID%2CSUGGEST_THEME_ALLOWED%2CTAGS%2CTRANSFERS_ALLOWED%2CUID%2CUNFOLLOW_ALLOWED%2CUSER_PAID_ACCESS%2CUSER_PAID_ACCESS_TILL%2CUSER_PAID_CONTENT%2CUSER_PAID_CONTENT_TILL%2CVIDEO_TAB_HIDDEN%2CVIEW_MEMBERS_ALLOWED%2CVIEW_MODERATORS_ALLOWED%2CVIEW_PAID_THEMES_ALLOWED%2CYEAR_FROM%2CYEAR_TO&format=json&method=group.getInfo&uids={Query}&sig={Signature}&access_token={OK_API_Details[3]}")
                    JSON_Object = Common.JSON_Handler(OK_Response)
                    JSON_Response = JSON_Object.To_JSON_Loads()
                    JSON_Output_Response = JSON_Object.Dump_JSON()
                    Main_File = General.Main_File_Create(Directory, self.Plugin_Name, JSON_Output_Response, Query, self.The_File_Extensions["Main"])
                    Output_Connections = General.Connections(Query, self.Plugin_Name, self.Domain, "Social Media - Group", self.Task_ID, self.Plugin_Name.lower())

                    try:

                        if "error_code" not in JSON_Response and self.Type(JSON_Response) == list:
                            OK_Item = JSON_Response[0]

                            if all(Item in OK_Item for Item in ["name", "shortname"]):
                                OK_URL = f"https://{self.Domain}/" + OK_Item["shortname"]
                                Full_Name = OK_Item["name"]
                                Title = f"{self.Plugin_Name} Group | {Full_Name}"

                                if OK_URL not in Cached_Data and OK_URL not in Data_to_Cache:
                                    OK_Item_Responses = Common.Request_Handler(OK_URL, Filter=True, Host=f"https://{self.Domain}")
                                    OK_Item_Response = OK_Item_Responses["Filtered"]
                                    Output_file = General.Create_Query_Results_Output_File(Directory, Query, self.Plugin_Name, OK_Item_Response, OK_URL, self.The_File_Extensions["Query"])

                                    if Output_file:
                                        Output_Connections.Output([Main_File, Output_file], OK_URL, Title, self.Plugin_Name.lower())
                                        Data_to_Cache.append(OK_URL)

                                    else:
                                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Failed to create output file. File may already exist.")

                            else:
                                logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid response.")

                        else:
                            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid query provided, the group ID provided possibly doesn't exist.")

                    except Exception as e:
                        logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")

                else:
                    logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - Invalid type supplied.")

            Cached_Data_Object.Write_Cache(Data_to_Cache)

        except Exception as e:
            logging.warning(f"{Common.Date()} - {self.Logging_Plugin_Name} - {str(e)}")