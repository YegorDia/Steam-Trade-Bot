from steam_bot import SteamBot

test_info = {
    "username": "*",
    "password": "*",
    "email": "*",
    "email_password": "*"
}

if __name__ == "__main__":
    bot = SteamBot(test_info["username"], email=test_info["email"], email_password=test_info["email_password"])
    bot.check_logon()
    if not bot._logged_in:
        bot.mobile_login(test_info["password"])
    bot.api_key()


