from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import NoSuchElementException

from selenium.webdriver.common.by import By

from selenium.webdriver.support import expected_conditions as EC
from seleniumwire import webdriver


import os
import time
import requests

#BINANCE CLAS NAMES
BINANCE_LOGGED_IN_ICON_XPATH = "//body/div/div/header/div[3]/div[1]//*[name()='svg']"
BINANCE_NFT_TERMS_ACCEPTBTN_XPATH = "//button[normalize-space()='Accept']"

BINANCE_NFT_TIMER_DAYS_XPATH = "//div[normalize-space()='Days']/preceding-sibling::div"
BINANCE_NFT_TIMER_HOURS_XPATH = "//div[normalize-space()='Hours']/preceding-sibling::div"
BINANCE_NFT_TIMER_MINUTES_XPATH = "//div[normalize-space()='Mins']/preceding-sibling::div"
BINANCE_NFT_TIMER_SECONDS_XPATH = "//div[normalize-space()='Secs']/preceding-sibling::div"

BINANCE_NFT_MARKETPLACE_ITEMS_XPATH = "(//div[@data-bn-type='text'][normalize-space()='Current bid'])"
BINANCE_NFT_MARKETPLACE_PLACE_BID_XPATH = "//button[normalize-space()='Place a Bid']"
BINANCE_NFT_MARKETPLACE_CONFIRM_BID_XPATH = "//div[contains(text(),'Place a Bid')]"

#https://www.binance.com/bapi/nft/v1/private/nft/nft-trade/order-create
#https://www.binance.com/bapi/nft/v1/private/nft/mystery-box/purchase


chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument("--incognito")
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("disable-infobars")

web_driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

web_driver.get("https://accounts.binance.com/en/login")

print("Please login into your account...")

wait = WebDriverWait(web_driver, 300)

wait.until(EC.visibility_of_element_located((By.XPATH, BINANCE_LOGGED_IN_ICON_XPATH)))

print("Login succesfull!")

str_mysterybox_id = input("Target MysteryBOX ID : ")
str_mysterybox_count = input("Boxes to purchase : ")

mysterbox_link = "https://www.binance.com/en/nft/mystery-box/detail?productId="+ str_mysterybox_id +"&number="+str_mysterybox_count+""

web_driver.get(mysterbox_link)

print("Looking for Binance NFT TOS message...")
try:
    wait = WebDriverWait(web_driver, 5)
    accept_btn = wait.until(EC.visibility_of_element_located((By.XPATH, BINANCE_NFT_TERMS_ACCEPTBTN_XPATH)))
    accept_btn.click()
    print("Binance TOS accepted...")
except NoSuchElementException:
    print("Binance NFT TOS window not located...")

print("Calculating Sale Start time...")

try:
    wait = WebDriverWait(web_driver, 5)
    SALE_TIME_DAYS = wait.until(EC.visibility_of_element_located((By.XPATH, BINANCE_NFT_TIMER_DAYS_XPATH)))
    SALE_TIME_HOURS = wait.until(EC.visibility_of_element_located((By.XPATH, BINANCE_NFT_TIMER_HOURS_XPATH)))
    SALE_TIME_MINUTES = wait.until(EC.visibility_of_element_located((By.XPATH, BINANCE_NFT_TIMER_MINUTES_XPATH)))
    SALE_TIME_SECONDS = wait.until(EC.visibility_of_element_located((By.XPATH, BINANCE_NFT_TIMER_SECONDS_XPATH)))
    request_time = time.time()
except NoSuchElementException:
    print("Failed locating count-down timer")
    web_driver.quit()

print("D:" + SALE_TIME_DAYS.text)
print("H:" + SALE_TIME_HOURS.text)
print("M:" + SALE_TIME_MINUTES.text)
print("S:" + SALE_TIME_SECONDS.text)

time_remaining = int(SALE_TIME_DAYS.text) * 86400
time_remaining += int(SALE_TIME_HOURS.text) * 3600
time_remaining += int(SALE_TIME_MINUTES.text) * 60
time_remaining += int(SALE_TIME_SECONDS.text)

time_remaining += request_time

while (time_remaining - time.time() > 240):
    print("Seconds Remaining : " + str(time_remaining - time.time()))
    time.sleep(1)

#Navigate to store page and place a bid on random item, to recieve headers
print("Looking for a cheap item to bid on...")
web_driver.get("https://www.binance.com/en/nft/marketplace?currency=BUSD&tradeType=1&amountFrom=0.1&amountTo=0.5&page=1&rows=16&order=set_end_time%401")

try:
    wait = WebDriverWait(web_driver, 5)
    FIRST_NFT_ITEM = wait.until(EC.visibility_of_element_located((By.XPATH, BINANCE_NFT_MARKETPLACE_ITEMS_XPATH)))
except NoSuchElementException:
    print("Failed locating NFT Marketplace Biddable Item...")
    web_driver.quit()

#Click on the item to be redirected
print("Opening NFT MarketPlace item...")
FIRST_NFT_ITEM.click()

#Waiting for some time for the request to go thru
time.sleep(3)

web_driver.switch_to.window(web_driver.window_handles[1])
print("Active Window Title : " + web_driver.title)


try:
    wait = WebDriverWait(web_driver, 15)
    PLACE_BID_BTN = wait.until(EC.visibility_of_element_located((By.XPATH, BINANCE_NFT_MARKETPLACE_PLACE_BID_XPATH)))
except NoSuchElementException:
    print("Failed locating NFT Marketplace PLACE BID BTN...")
    web_driver.quit()

print("Placing BID on item...")
PLACE_BID_BTN.click()

try:
    wait = WebDriverWait(web_driver, 15)
    PLACE_BID_BTN = wait.until(EC.visibility_of_element_located((By.XPATH, BINANCE_NFT_MARKETPLACE_CONFIRM_BID_XPATH)))
except NoSuchElementException:
    print("Failed locating NFT Marketplace Confirm BID BTN...")
    web_driver.quit()

print("Confirming BID on item...")
PLACE_BID_BTN.click()

#Waiting for some time for the request to go thru
time.sleep(3)

print("Looking for create-order request...")

REQUEST_LOCATED = False

for request in web_driver.requests:
    if request.response:
        if str(request.url) == "https://www.binance.com/bapi/nft/v1/private/nft/nft-trade/order-create":
            print(
                  request.url,
                  request.response.status_code,
                  request.response.headers['Content-Type'])
            TARGET_REQUEST = request
            REQUEST_LOCATED = True

#print("Request Body : " + str(TARGET_REQUEST.body))


if REQUEST_LOCATED == False:
    print("Failed order-create request...")
    web_driver.quit()

print("Located order-create request...")

#request info dump
#print("x-nft-checkbot-sitekey : " + str(TARGET_REQUEST.headers['x-nft-checkbot-sitekey']))
#print("x-nft-checkbot-token : " + str(TARGET_REQUEST.headers['x-nft-checkbot-token']))
#print("x-trace-id : " + str(TARGET_REQUEST.headers['x-trace-id']))
#print("x-ui-request-trace : " + str(TARGET_REQUEST.headers['x-ui-request-trace']))
#print("request_body : " + str(TARGET_REQUEST.body))

#request_body_json = json.loads(TARGET_REQUEST.body)
#print(" > productID : " + str(request_body_json['productId']))
#print(" > userId : " + str(request_body_json['userId']))

print("Switching browser tab, to the original...")
#web_driver.close()

#Redirecting back to myster box link
web_driver.get(mysterbox_link)
print("Creating new body for create-order request..")

purchase_box_body = {
    'number': str_mysterybox_count,
    'productId': str_mysterybox_id
    }

#print("purchase_box_body : " + str(purchase_box_body))

s = requests.session()
#selenium_user_agent = web_driver.execute_script("return navigator.userAgent;")
#s.headers.update({"user-agent": selenium_user_agent})

for cookie in web_driver.get_cookies():
    s.cookies.set(cookie['name'], cookie['value'], domain=cookie['domain'])

#Setting the link the request was made from
TARGET_REQUEST.headers['referer'] = mysterbox_link

for hed in TARGET_REQUEST.headers:
    #print("hed : " + str(hed) + " , " + str(TARGET_REQUEST.headers[hed]))
    s.headers.update({hed: TARGET_REQUEST.headers[hed]})

s.get(mysterbox_link)

#print("TARGET_REQUEST : " + str(TARGET_REQUEST.headers))
#print("session_request : " + str(s.headers))
#print("COOKIE TARGET_REQUEST : " + str(web_driver.get_cookies()))
#print("COOKIE session_request : " + str(s.cookies))


#purchase_box_body = {
#    'amount': '0.1',
#    'productId': 36421499,
#    'tradeType': 1,
#    'userId': 284081164
#    }
#resp = s.post("https://www.binance.com/bapi/nft/v1/private/nft/nft-trade/order-create", json=purchase_box_body)

order_succeeded = False
post_attempts = 0

while (time_remaining - time.time() > 2):
    print("Seconds Remaining : " + str(time_remaining - time.time()))
    time.sleep(1)

print("Sending buy requests to Binance server...")

while order_succeeded == False:
    post_responce = s.post("https://www.binance.com/bapi/nft/v1/private/nft/mystery-box/purchase", json=purchase_box_body)
    post_attempts += 1
    #print(str(post_attempts) + " " + post_responce.text)
    if (post_responce.json()['success']):
        order_succeeded = True
        break
    if post_attempts >= 25:
        break
    #time.sleep(0.005)

if order_succeeded:
    print("Box purchased succesfully!")
else:
    print("Damm Bro, sucks to suck...")
    print("Last request response : " + post_responce.text)

#resp = s.post("https://www.binance.com/bapi/nft/v1/private/nft/mystery-box/purchase", json=purchase_box_body)

print("Script execution finished...")

os.system("pause")
web_driver.quit()