#coding:utf-8
import requests
import json
from twilio.rest import Client


def req_api_beijing():
    res_beijing = requests.get('http://t.weather.sojson.com/api/weather/city/101010100')
    return res_beijing

def req_api_taiyuan():
    res_taiyuan = requests.get('http://t.weather.sojson.com/api/weather/city/101100101')
    return res_taiyuan

def get_info(res):
    info = [] 
    result = res.json()
    if result['status'] == 200:
        date = result['date']
        city = result['cityInfo']
        today = result['data']['forecast'][0]
        tomorrow = result['data']['forecast'][1]
        aftertomorrow = result['data']['forecast'][2]
        info.append("**日期**:{}".format(result['date']))
        info.append("**城市**:{}".format(result['cityInfo']))
        info.append("**今日天气**:{}".format(result['data']['forecast'][0]))
        info.append("**明日天气**:{}".format(result['data']['forecast'][1]))
        info.append("**后日天气**:{}".format(result['data']['forecast'][2]))
        string = " | ".join(str(i) for i in info)
        string = string.replace('\'','')
        string = string.replace('<','小于')
        string = string.replace('>','大于')
        return string
    else:
        print('API BREAK!')
        return 'API BREAK!'

def send_info(to_number,from_number,info):
    account_sid = "AC129418c9c5d9b91f63bb687c8c547e38"
    auth_token = "e90bcbf52fb2daaca79439575288b413"
    client = Client(account_sid, auth_token)
    message = client.messages.create(to = to_number,from_ = from_number,body = info)
    print(message.sid)

def send_info_wechat_us(info):
    r1 = requests.post('https://sc.ftqq.com/SCU72677T938a51d1561e26da0b26bf871708d84c5e042dd40ce09.send', data={'text':'天气预报 -By Scotoma8','desp':info})
    r2 = requests.post('https://sc.ftqq.com/SCU73077Tbb0cb331c254410cd623bd9a8d5e6f195e04d38e06dd1.send', data={'text':'天气预报 -By Scotoma8','desp':info})
    print(r1.status_code, ' ', r2.status_code)

def send_info_wechat_home(info):
    r1 = requests.post('https://sc.ftqq.com/SCU73080T8e8e7d09f62d158dd66e6ac968ff5c305e04d51d0da97.send', data={'text':'天气预报 -By Scotoma8','desp':info})
    r2 = requests.post('https://sc.ftqq.com/SCU73081T1c0aaec75576305d886873c6935332a25e04d63ba2bbc.send', data={'text':'天气预报 -By Scotoma8','desp':info})
    print(r1.status_code, ' ', r2.status_code)

if __name__ == '__main__':
    to_number = "+8618515834425"
    from_number = "+19382220848"
    beijing_info = get_info(req_api_beijing())
    taiyuan_info = get_info(req_api_taiyuan())
    #send_info(to_number,from_number,info)
    send_info_wechat_us(beijing_info)
    send_info_wechat_home(taiyuan_info)
