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

def req_api_news():
    res_news = requests.get('http://v.juhe.cn/toutiao/index?type=top&key=282d8f30b28efffa483876f7e9f75685')
    return res_news

def get_info_news(res):
    info = []
    result = res.json()
    if result['reason'] == "成功的返回":
        data = result['result']['data']
        info.append('\n\n')
        info.append('###\#每日新闻\n\n')
        info.append('---\n\n')
        for i in data:
            delkeys = []
            key = i.keys()
            for j in key:
                if '.jpg' in i[j]:
                    delkeys.append(j)
            for k in delkeys:
                del i[k]
            del i['uniquekey']
            i['title'] = '**' + i['title'] + '**'
            i['url'] = '**' + i['url'] + '**'
            info.append("{}\n\n".format(i))
        string = "".join(str(i) for i in info)
        string = string.replace('\'','')
        string = string.replace('<','小于')
        string = string.replace('>','大于')
        return string

def get_info_weather(res):
    info = [] 
    result = res.json()
    if result['status'] == 200:
        info.append('\n\n')
        info.append("###\#天气预报\n\n")
        info.append("---\n\n")
        info.append("**日期**:{}\n\n".format(result['date']))
        info.append("**城市**:{}\n\n".format(result['cityInfo']))
        info.append("**今日天气**:{}\n\n".format(result['data']['forecast'][0]))
        info.append("**明日天气**:{}\n\n".format(result['data']['forecast'][1]))
        info.append("**后日天气**:{}\n\n".format(result['data']['forecast'][2]))
        string = "".join(str(i) for i in info)
        string = string.replace('\'','')
        string = string.replace('<','小于')
        string = string.replace('>','大于')
        return string
    else:
        print('API BREAK!')
        return 'API BREAK!'

def send_info_message(to_number,from_number,info):
    account_sid = "AC129418c9c5d9b91f63bb687c8c547e38"
    auth_token = "e90bcbf52fb2daaca79439575288b413"
    client = Client(account_sid, auth_token)
    message = client.messages.create(to = to_number,from_ = from_number,body = info)
    print(message.sid)

def send_info_wechat_us(info):
    r1 = requests.post('https://sc.ftqq.com/SCU72677T938a51d1561e26da0b26bf871708d84c5e042dd40ce09.send', data={'text':'每日关心 -By Scotoma8','desp':info})
    r2 = requests.post('https://sc.ftqq.com/SCU73077Tbb0cb331c254410cd623bd9a8d5e6f195e04d38e06dd1.send', data={'text':'每日关心 -By Scotoma8','desp':info})
    print(r1.status_code, ' ', r2.status_code)

def send_info_wechat_home(info):
    r1 = requests.post('https://sc.ftqq.com/SCU73080T8e8e7d09f62d158dd66e6ac968ff5c305e04d51d0da97.send', data={'text':'每日关心 -By Scotoma8','desp':info})
    r2 = requests.post('https://sc.ftqq.com/SCU73081T1c0aaec75576305d886873c6935332a25e04d63ba2bbc.send', data={'text':'每日关心 -By Scotoma8','desp':info})
    print(r1.status_code, ' ', r2.status_code)

if __name__ == '__main__':
    to_number = "+8618515834425"
    from_number = "+19382220848"
    beijing_info = get_info_weather(req_api_beijing())
    taiyuan_info = get_info_weather(req_api_taiyuan())
    news_info = get_info_news(req_api_news())
    #send_info_message(to_number,from_number,info)
    send_info_wechat_us(beijing_info + news_info)
    #send_info_wechat_home(taiyuan_info + news_info)
