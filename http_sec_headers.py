import sys
import random
import requests
import argparse

try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except:
    pass


parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url",
                    dest="url",
                    help="Check a single host",
                    action='store')
parser.add_argument("-il", "--input_list",
                    dest="il",
                    help="Use an input list",
                    action='store')
parser.add_argument("-c", "--check",
                    dest="check",
                    help="Check if a target is vulnerable.",
                    action='store_true')
args = parser.parse_args()
url = args.url if args.url else None
il = args.il if args.il else None
url = args.url if args.url else None
check = args.check if args.check else None


def url_prepare(url):
    url = url.replace('#', '%23')
    url = url.replace(' ', '%20')
    if ('://' not in url):
        url = str('https') + str('://') + str(url)
    return(url)

def check(url):
    url = url_prepare(url)
    print('\n[*] URL: %s' % (url))
    
    timeout = 3
    try:
        #proxy = {
        #    "http": "http://127.0.0.1:8080",
        #}
        #r = requests.options(url, proxies=proxy)
        ### ADD PROXY ####
        proxy = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
        r = requests.options(url, timeout=timeout)
        rh = r.headers
        if "X-Frame-Options" in rh:
            result = True
        elif "X-XSS-Protection" in rh:
            result = True
        elif "X-Content-Type-Options" in rh:
            result = True
        else:
            result = False
    except Exception as e:
        print("EXCEPTION::::--> " + str(e))
        result = False
    return(result)
    print(result)

def main(url=url, il=il, check=check):
    if url:
        if check:
            result = check(url)
            output = 'Verification: '
            r = requests.options("https://" + url)
            rh = r.headers
            if "Allow" in rh:
                result = True
            elif "Public" in rh:
                result = True
            else:
                result = False
            return(result)   

    if il:
        URLs_List = []
        try:
            f_file = open(str(il), 'r')
            URLs_List = f_file.read().replace('\r', '').split('\n')
            try:
                URLs_List.remove('')
            except ValueError:
                pass
                f_file.close()
        except:
            print('Error reading file')
            exit(1)
        for url in URLs_List:
            if check:
                result = check(url)
                output = 'Verification: '
                if result is True:
                    output += 'True Positive'
                else:
                    output += 'False Positive'
            print(output)

    print('[%] Done.')

if __name__ == '__main__':
    try:
        main(url=url, il=il, check=check)
    except KeyboardInterrupt:
        print('\nKeyboardInterrupt Detected.')
        print('Exiting...')
        exit(0)
