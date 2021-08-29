---
Challenge Name: NSFW
category: Web
difficulty: hard(points:400)
---
challenge website:http://20.198.106.95:22001/
This was a request smuggling challenge and the exploit was quite new as well.We were given a 
webapp.py file and the source code of gunicorn:https://bit.ly/3Dq3KTq
**webapp.py**
```python
from flask import redirect, Flask, render_template, request
from flask import make_response,url_for, send_from_directory

app = Flask(__name__)

STORE = {}

@app.route('/', methods=["GET", "POST"])
def index():
    global STORE
    if request.method == "POST":
        if len(STORE) > 4000:
            STORE = {}
        message = str(request.form["echo"])
        if request.args.get("save") is not None and request.content_length is not None and request.content_length < 696:
            STORE[request.args.get("save")] = message
    else:
        message = "nothing"
    return render_template("index.html", msg=message)

@app.route('/pop/<id>', methods=["GET"])
def pop(id):
    try:
        return STORE.pop(id, "nothing")
    except:
        return "nothing"
     

if __name__ == '__main__':
    app.run()
 ```
 Initially I thought it was similar to the request smuggling challenge in defcon link:https://ctftime.org/writeup/20655 where they were exploiting the TE.CL scenerio 
 but it wes not working here and I was not aware of the reason.But reading about the TE.CL I realised that the backend and frontend were not confused in this scenerio.
 
 In the source code of gunicorn I found a special header SEC-WEBSOCKET-KEY1 and searching about it I found a bug which was quite recent and worth the try.
 **https://grenfeldt.dev/2021/04/01/gunicorn-20.0.4-request-smuggling**
 
 The vulnerability in this gunicorn lied in the function set_body_reader.Due to the header SEC-WEBSOCKET-KEY1 any incoming request to gunicorn it by default taken to be 
 8(echo=ggg in this case) irrespective of content header.So,if the gunicorn is placed behind the proxy and they interact then it is possible that we smuggle request.Now,the proxy in this case was nginx.
 
 Now the request will look like something like this but was confused with the content length.
 ```
GET / HTTP/1.1
Host: 20.198.106.95:22001
Content-Length: 144
Sec-Websocket-Key1: x

xxxxxxxxPOST /?save=archi HTTP/1.1
Host: 20.198.106.95:22001
Content-Type: application/x-www-form-urlencoded
Content-Length: 600

echo=ggg
```
I was confused with the content-length
when I sent a request like this

![](/pic1.png)

it gave 200 response but when we send out get request to pop in the hope that our request was smuggled we got dissappointment but I realised there was problem with 
content length so changed it to a value such that it it greater than out response

![](/pic2.png)

and it worked
we sent a request like this 

![](/pic3.png)

and then our request got stored in pop with id archi then we get request to it with /pop/archi 

![](/pic4.png)

and we have our flag
So what happens actually is that gunicorn reads the request after xxxxxx in the next request just sent after the first one.

Initially I was getting confused with TE CL and searched and read about it a lot.It had nothing to do with this challenge but was worth reading and watching.

Finally,to end with it was quite a good challenge and I learnt a lot about request smuggling
(Thanks to Naughtyboy sir for finding the bug report and setting the path for us) 



