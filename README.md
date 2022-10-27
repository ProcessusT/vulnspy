# VULNSPY
 

<div align="center">
  <br>
  <img src="https://img.shields.io/badge/Python-3.6+-informational">
  <br>
  <a href="https://twitter.com/intent/follow?screen_name=ProcessusT" title="Follow"><img src="https://img.shields.io/twitter/follow/ProcessusT?label=ProcessusT&style=social"></a>
  <br>
  <br><br>
</div>



> VULNSPY regularly retrieves the latest alerts published by the CERT-FR<br>
> and the related vulnerabilities with their CVSS score and allows you to<br />
> notify by email, slack or by discord if a defined threshold is exceeded<br>
<br />
<br>
<div align="center">
<img src="https://docs.lestutosdeprocessus.fr/vulnspy.png" width="80%;">
</div>
<br>


## Changelog

<br />
On last version (V 1.2) :<br />
- Add Slack Notifer
- Dependencies => requirements.txt
<br />
Version 1.1  :<br />
- Complete rewrite for discord bot and webhook<br />
- Best format for message output<br />
<br />
Version 1.0 :<br />
- Notify by email and by discord<br />
<br />

## Installation
<br>

```python
git clone https://github.com/Processus-Thief/vulnspy
cd vulnspy/
python3 -m venv .venv
pip install -r requirements.txt
python3 ./vulnspy.py
```

<br>
<b>IMPORTANT : You need to configure SMTP, Discord and Slack options in script :</b><br><br>
<img src="https://docs.lestutosdeprocessus.fr/vulnspy_config.png" width="70%;">
<br><br><br><br>