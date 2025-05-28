# Ripley

Nessus style enumerator/vulnerability scanner. Final year uni project.

### Prerequisites

- Kali Linux & root access
- Optional [OpenAI api key](https://openai.com/index/openai-api/)

### Setup Instructions

```
sudo su #create and run as root for full functionality
cd ~
git clone https://github.com/h0bnobs/Ripley
cd Ripley
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python ripley_gui.py
```