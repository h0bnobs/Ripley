# Ripley

### Prerequisites
- Kali Linux & root access
- Optional [OpenAI api key](https://openai.com/index/openai-api/)

### Setup Instructions
```
sudo su
cd ~
git clone https://github.com/h0bnobs/Ripley
cd Ripley
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python ripley_gui.py
```