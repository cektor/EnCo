# EnCo
EnCo is a file encryption application developed with Python. This application allows users to encrypt and decrypt their files. The encryption and decryption operations are performed with the AES encryption algorithm.

Install Git Clone and Python3

Github Package Must Be Installed On Your Device.
```bash
sudo apt install git -y
```

```bash
sudo apt install python3 -y 

```

# Required Libraries

PyQt6
```bash
pip install PyQt6
```
cryptography
```bash
pip install cryptography
```

----------------------------------


# Installation
Install EnCo

```bash
sudo git clone https://github.com/cektor/EnCo.git
```
```bash
cd EnCo
```

```bash
python enco.py
```
or

```bash
python3 enco.py

```

# To compile

NOTE: For Compilation Process pyinstaller must be installed. To Install If Not Installed.

pip install pyinstaller 

Linux Terminal 
```bash
pytohn3 -m pyinstaller --onefile --windowed enco.py
```

Windows VSCode Terminal 
```bash
pyinstaller --onefile --noconsole enco.py
```

MacOS VSCode Terminal 
```bash
pyinstaller --onefile --noconsole enco.py
```

# To install directly on Windows or Linux
Download and Install according to your Operating System from the link.

Linux (based debian): wget -O EnCo_Linux64.deb https://github.com/cektor/EnCo/releases/download/1.00/Setup_Linux64.deb && sudo apt install ./EnCo_Linux64.deb && sudo apt-get install -f

Windows İnstaller: https://github.com/cektor/EnCo/releases/download/1.00/Setup_Win64.exe

Release: Page: https://github.com/cektor/EnCo/releases/tag/1.00


# Linux Screenshot
![Linux(pardus)](enco-linux.png)  

# Windows Screenshot
![Windows(11)](enco-windows.png) 



