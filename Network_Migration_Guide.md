# 🌐 Wazuh Network Migration Notes (Hotspot / Network Change)

**Scenario:** Jab aap apna laptop kisi naye WiFi ya Mobile Hotspot se connect karte hain, toh network change ho jata hai. Kyunki aapki **Wazuh VM "Bridged Adapter"** pe set hai, use naye network (Hotspot) se ek bilkul NAYA IP address assign hoga.

Iske wajah se:
1. Aapki **WinClient VM (NAT)** purane IP par data bhejti rahegi aur **"Disconnected"** ho jayegi.
2. Aapka Python dashboard (`wazuh_api.py`) purane IP se alerts mangega aur **Timeout Error** dega.

Neeche diye gaye in **3 Steps** ko line-by-line follow karein jab bhi aap network change karein!

---

### Step 1: Naya Wazuh IP Pata Karein
Sabse pehle hume naya IP dhundna hoga.
1. Apni **Wazuh Linux VM** ke terminal me login karein.
2. Ye command type karein:
   ```bash
   ip a
   ```
3. Network adapter me se apni nayi IP note kar lein (Example ke liye maan lijiye nayi IP `192.168.43.50` aayi hai).

**Note:** Aage ke saare steps me hum is nayi IP ko **`<NEW_IP>`** kahenge.

---

### Step 2: Windows Agent (WinClient VM) Me IP Update Karein
WinClient ko naye Wazuh Manager ka address batana zaroori hai tabhi wo `agent_control` me 'Active' hoga.

1. Apni **Windows 10/11 VM (WinClient)** open karein.
2. Windows search me **Notepad** likhein -> Right Click -> **"Run as Administrator"**.
3. Notepad me `File > Open` par jayein aur ye file kholiye:
   `C:\Program Files (x86)\ossec-agent\ossec.conf`
4. File ke starting me `<client>` tag ke andar purane IP ko hatakar apni Nayi Wazuh IP likhiye:
   ```xml
   <client>
     <server>
       <address>192.168.43.50</address> <!-- Yahan NAYA IP DALEIN -->
       <port>1514</port>
       <protocol>tcp</protocol>
     </server>
   ```
5. File ko **Save** karein (`Ctrl+S`).
6. Usi Windows me **PowerShell (Admin)** kholiye aur ye likh kar service restart karein:
   ```powershell
   Restart-Service -Name "Wazuh"
   ```

---

### Step 3: BlueGuard Python Dashboard Me IP Update Karein
Ab aapke apne Host PC (Laptop) ki Python file ko indexer tak pahuchane ke liye IP update karna hoga.

1. VS Code me `BlueGuard` folder kholiye.
2. **`wazuh_api.py`** file open karein.
3. Line No. 9 ke aas paas Indexer ka IP likha hoga, usme IP replace kariye:
   ```python
   # Puraane IP (192.168.1.111) ko hatakar naya IP dalein:
   WAZUH_INDEXER_URL = "https://192.168.43.50:9200" 
   ```
4. File Save karein (`Ctrl+S`).

---

### Step 4: Final Verification ✅
1. **Agent Check:** Apne Wazuh Linux VM terminal par ye lagakar dekhein ki agent 'Active' hua ya nahi:
   ```bash
   sudo /var/ossec/bin/agent_control -l
   ```
2. **Python Check:** Apne host laptop me purane band terminals ko clear karke dono scripts dobara run kar dein:
   ```cmd
   python app.py
   python wazuh_api.py
   ```

**Pro Tip & Firewall Setup:** 
Agar VM restart karne par agents connect nahi ho rahe (`Disconnected`) ya dashboard par timeout aa raha hai, toh iska matlab firewall block kar raha hai. 

Wazuh VM terminal par neeche di gayi **iptables / firewalld** commands chala kar connection allow karein:

**Option A (Using Firewalld - Default Wazuh OVA):**
```bash
sudo firewall-cmd --add-port=9200/tcp --permanent
sudo firewall-cmd --add-port=1514/tcp --permanent
sudo firewall-cmd --reload
```

**Option B (Using Iptables):**
Agar aapki VM me `iptables` chal raha hai, toh in commands ko run karke traffic `ACCEPT` karein. (Hamesha `-I` use karein taaki ye rule sabse uper aayein aur REJECT rules inko block na karein):
```bash

sudo iptables -I INPUT 1 -p tcp --dport 1514 -j ACCEPT
sudo iptables -I INPUT 1 -p udp --dport 1514 -j ACCEPT

sudo iptables -I INPUT 1 -p tcp --dport 9200 -j ACCEPT

# Rules save karein
sudo iptables-save > /etc/sysconfig/iptables
```

### 🔴 Specific Error: "Port 9200 Max retries exceeded / Connection timed out"
Agar aapke Python dashboard me aisi error aa rahi hai:
`HTTPSConnectionPool(host='...', port=9200): Max retries exceeded... Connection timed out`

iska matlab Wazuh Indexer connect nahi ho pa raha. Isko fix karne ke liye seedha Wazuh VM terminal par ye command lagayein:
```bash
sudo iptables -I INPUT 1 -p tcp --dport 9200 -j ACCEPT
```
*(Yeh rule ko list me sabse upar 1st position par dalega taaki CentOS/RHEL ka default firewall packet ko drop na kar sake!)*

### 🔍 Kaise Check Karein Konse Ports ACCEPT/REJECT hai?
Agar aapko dekhna hai ki filhal iptables me kya allowed hai aur kya blocked hai, ye command chalayein:

```bash
sudo iptables -L -n -v
```
**Kaise Padhein Is List Ko:**
*   List me `ACCEPT` likha hai toh us port par connection chalu hai.
*   Agar list ke end me `REJECT`/`DROP` rule hai aur aapka rule uske neeche aata hai, toh wazuh timeout ho jayega. (Make sure Wazuh ke ACCEPT rules DROP rules ke pehle aayein).
