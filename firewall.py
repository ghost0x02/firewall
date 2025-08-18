import requests
import os
import logging
from colorama import Fore

class FirewallScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.mod_security_rules = self.load_mod_security_rules()

    def load_mod_security_rules(self):
        return [
            ("SecRuleEngine On", "ModSecurity kural motoru"),
            ("SecRequestBodyAccess On", "İstek gövdesi erişim kontrolü"),
            ("SecResponseBodyAccess On", "Yanıt gövdesi erişim kontrolü"),
            ("bigip", "F5 BIG-IP WAF"),
            ("netscaler", "Citrix NetScaler WAF"),
            ("fortinet", "Fortinet WAF"),
            ("sonicwall", "SonicWall WAF"),
            ("palo alto", "Palo Alto WAF"),
            ("imperva", "Imperva WAF"),
            ("barracuda", "Barracuda WAF"),
            ("juniper", "Juniper WAF"),
            ("cloudflare", "Cloudflare WAF"),
            ("incapsula", "Incapsula WAF"),
            ("akamai", "Akamai WAF"),
            ("f5", "F5 WAF"),
            ("citrix", "Citrix WAF"),
            ("radware", "Radware WAF"),
            ("fastly", "Fastly WAF")
        ]

    def scan(self):
        results = []
        print("\nTarama başlıyor:\n")
        for rule, description in self.mod_security_rules:
            result = self.test_rule(rule, description)
            logging.info(result)
            print(result)
            results.append(result)
        print("\nTarama tamamlandı.\n")
        return results

    def test_rule(self, rule, description):
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        try:
            response = requests.post(self.target_url, headers=headers, data=rule, timeout=10)
            if response.status_code == 403:
                return f"{description} (+) Potansiyel güvenlik açığı"
            else:
                return f"{description} (-) Tespit edilmedi (Durum {response.status_code})"
        except requests.exceptions.Timeout:
            return f"{description} - Hata: Zaman aşımı."
        except requests.exceptions.RequestException as e:
            return f"{description} - Hata: {str(e)}"

def check_target_accessibility(target_url):
    try:
        response = requests.get(target_url, timeout=5)
        if response.status_code == 200:
            print(f"Hedef {target_url} Erişim onaylandı.")
            return True
        else:
            print(f"Hedef {target_url} durum kodu: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Hedef {target_url} Erişilirken bir hata oluştu: {str(e)}")
        return False

if __name__ == "__main__":
    logging.basicConfig(filename="tarama.log", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    os.system("clear")
    print(Fore.RED + "")
    target = input("Host Girin: ").strip()
    os.system("figlet firewall")
    print(Fore.GREEN + "CODED BY ghost0x02 - enesxsec ")

    if not target.startswith("http://") and not target.startswith("https://"):
        print("Geçerli bir URL giriniz (http:// veya https:// ile başlamalı).")
    elif check_target_accessibility(target):
        scanner = FirewallScanner(target)
        scanner.scan()
    else:
        print("Erişim hatası!")
