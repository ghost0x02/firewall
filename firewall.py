import requests
import os
import logging
import json
import csv
from colorama import Fore

class FirewallScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.mod_security_rules = self.load_mod_security_rules()

    def load_mod_security_rules(self):

        return [
            "SecRuleEngine On",
            "SecRequestBodyAccess On",
            "SecResponseBodyAccess On",
            "bigip",
            "netscaler",
            "fortinet",
            "sonicwall",
            "palo alto",
            "imperva",
            "barracuda",
            "juniper",
            "cloudflare",
            "incapsula",
            "akamai",
            "f5",
            "citrix",
            "radware",
            "fastly"
        ]

    def scan(self):
        results = []
        print("\nTarama başlıyor:\n")
        for rule in self.mod_security_rules:
            result = self.test_rule(rule)
            logging.info(result)
            print(result)
            results.append(result)
        print("\nTarama tamamlandı.\n")
        return results

    def test_rule(self, rule):
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        try:
            response = requests.post(self.target_url, headers=headers, data=rule, timeout=10)
            if response.status_code == 403:
                return f"Rule: {rule} - Result: Potansiyel güvenlik açığı (403 Yasaklanmış)"
            else:
                return f"Rule: {rule} - Result: Sorun tespit edilmedi (Durum {response.status_code})"
        except requests.exceptions.Timeout:
            return f"Rule: {rule} - Error: İstek 10 saniyede zaman aşımına uğradı."
        except requests.exceptions.RequestException as e:
            return f"Rule: {rule} - Error: {str(e)}"

def check_target_accessibility(target_url):
    try:
        response = requests.get(target_url, timeout=5)
        if response.status_code == 200:
            print(f"Target {target_url} girilen hedefe erişim onaylandı.")
            return True
        else:
            print(f"Target {target_url} status kodu: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Hedef {target_url} erişilirken bir hata oluştu: {str(e)}")
        return False

def save_results_to_json(results, filename):
    with open(filename, 'w') as file:
        json.dump(results, file, indent=4)
    print(f"Sonuçlar {filename} dosyasına JSON formatında kaydedildi.")

def save_results_to_csv(results, filename):
    with open(filename, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Rule", "Result"])
        for result in results:
            rule, result_text = result.split(" - Result: ")
            writer.writerow([rule, result_text])
    print(f"Sonuçlar {filename} dosyasına CSV formatında kaydedildi.")

if __name__ == "__main__":
    logging.basicConfig(filename="tarama.log", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    os.system("clear")
    print(Fore.RED + "")
    target = input("Taranacak sitenin URL'sini girin (örn. http://example.com): ").strip()
    os.system("figlet firewall")
    print(Fore.GREEN + "CODE BY ghost0x02 - enesxsec ")

    if not target.startswith("http://") and not target.startswith("https://"):
        print("Geçerli bir URL giriniz (http:// veya https:// ile başlamalı).")
    elif check_target_accessibility(target):
        scanner = FirewallScanner(target)
        scan_results = scanner.scan()

        save_results_to_json(scan_results, "tarama_sonuclari.json")
        save_results_to_csv(scan_results, "tarama_sonuclari.csv")

        print("Tüm işlemler başarıyla tamamlandı.")
    else:
        print("Hedef URL'ye erişilemiyor. Lütfen URL'yi kontrol edin.")
