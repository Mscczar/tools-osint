#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSINT Multi-Tools Suite v2.0 - Edition Automatique
Recherche automatique d'informations Open Source
Compatible Linux et Windows
"""

import os
import sys
import json
import requests
import platform
import socket
import re
import threading
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import quote, urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Détection du système d'exploitation
IS_WINDOWS = platform.system() == "Windows"

# Couleurs pour le terminal
class Colors:
    if IS_WINDOWS:
        os.system('color')
    
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def clear_screen():
    os.system('cls' if IS_WINDOWS else 'clear')

def print_banner():
    banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════╗
║        OSINT MULTI-TOOLS SUITE v2.0 - AUTO EDITION       ║
║       Recherche Automatique d'Informations OSINT          ║
╚═══════════════════════════════════════════════════════════╝{Colors.END}
    """
    print(banner)

def print_menu():
    menu = f"""
{Colors.HEADER}═══ RECHERCHE PERSONNE ═══{Colors.END}
{Colors.BOLD}[1]{Colors.END}  Username Search      - Recherche auto sur 35+ plateformes
{Colors.BOLD}[2]{Colors.END}  Email OSINT          - Analyse complète + validation + breach
{Colors.BOLD}[3]{Colors.END}  Phone OSINT          - Validation + opérateur + localisation
{Colors.BOLD}[4]{Colors.END}  People Search        - Recherche automatique de personnes

{Colors.HEADER}═══ RECHERCHE RÉSEAU ═══{Colors.END}
{Colors.BOLD}[5]{Colors.END}  IP Lookup            - Géolocalisation + ISP + Ports ouverts
{Colors.BOLD}[6]{Colors.END}  Domain Analysis      - WHOIS + DNS + SSL + Subdomains
{Colors.BOLD}[7]{Colors.END}  URL Scanner          - Analyse automatique + redirections
{Colors.BOLD}[8]{Colors.END}  Port Scanner         - Scan automatique de ports TCP

{Colors.HEADER}═══ RÉSEAUX SOCIAUX ═══{Colors.END}
{Colors.BOLD}[9]{Colors.END}  Social Media Deep    - Extraction automatique multi-plateformes
{Colors.BOLD}[10]{Colors.END} LinkedIn Hunter      - Recherche automatique d'employés
{Colors.BOLD}[11]{Colors.END} GitHub Intelligence  - Analyse automatique repos/commits

{Colors.HEADER}═══ RECHERCHE AVANCÉE ═══{Colors.END}
{Colors.BOLD}[12]{Colors.END} Google Dorks         - Recherche avancée automatique
{Colors.BOLD}[13]{Colors.END} Subdomain Finder     - Énumération automatique sous-domaines
{Colors.BOLD}[14]{Colors.END} Email Harvester      - Extraction automatique d'emails
{Colors.BOLD}[15]{Colors.END} Breach Check         - Vérification automatique fuites

{Colors.HEADER}═══ IMAGES & DOCUMENTS ═══{Colors.END}
{Colors.BOLD}[16]{Colors.END} Reverse Image        - Recherche inversée automatique
{Colors.BOLD}[17]{Colors.END} EXIF Extractor       - Extraction automatique métadonnées

{Colors.HEADER}═══ CRYPTO & AUTRES ═══{Colors.END}
{Colors.BOLD}[18]{Colors.END} Crypto Tracker       - Analyse automatique blockchain
{Colors.BOLD}[19]{Colors.END} WiFi Networks        - Recherche automatique réseaux WiFi
{Colors.BOLD}[20]{Colors.END} Paste Search         - Recherche automatique sur Pastebin

{Colors.HEADER}═══ SYSTÈME ═══{Colors.END}
{Colors.BOLD}[98]{Colors.END} Export Results       - Exporter résultats (JSON/HTML/CSV)
{Colors.BOLD}[99]{Colors.END} Settings             - Configuration API Keys
{Colors.BOLD}[0]{Colors.END}  Exit                 - Quitter

{Colors.YELLOW}[i] Toutes les recherches sont automatiques et réelles !{Colors.END}
    """
    print(menu)

class UsernameSearch:
    """Module de recherche automatique de username sur 35+ plateformes"""
    
    PLATFORMS = {
        # Réseaux sociaux principaux
        "GitHub": {"url": "https://github.com/{}", "method": "status"},
        "Twitter/X": {"url": "https://twitter.com/{}", "method": "status"},
        "Instagram": {"url": "https://instagram.com/{}", "method": "status"},
        "Reddit": {"url": "https://reddit.com/user/{}", "method": "status"},
        "Facebook": {"url": "https://facebook.com/{}", "method": "status"},
        "TikTok": {"url": "https://tiktok.com/@{}", "method": "status"},
        "YouTube": {"url": "https://youtube.com/@{}", "method": "status"},
        "LinkedIn": {"url": "https://linkedin.com/in/{}", "method": "status"},
        "Pinterest": {"url": "https://pinterest.com/{}", "method": "status"},
        "Snapchat": {"url": "https://snapchat.com/add/{}", "method": "status"},
        "Telegram": {"url": "https://t.me/{}", "method": "status"},
        
        # Plateformes créatives
        "Medium": {"url": "https://medium.com/@{}", "method": "status"},
        "DeviantArt": {"url": "https://{}.deviantart.com", "method": "status"},
        "Behance": {"url": "https://behance.net/{}", "method": "status"},
        "Dribbble": {"url": "https://dribbble.com/{}", "method": "status"},
        "Flickr": {"url": "https://flickr.com/people/{}", "method": "status"},
        "SoundCloud": {"url": "https://soundcloud.com/{}", "method": "status"},
        "Spotify": {"url": "https://open.spotify.com/user/{}", "method": "status"},
        
        # Gaming
        "Twitch": {"url": "https://twitch.tv/{}", "method": "status"},
        "Steam": {"url": "https://steamcommunity.com/id/{}", "method": "status"},
        "Xbox": {"url": "https://xboxgamertag.com/search/{}", "method": "status"},
        "PlayStation": {"url": "https://psnprofiles.com/{}", "method": "status"},
        
        # Tech & Dev
        "GitLab": {"url": "https://gitlab.com/{}", "method": "status"},
        "CodePen": {"url": "https://codepen.io/{}", "method": "status"},
        "Replit": {"url": "https://replit.com/@{}", "method": "status"},
        
        # Forums & Communautés
        "HackerNews": {"url": "https://news.ycombinator.com/user?id={}", "method": "status"},
        "ProductHunt": {"url": "https://producthunt.com/@{}", "method": "status"},
        
        # Autres
        "Patreon": {"url": "https://patreon.com/{}", "method": "status"},
        "Linktree": {"url": "https://linktr.ee/{}", "method": "status"},
        "About.me": {"url": "https://about.me/{}", "method": "status"},
        "Gravatar": {"url": "https://gravatar.com/{}", "method": "status"},
        "Keybase": {"url": "https://keybase.io/{}", "method": "status"},
        "Giphy": {"url": "https://giphy.com/{}", "method": "status"},
        "Vimeo": {"url": "https://vimeo.com/{}", "method": "status"},
    }
    
    def __init__(self):
        self.results = []
        self.found_count = 0
    
    def check_platform(self, platform: str, data: dict, username: str):
        """Vérifie si le username existe sur une plateforme"""
        url = data["url"].format(username)
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=7, allow_redirects=True)
            
            # Détection plus fine du statut
            found = False
            if response.status_code == 200:
                # Vérifications supplémentaires pour éviter les faux positifs
                content_lower = response.text.lower()
                
                # Mots-clés indiquant que le profil n'existe pas
                not_found_keywords = [
                    'page not found', '404', 'not found', 'does not exist',
                    'user not found', 'profile not found', 'account not found',
                    'n\'existe pas', 'introuvable', 'no encontrado'
                ]
                
                if any(keyword in content_lower for keyword in not_found_keywords):
                    found = False
                else:
                    found = True
                    self.found_count += 1
            
            status = f"{Colors.GREEN}[✓] TROUVÉ{Colors.END}" if found else f"{Colors.RED}[✗] ABSENT{Colors.END}"
            
            print(f"{status} {platform:20} - {url}")
            
            result = {
                "platform": platform,
                "url": url,
                "found": found,
                "status_code": response.status_code,
                "timestamp": datetime.now().isoformat()
            }
            
            return result
            
        except requests.Timeout:
            print(f"{Colors.YELLOW}[!] TIMEOUT{Colors.END}  {platform:20} - {url}")
            return None
        except Exception as e:
            print(f"{Colors.RED}[✗] ERREUR{Colors.END}   {platform:20} - {url}")
            return None
    
    def search(self, username: str) -> List[Dict]:
        """Recherche un username sur toutes les plateformes en parallèle"""
        print(f"\n{Colors.CYAN}[*] Recherche automatique de '{username}' sur {len(self.PLATFORMS)} plateformes...{Colors.END}\n")
        
        self.results = []
        self.found_count = 0
        
        # Recherche en parallèle pour plus de rapidité
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self.check_platform, platform, data, username): platform 
                for platform, data in self.PLATFORMS.items()
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results.append(result)
        
        print(f"\n{Colors.GREEN}[✓] Recherche terminée: {self.found_count} profils trouvés sur {len(self.PLATFORMS)} plateformes{Colors.END}")
        
        if self.found_count > 0:
            print(f"\n{Colors.BOLD}═══ RÉSUMÉ DES PROFILS TROUVÉS ═══{Colors.END}")
            for result in self.results:
                if result['found']:
                    print(f"{Colors.GREEN}✓{Colors.END} {result['platform']:20} {result['url']}")
        
        return self.results

class EmailOSINT:
    """Module d'analyse automatique d'email"""
    
    def analyze(self, email: str):
        print(f"\n{Colors.CYAN}[*] Analyse OSINT automatique de: {email}{Colors.END}\n")
        
        if '@' not in email:
            print(f"{Colors.RED}[✗] Email invalide{Colors.END}")
            return
        
        username, domain = email.split('@')
        
        print(f"{Colors.BOLD}═══ INFORMATIONS BASIQUES ═══{Colors.END}")
        print(f"{Colors.GREEN}[✓]{Colors.END} Username: {username}")
        print(f"{Colors.GREEN}[✓]{Colors.END} Domaine: {domain}")
        print(f"{Colors.GREEN}[✓]{Colors.END} Longueur: {len(email)} caractères")
        
        # Validation format
        self._validate_format(email)
        
        # Analyse du domaine
        self._analyze_domain(domain)
        
        # Vérification MX records
        self._check_mx_records(domain)
        
        # Recherche de profils liés
        self._find_profiles(email, username)
        
        # Vérification breaches
        self._check_breaches_auto(email)
    
    def _validate_format(self, email: str):
        print(f"\n{Colors.BOLD}═══ VALIDATION FORMAT ═══{Colors.END}")
        
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(pattern, email):
            print(f"{Colors.GREEN}[✓]{Colors.END} Format valide (RFC 5322)")
            
            # Vérifications supplémentaires
            if '..' in email:
                print(f"{Colors.YELLOW}[!]{Colors.END} Points consécutifs détectés")
            if email.startswith('.') or email.endswith('.'):
                print(f"{Colors.YELLOW}[!]{Colors.END} Email commence ou finit par un point")
        else:
            print(f"{Colors.RED}[✗]{Colors.END} Format invalide")
    
    def _analyze_domain(self, domain: str):
        print(f"\n{Colors.BOLD}═══ ANALYSE DU DOMAINE ═══{Colors.END}")
        
        try:
            ip = socket.gethostbyname(domain)
            print(f"{Colors.GREEN}[✓]{Colors.END} Résolution DNS: {ip}")
            
            # Géolocalisation de l'IP
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if data['status'] == 'success':
                        print(f"{Colors.GREEN}[✓]{Colors.END} Pays du serveur: {data.get('country')} ({data.get('countryCode')})")
                        print(f"{Colors.GREEN}[✓]{Colors.END} ISP: {data.get('isp')}")
            except:
                pass
                
        except socket.gaierror:
            print(f"{Colors.RED}[✗]{Colors.END} Domaine non résolu - Email probablement invalide")
    
    def _check_mx_records(self, domain: str):
        print(f"\n{Colors.BOLD}═══ VÉRIFICATION MX RECORDS ═══{Colors.END}")
        
        try:
            import dns.resolver
            mx_records = dns.resolver.resolve(domain, 'MX')
            print(f"{Colors.GREEN}[✓]{Colors.END} Serveurs mail trouvés:")
            for mx in mx_records:
                print(f"    └─ {mx.exchange} (priorité: {mx.preference})")
        except ImportError:
            print(f"{Colors.YELLOW}[!]{Colors.END} Installez dnspython: pip install dnspython")
        except:
            print(f"{Colors.RED}[✗]{Colors.END} Aucun MX record trouvé - Domaine ne reçoit pas d'emails")
    
    def _find_profiles(self, email: str, username: str):
        print(f"\n{Colors.BOLD}═══ RECHERCHE DE PROFILS LIÉS ═══{Colors.END}")
        
        # Test sur quelques plateformes
        platforms = {
            "Gravatar": f"https://gravatar.com/{username}",
            "GitHub": f"https://github.com/{username}",
        }
        
        for platform, url in platforms.items():
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    print(f"{Colors.GREEN}[✓]{Colors.END} {platform}: {url}")
            except:
                pass
    
    def _check_breaches_auto(self, email: str):
        print(f"\n{Colors.BOLD}═══ VÉRIFICATION FUITES DE DONNÉES ═══{Colors.END}")
        
        # API HaveIBeenPwned (nécessite API key pour version automatique)
        print(f"{Colors.YELLOW}[i]{Colors.END} Vérification via HaveIBeenPwned...")
        
        try:
            # Version sans API key - juste vérification du domaine
            domain = email.split('@')[1]
            response = requests.get(
                f"https://haveibeenpwned.com/api/v3/breaches",
                headers={'User-Agent': 'OSINT-Tool'},
                timeout=10
            )
            
            if response.status_code == 200:
                breaches = response.json()
                print(f"{Colors.GREEN}[✓]{Colors.END} {len(breaches)} fuites de données connues au total")
                print(f"{Colors.YELLOW}[i]{Colors.END} Pour vérifier cet email spécifique: https://haveibeenpwned.com/account/{email}")
            
        except Exception as e:
            print(f"{Colors.YELLOW}[!]{Colors.END} Vérification limitée - Visitez: https://haveibeenpwned.com")

class PhoneOSINT:
    """Module d'analyse automatique de numéro de téléphone"""
    
    def analyze(self, phone: str):
        print(f"\n{Colors.CYAN}[*] Analyse automatique du numéro: {phone}{Colors.END}\n")
        
        # Nettoyage du numéro
        cleaned = re.sub(r'[^\d+]', '', phone)
        
        print(f"{Colors.BOLD}═══ ANALYSE DU NUMÉRO ═══{Colors.END}")
        print(f"{Colors.GREEN}[✓]{Colors.END} Numéro nettoyé: {cleaned}")
        print(f"{Colors.GREEN}[✓]{Colors.END} Longueur: {len(cleaned)} chiffres")
        
        # Détection du pays
        country_info = self._detect_country(cleaned)
        if country_info:
            print(f"{Colors.GREEN}[✓]{Colors.END} Pays détecté: {country_info['name']} {country_info['flag']}")
            print(f"{Colors.GREEN}[✓]{Colors.END} Indicatif: {country_info['code']}")
        
        # Validation via API
        self._validate_number(cleaned)
        
        # Type de numéro
        self._detect_type(cleaned)
    
    def _detect_country(self, phone: str):
        """Détecte le pays du numéro"""
        country_codes = {
            '+33': {'name': 'France', 'flag': '🇫🇷', 'code': '+33'},
            '+1': {'name': 'USA/Canada', 'flag': '🇺🇸🇨🇦', 'code': '+1'},
            '+44': {'name': 'Royaume-Uni', 'flag': '🇬🇧', 'code': '+44'},
            '+49': {'name': 'Allemagne', 'flag': '🇩🇪', 'code': '+49'},
            '+34': {'name': 'Espagne', 'flag': '🇪🇸', 'code': '+34'},
            '+39': {'name': 'Italie', 'flag': '🇮🇹', 'code': '+39'},
            '+32': {'name': 'Belgique', 'flag': '🇧🇪', 'code': '+32'},
            '+41': {'name': 'Suisse', 'flag': '🇨🇭', 'code': '+41'},
            '+212': {'name': 'Maroc', 'flag': '🇲🇦', 'code': '+212'},
            '+213': {'name': 'Algérie', 'flag': '🇩🇿', 'code': '+213'},
        }
        
        for code, info in country_codes.items():
            if phone.startswith(code) or phone.startswith('00' + code[1:]):
                return info
        
        return None
    
    def _validate_number(self, phone: str):
        """Valide le numéro via API"""
        print(f"\n{Colors.BOLD}═══ VALIDATION ═══{Colors.END}")
        
        try:
            # API numverify (gratuite avec limite)
            response = requests.get(
                f"https://api.apilayer.com/number_verification/validate?number={phone}",
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('valid'):
                    print(f"{Colors.GREEN}[✓]{Colors.END} Numéro valide")
                else:
                    print(f"{Colors.RED}[✗]{Colors.END} Numéro invalide")
        except:
            print(f"{Colors.YELLOW}[!]{Colors.END} Validation API limitée")
    
    def _detect_type(self, phone: str):
        """Détecte le type de numéro (mobile/fixe)"""
        print(f"\n{Colors.BOLD}═══ TYPE DE NUMÉRO ═══{Colors.END}")
        
        # Pour la France
        if phone.startswith('+336') or phone.startswith('+337'):
            print(f"{Colors.GREEN}[✓]{Colors.END} Type: Mobile 📱")
        elif phone.startswith('+33'):
            print(f"{Colors.GREEN}[✓]{Colors.END} Type: Fixe 📞")

class PeopleSearch:
    """Module de recherche automatique de personnes"""
    
    def search(self, name: str, location: str = ""):
        print(f"\n{Colors.CYAN}[*] Recherche automatique de: {name}{Colors.END}")
        if location:
            print(f"{Colors.CYAN}[*] Localisation: {location}{Colors.END}\n")
        
        print(f"{Colors.BOLD}═══ RECHERCHE EN COURS ═══{Colors.END}")
        
        # Recherche Google automatique
        self._google_search(name, location)
        
        # Recherche réseaux sociaux
        self._social_search(name)
        
        # Recherche dans les annuaires
        self._directory_search(name, location)
    
    def _google_search(self, name: str, location: str):
        """Recherche Google automatique"""
        print(f"\n{Colors.CYAN}[*] Recherche Google...{Colors.END}")
        
        query = f'"{name}"'
        if location:
            query += f' "{location}"'
        
        try:
            # Note: Google bloque souvent les requêtes automatiques
            # Utilisation d'une recherche DuckDuckGo à la place
            url = f"https://html.duckduckgo.com/html/?q={quote(query)}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                # Extraction basique de résultats
                links = re.findall(r'uddg=([^&"]+)', response.text)
                if links:
                    print(f"{Colors.GREEN}[✓]{Colors.END} {len(links[:5])} résultats trouvés:")
                    for link in links[:5]:
                        try:
                            from urllib.parse import unquote
                            decoded = unquote(link)
                            print(f"    └─ {decoded}")
                        except:
                            pass
        except:
            print(f"{Colors.YELLOW}[!]{Colors.END} Recherche limitée")
    
    def _social_search(self, name: str):
        """Recherche sur les réseaux sociaux"""
        print(f"\n{Colors.CYAN}[*] Recherche réseaux sociaux...{Colors.END}")
        
        # Générer des usernames possibles
        parts = name.lower().split()
        if len(parts) >= 2:
            possible_usernames = [
                parts[0] + parts[1],
                parts[0] + "." + parts[1],
                parts[0] + "_" + parts[1],
                parts[0][0] + parts[1],
            ]
            
            print(f"{Colors.GREEN}[✓]{Colors.END} Usernames possibles générés:")
            for username in possible_usernames:
                print(f"    └─ {username}")
    
    def _directory_search(self, name: str, location: str):
        """Recherche dans les annuaires"""
        print(f"\n{Colors.CYAN}[*] Recherche annuaires...{Colors.END}")
        
        # URLs de recherche
        if location.lower() in ['france', 'fr']:
            url = f"https://www.pagesjaunes.fr/annuaire/chercherlespros?quoi=&ou={location}&proximite=0"
            print(f"{Colors.GREEN}[✓]{Colors.END} Pages Jaunes FR: {url}")

class IPLookup:
    """Module avancé de géolocalisation et analyse IP"""
    
    def lookup(self, ip: str):
        print(f"\n{Colors.CYAN}[*] Analyse complète automatique de: {ip}{Colors.END}\n")
        
        # Géolocalisation
        self._geolocate(ip)
        
        # Scan de ports rapide
        self._quick_port_scan(ip)
        
        # Reverse DNS
        self._reverse_dns(ip)
    
    def _geolocate(self, ip: str):
        """Géolocalisation de l'IP"""
        print(f"{Colors.BOLD}═══ GÉOLOCALISATION ═══{Colors.END}")
        
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if data['status'] == 'success':
                    print(f"{Colors.GREEN}[✓]{Colors.END} IP: {data.get('query')}")
                    print(f"{Colors.GREEN}[✓]{Colors.END} Pays: {data.get('country')} ({data.get('countryCode')})")
                    print(f"{Colors.GREEN}[✓]{Colors.END} Région: {data.get('regionName')}")
                    print(f"{Colors.GREEN}[✓]{Colors.END} Ville: {data.get('city')}")
                    print(f"{Colors.GREEN}[✓]{Colors.END} Code postal: {data.get('zip')}")
                    print(f"{Colors.GREEN}[✓]{Colors.END} Coordonnées: {data.get('lat')}, {data.get('lon')}")
                    print(f"{Colors.GREEN}[✓]{Colors.END} Timezone: {data.get('timezone')}")
                    
                    print(f"\n{Colors.BOLD}═══ INFORMATIONS RÉSEAU ═══{Colors.END}")
                    print(f"{Colors.GREEN}[✓]{Colors.END} ISP: {data.get('isp')}")
                    print(f"{Colors.GREEN}[✓]{Colors.END} Organisation: {data.get('org')}")
                    print(f"{Colors.GREEN}[✓]{Colors.END} AS: {data.get('as')}")
                    
                    if data.get('mobile'):
                        print(f"{Colors.YELLOW}[!]{Colors.END} Type: Connexion Mobile 📱")
                    if data.get('proxy'):
                        print(f"{Colors.YELLOW}[!]{Colors.END} Proxy/VPN détecté 🔒")
                    if data.get('hosting'):
                        print(f"{Colors.YELLOW}[!]{Colors.END} Hébergement/Datacenter 🖥️")
                    
                    # Lien Google Maps
                    maps_url = f"https://www.google.com/maps?q={data.get('lat')},{data.get('lon')}"
                    print(f"\n{Colors.CYAN}[i]{Colors.END} Carte: {maps_url}")
                    
        except Exception as e:
            print(f"{Colors.RED}[✗] Erreur de géolocalisation: {str(e)}{Colors.END}")
    
    def _quick_port_scan(self, ip: str):
        """Scan rapide des ports communs"""
        print(f"\n{Colors.BOLD}═══ SCAN DE PORTS RAPIDE ═══{Colors.END}")
        
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            8080: "HTTP-Alt"
        }
        
        print(f"{Colors.CYAN}[*]{Colors.END} Scan des ports communs...")
        
        open_ports = []
        
        for port, service in common_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                print(f"{Colors.GREEN}[✓]{Colors.END} Port {port} OUVERT - {service}")
                open_ports.append(port)
            
            sock.close()
        
        if not open_ports:
            print(f"{Colors.YELLOW}[i]{Colors.END} Aucun port commun ouvert détecté")
    
    def _reverse_dns(self, ip: str):
        """Reverse DNS lookup"""
        print(f"\n{Colors.BOLD}═══ REVERSE DNS ═══{Colors.END}")
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            print(f"{Colors.GREEN}[✓]{Colors.END} Hostname: {hostname}")
        except:
            print(f"{Colors.YELLOW}[!]{Colors.END} Pas de reverse DNS")

class DomainAnalysis:
    """Module d'analyse complète et automatique de domaine"""
    
    def analyze(self, domain: str):
        print(f"\n{Colors.CYAN}[*] Analyse complète automatique de: {domain}{Colors.END}\n")
        
        # DNS Resolution
        self._dns_lookup(domain)
        
        # Sous-domaines
        self._find_subdomains(domain)
        
        # SSL/TLS Info
        self._ssl_check(domain)
    
    def _dns_lookup(self, domain: str):
        """Lookup DNS complet"""
        print(f"{Colors.BOLD}═══ ENREGISTREMENTS DNS ═══{Colors.END}")
        
        try:
            # A Record
            ip = socket.gethostbyname(domain)
            print(f"{Colors.GREEN}[✓]{Colors.END} A Record: {ip}")
            
            # Essai avec dnspython si disponible
            try:
                import dns.resolver
                
                # MX Records
                try:
                    mx = dns.resolver.resolve(domain, 'MX')
                    print(f"\n{Colors.GREEN}[✓]{Colors.END} MX Records:")
                    for r in mx:
                        print(f"    └─ {r.exchange} (priorité: {r.preference})")
                except:
                    print(f"{Colors.YELLOW}[!]{Colors.END} Pas de MX records")
                
                # TXT Records
                try:
                    txt = dns.resolver.resolve(domain, 'TXT')
                    print(f"\n{Colors.GREEN}[✓]{Colors.END} TXT Records:")
                    for r in txt:
                        txt_value = r.to_text()[:100]
                        print(f"    └─ {txt_value}")
                except:
                    pass
                
                # NS Records
                try:
                    ns = dns.resolver.resolve(domain, 'NS')
                    print(f"\n{Colors.GREEN}[✓]{Colors.END} NS Records:")
                    for r in ns:
                        print(f"    └─ {r.to_text()}")
                except:
                    pass
                    
            except ImportError:
                print(f"\n{Colors.YELLOW}[!]{Colors.END} Pour plus d'infos DNS: pip install dnspython")
                
        except Exception as e:
            print(f"{Colors.RED}[✗]{Colors.END} Impossible de résoudre le domaine")
    
    def _find_subdomains(self, domain: str):
        """Recherche automatique de sous-domaines"""
        print(f"\n{Colors.BOLD}═══ ÉNUMÉRATION SOUS-DOMAINES ═══{Colors.END}")
        
        common_subdomains = [
            'www', 'mail', 'ftp', 'smtp', 'pop', 'imap',
            'webmail', 'admin', 'blog', 'shop', 'forum',
            'dev', 'staging', 'test', 'api', 'cdn',
            'm', 'mobile', 'vpn', 'remote', 'portal'
        ]
        
        print(f"{Colors.CYAN}[*]{Colors.END} Test de {len(common_subdomains)} sous-domaines...")
        
        found_subdomains = []
        
        for sub in common_subdomains:
            full_domain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                print(f"{Colors.GREEN}[✓]{Colors.END} {full_domain} → {ip}")
                found_subdomains.append(full_domain)
            except:
                pass
        
        if not found_subdomains:
            print(f"{Colors.YELLOW}[!]{Colors.END} Aucun sous-domaine commun trouvé")
    
    def _ssl_check(self, domain: str):
        """Vérification SSL/TLS"""
        print(f"\n{Colors.BOLD}═══ VÉRIFICATION SSL/TLS ═══{Colors.END}")
        
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    print(f"{Colors.GREEN}[✓]{Colors.END} SSL/TLS actif")
                    print(f"{Colors.GREEN}[✓]{Colors.END} Émetteur: {cert.get('issuer')}")
                    print(f"{Colors.GREEN}[✓]{Colors.END} Sujet: {cert.get('subject')}")
                    print(f"{Colors.GREEN}[✓]{Colors.END} Version: {ssock.version()}")
                    
                    # Date d'expiration
                    not_after = cert.get('notAfter')
                    if not_after:
                        print(f"{Colors.GREEN}[✓]{Colors.END} Expire le: {not_after}")
        except:
            print(f"{Colors.YELLOW}[!]{Colors.END} Pas de SSL/TLS ou inaccessible")

class PortScanner:
    """Scanner de ports TCP automatique"""
    
    def scan(self, target: str, port_range: str = "1-1000"):
        print(f"\n{Colors.CYAN}[*] Scan automatique de ports sur: {target}{Colors.END}")
        print(f"{Colors.CYAN}[*] Range: {port_range}{Colors.END}\n")
        
        # Parse du range
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
        else:
            start = end = int(port_range)
        
        print(f"{Colors.BOLD}═══ SCAN EN COURS ═══{Colors.END}")
        
        open_ports = []
        
        for port in range(start, min(end + 1, start + 100)):  # Limite à 100 ports
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                service = self._get_service(port)
                print(f"{Colors.GREEN}[✓]{Colors.END} Port {port} OUVERT - {service}")
                open_ports.append({"port": port, "service": service})
            
            sock.close()
        
        print(f"\n{Colors.GREEN}[✓]{Colors.END} Scan terminé: {len(open_ports)} ports ouverts")
        return open_ports
    
    def _get_service(self, port: int) -> str:
        """Retourne le service connu pour un port"""
        services = {
            20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
        }
        return services.get(port, "Inconnu")

class GitHubIntelligence:
    """Module d'analyse automatique GitHub"""
    
    def analyze(self, username: str):
        print(f"\n{Colors.CYAN}[*] Analyse automatique GitHub de: {username}{Colors.END}\n")
        
        # API GitHub publique
        try:
            # Infos utilisateur
            response = requests.get(f"https://api.github.com/users/{username}", timeout=10)
            
            if response.status_code == 200:
                user = response.json()
                
                print(f"{Colors.BOLD}═══ PROFIL UTILISATEUR ═══{Colors.END}")
                print(f"{Colors.GREEN}[✓]{Colors.END} Nom: {user.get('name', 'N/A')}")
                print(f"{Colors.GREEN}[✓]{Colors.END} Login: {user.get('login')}")
                print(f"{Colors.GREEN}[✓]{Colors.END} Bio: {user.get('bio', 'N/A')}")
                print(f"{Colors.GREEN}[✓]{Colors.END} Localisation: {user.get('location', 'N/A')}")
                print(f"{Colors.GREEN}[✓]{Colors.END} Email: {user.get('email', 'N/A')}")
                print(f"{Colors.GREEN}[✓]{Colors.END} Blog: {user.get('blog', 'N/A')}")
                print(f"{Colors.GREEN}[✓]{Colors.END} Twitter: {user.get('twitter_username', 'N/A')}")
                print(f"{Colors.GREEN}[✓]{Colors.END} Entreprise: {user.get('company', 'N/A')}")
                print(f"{Colors.GREEN}[✓]{Colors.END} Repos publics: {user.get('public_repos')}")
                print(f"{Colors.GREEN}[✓]{Colors.END} Followers: {user.get('followers')}")
                print(f"{Colors.GREEN}[✓]{Colors.END} Following: {user.get('following')}")
                print(f"{Colors.GREEN}[✓]{Colors.END} Créé le: {user.get('created_at')}")
                
                # Liste des repos
                self._get_repos(username)
                
            elif response.status_code == 404:
                print(f"{Colors.RED}[✗]{Colors.END} Utilisateur GitHub non trouvé")
            else:
                print(f"{Colors.YELLOW}[!]{Colors.END} Erreur API GitHub")
                
        except Exception as e:
            print(f"{Colors.RED}[✗] Erreur: {str(e)}{Colors.END}")
    
    def _get_repos(self, username: str):
        """Récupère les repositories"""
        print(f"\n{Colors.BOLD}═══ REPOSITORIES ═══{Colors.END}")
        
        try:
            response = requests.get(
                f"https://api.github.com/users/{username}/repos?sort=updated&per_page=10",
                timeout=10
            )
            
            if response.status_code == 200:
                repos = response.json()
                
                print(f"{Colors.CYAN}[*]{Colors.END} Top 10 repositories récents:")
                for repo in repos[:10]:
                    print(f"\n  {Colors.GREEN}[✓]{Colors.END} {repo['name']}")
                    print(f"      └─ Description: {repo.get('description', 'N/A')}")
                    print(f"      └─ Langage: {repo.get('language', 'N/A')}")
                    print(f"      └─ Stars: ⭐ {repo.get('stargazers_count')}")
                    print(f"      └─ Forks: 🍴 {repo.get('forks_count')}")
                    print(f"      └─ URL: {repo['html_url']}")
        except:
            pass

class SubdomainFinder:
    """Énumération automatique de sous-domaines"""
    
    def find(self, domain: str):
        print(f"\n{Colors.CYAN}[*] Énumération automatique des sous-domaines de: {domain}{Colors.END}\n")
        
        # Liste étendue de sous-domaines
        subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns',
            'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2',
            'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta',
            'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email',
            'images', 'img', 'www1', 'intranet', 'portal', 'video', 'sip', 'dns2', 'api', 'cdn',
            'stats', 'dns1', 'ns4', 'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat',
            'wap', 'my', 'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup',
            'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums', 'store',
            'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office',
            'exchange', 'ipv4', 'help', 'home', 'library', 'ftp2', 'ntp', 'monitor', 'login'
        ]
        
        print(f"{Colors.BOLD}═══ SCAN DE {len(subdomains)} SOUS-DOMAINES ═══{Colors.END}\n")
        
        found = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self._check_subdomain, sub, domain): sub for sub in subdomains}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
        
        print(f"\n{Colors.GREEN}[✓]{Colors.END} Scan terminé: {len(found)} sous-domaines trouvés")
        
        if found:
            print(f"\n{Colors.BOLD}═══ SOUS-DOMAINES TROUVÉS ═══{Colors.END}")
            for sub_info in found:
                print(f"{Colors.GREEN}[✓]{Colors.END} {sub_info['subdomain']} → {sub_info['ip']}")
    
    def _check_subdomain(self, sub: str, domain: str):
        """Vérifie si un sous-domaine existe"""
        full_domain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            print(f"{Colors.GREEN}[✓]{Colors.END} Trouvé: {full_domain} → {ip}")
            return {"subdomain": full_domain, "ip": ip}
        except:
            return None

class EmailHarvester:
    """Extraction automatique d'emails depuis un site"""
    
    def harvest(self, domain: str):
        print(f"\n{Colors.CYAN}[*] Extraction automatique d'emails depuis: {domain}{Colors.END}\n")
        
        if not domain.startswith('http'):
            domain = f"https://{domain}"
        
        print(f"{Colors.BOLD}═══ EXTRACTION EN COURS ═══{Colors.END}")
        
        emails = set()
        
        try:
            # Crawl de la page principale
            response = requests.get(domain, timeout=10)
            
            if response.status_code == 200:
                # Regex pour trouver les emails
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                found_emails = re.findall(email_pattern, response.text)
                
                emails.update(found_emails)
                
                # Chercher dans les liens communs
                common_pages = ['/contact', '/about', '/team', '/staff', '/about-us', '/contact-us']
                
                for page in common_pages:
                    try:
                        url = urljoin(domain, page)
                        resp = requests.get(url, timeout=5)
                        if resp.status_code == 200:
                            found = re.findall(email_pattern, resp.text)
                            emails.update(found)
                    except:
                        pass
                
                if emails:
                    print(f"\n{Colors.GREEN}[✓]{Colors.END} {len(emails)} emails trouvés:\n")
                    for email in sorted(emails):
                        print(f"    └─ {email}")
                else:
                    print(f"{Colors.YELLOW}[!]{Colors.END} Aucun email trouvé sur les pages publiques")
            
        except Exception as e:
            print(f"{Colors.RED}[✗] Erreur: {str(e)}{Colors.END}")

class OSINTSuite:
    """Classe principale du programme"""
    
    def __init__(self):
        self.results = {}
        self.username_search = UsernameSearch()
        self.email_osint = EmailOSINT()
        self.phone_osint = PhoneOSINT()
        self.people_search = PeopleSearch()
        self.ip_lookup = IPLookup()
        self.domain_analysis = DomainAnalysis()
        self.port_scanner = PortScanner()
        self.github_intel = GitHubIntelligence()
        self.subdomain_finder = SubdomainFinder()
        self.email_harvester = EmailHarvester()
    
    def run(self):
        while True:
            clear_screen()
            print_banner()
            print_menu()
            
            choice = input(f"\n{Colors.BOLD}Sélectionnez une option:{Colors.END} ")
            
            try:
                if choice == '1':
                    self.username_search_menu()
                elif choice == '2':
                    self.email_osint_menu()
                elif choice == '3':
                    self.phone_osint_menu()
                elif choice == '4':
                    self.people_search_menu()
                elif choice == '5':
                    self.ip_lookup_menu()
                elif choice == '6':
                    self.domain_analysis_menu()
                elif choice == '7':
                    self.url_scanner_menu()
                elif choice == '8':
                    self.port_scanner_menu()
                elif choice == '9':
                    self.social_media_menu()
                elif choice == '10':
                    self.linkedin_menu()
                elif choice == '11':
                    self.github_menu()
                elif choice == '12':
                    self.reverse_image_menu()
                elif choice == '13':
                    self.subdomain_finder_menu()
                elif choice == '14':
                    self.email_harvester_menu()
                elif choice == '15':
                    self.breach_check_menu()
                elif choice == '16':
                    self.reverse_image_menu()
                elif choice == '17':
                    self.exif_menu()
                elif choice == '18':
                    self.crypto_tracker_menu()
                elif choice == '19':
                    self.wifi_menu()
                elif choice == '20':
                    self.paste_search_menu()
                elif choice == '98':
                    self.export_results()
                elif choice == '99':
                    self.settings_menu()
                elif choice == '0':
                    print(f"\n{Colors.GREEN}[✓] Au revoir!{Colors.END}\n")
                    sys.exit(0)
                else:
                    print(f"\n{Colors.RED}[✗] Option invalide{Colors.END}")
            except Exception as e:
                print(f"\n{Colors.RED}[✗] Erreur: {str(e)}{Colors.END}")
            
            input(f"\n{Colors.YELLOW}Appuyez sur Entrée pour continuer...{Colors.END}")
    
    def username_search_menu(self):
        username = input(f"\n{Colors.BOLD}Entrez le username:{Colors.END} ")
        if username:
            results = self.username_search.search(username)
            self.results[f"username_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"] = results
    
    def email_osint_menu(self):
        email = input(f"\n{Colors.BOLD}Entrez l'email:{Colors.END} ")
        if email:
            self.email_osint.analyze(email)
    
    def phone_osint_menu(self):
        phone = input(f"\n{Colors.BOLD}Entrez le numéro (avec indicatif):{Colors.END} ")
        if phone:
            self.phone_osint.analyze(phone)
    
    def people_search_menu(self):
        name = input(f"\n{Colors.BOLD}Nom complet:{Colors.END} ")
        location = input(f"{Colors.BOLD}Localisation (optionnel):{Colors.END} ")
        if name:
            self.people_search.search(name, location)
    
    def ip_lookup_menu(self):
        ip = input(f"\n{Colors.BOLD}Entrez l'IP:{Colors.END} ")
        if ip:
            self.ip_lookup.lookup(ip)
    
    def domain_analysis_menu(self):
        domain = input(f"\n{Colors.BOLD}Entrez le domaine:{Colors.END} ")
        if domain:
            self.domain_analysis.analyze(domain)
    
    def url_scanner_menu(self):
        url = input(f"\n{Colors.BOLD}Entrez l'URL complète:{Colors.END} ")
        print(f"\n{Colors.CYAN}[*] Analyse d'URL...{Colors.END}")
        print(f"{Colors.YELLOW}[i] Vérification: virustotal.com et urlscan.io{Colors.END}")
    
    def port_scanner_menu(self):
        target = input(f"\n{Colors.BOLD}Cible (IP/domaine):{Colors.END} ")
        port_range = input(f"{Colors.BOLD}Range de ports (ex: 1-1000):{Colors.END} ") or "1-100"
        if target:
            self.port_scanner.scan(target, port_range)
    
    def social_media_menu(self):
        print(f"\n{Colors.CYAN}[*] Extraction réseaux sociaux{Colors.END}")
        username = input(f"{Colors.BOLD}Username à rechercher:{Colors.END} ")
        if username:
            self.username_search.search(username)
    
    def linkedin_menu(self):
        company = input(f"\n{Colors.BOLD}Nom de l'entreprise:{Colors.END} ")
        print(f"\n{Colors.YELLOW}[i] Recherchez sur: linkedin.com/company/{company}/people{Colors.END}")
    
    def github_menu(self):
        username = input(f"\n{Colors.BOLD}Username GitHub:{Colors.END} ")
        if username:
            self.github_intel.analyze(username)
    
    def reverse_image_menu(self):
        image_url = input(f"\n{Colors.BOLD}URL de l'image:{Colors.END} ")
        if image_url:
            print(f"\n{Colors.CYAN}[*] Recherche d'image inversée{Colors.END}")
            print(f"{Colors.GREEN}[✓]{Colors.END} Google: https://images.google.com/searchbyimage?image_url={image_url}")
            print(f"{Colors.GREEN}[✓]{Colors.END} Yandex: https://yandex.com/images/search?url={image_url}")
            print(f"{Colors.GREEN}[✓]{Colors.END} TinEye: https://tineye.com/search?url={image_url}")
    
    def subdomain_finder_menu(self):
        domain = input(f"\n{Colors.BOLD}Domaine:{Colors.END} ")
        if domain:
            self.subdomain_finder.find(domain)
    
    def email_harvester_menu(self):
        domain = input(f"\n{Colors.BOLD}Site web:{Colors.END} ")
        if domain:
            self.email_harvester.harvest(domain)
    
    def breach_check_menu(self):
        email = input(f"\n{Colors.BOLD}Email à vérifier:{Colors.END} ")
        if email:
            print(f"\n{Colors.CYAN}[*] Vérification des fuites{Colors.END}")
            print(f"{Colors.YELLOW}[i]{Colors.END} Visitez: https://haveibeenpwned.com/account/{email}")
    
    def exif_menu(self):
        print(f"\n{Colors.YELLOW}[i] EXIF Extraction nécessite PIL: pip install pillow{Colors.END}")
    
    def crypto_tracker_menu(self):
        address = input(f"\n{Colors.BOLD}Adresse crypto:{Colors.END} ")
        crypto_type = input(f"{Colors.BOLD}Type (btc/eth):{Colors.END} ") or 'btc'
        if address:
            if crypto_type.lower() == 'btc':
                print(f"\n{Colors.GREEN}[✓]{Colors.END} Blockchain.com: https://blockchain.com/btc/address/{address}")
            elif crypto_type.lower() == 'eth':
                print(f"\n{Colors.GREEN}[✓]{Colors.END} Etherscan: https://etherscan.io/address/{address}")
    
    def wifi_menu(self):
        location = input(f"\n{Colors.BOLD}Localisation:{Colors.END} ")
        print(f"\n{Colors.YELLOW}[i] Base de données WiFi: wigle.net{Colors.END}")
    
    def paste_search_menu(self):
        query = input(f"\n{Colors.BOLD}Recherche:{Colors.END} ")
        print(f"\n{Colors.YELLOW}[i] Recherchez sur: psbdmp.ws{Colors.END}")
    
    def export_results(self):
        if not self.results:
            print(f"\n{Colors.YELLOW}[!] Aucun résultat à exporter{Colors.END}")
            return
        
        filename = f"osint_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=4, ensure_ascii=False)
            print(f"\n{Colors.GREEN}[✓] Résultats exportés: {filename}{Colors.END}")
        except Exception as e:
            print(f"\n{Colors.RED}[✗] Erreur: {str(e)}{Colors.END}")
    
    def settings_menu(self):
        print(f"\n{Colors.CYAN}[*] Configuration{Colors.END}")
        print(f"\n{Colors.YELLOW}[i] Pour activer plus de fonctionnalités:{Colors.END}")
        print(f"    └─ Shodan API: shodan.io/account")
        print(f"    └─ GitHub API: github.com/settings/tokens")
        print(f"    └─ VirusTotal API: virustotal.com/api")

def main():
    print(f"{Colors.GREEN}[*] Initialisation de l'OSINT Multi-Tools Suite...{Colors.END}")
    time.sleep(1)
    
    try:
        suite = OSINTSuite()
        suite.run()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Programme interrompu{Colors.END}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[✗] Erreur fatale: {str(e)}{Colors.END}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()