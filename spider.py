import csv
import tldextract
from urllib.parse import urlparse, parse_qs, unquote ,urlunparse
import re
import requests
import unicodedata
import difflib

def print_banner():
    print(r"""                                                                                                    
                         .     ..                                 ..     .                          
                        .-    .+.                                .-+     -.                         
                       -#.    +-                                  .++    .+-                        
                      +#.    +#.                                   .#+    -#-                       
                    .+#-    +#-                                    .+#-    -#-                      
                   .+#+.   -##.                                     .##-    +#+.                    
                  .+##.   .##-                                       +##.   .##+                    
                  -##-    ###.                                       -##+    -##-                   
                 -##+    -##+                                        .###-    +##.                  
                .###.   .###.                                         -###.   .###.                 
                +##-    +###.                                         .###-    -##-                 
               .###.   .###+                                          .####.   .###.                
               +##+    +###-                                           +###+    +##-                
              .###-   .####.                                           -####.   -###.               
              +###.   +####.                                           -####-   .###-               
             .####   .#####-..........---.               .---..........+#####.  .####.              
             +###+   .+##################+.  .--.  --.  .+##################+.   ####-              
            .####+     -+#+++++--------+###+-#++-.--##-+###----+------++##+-.    +####.             
            -####-         ....-+#####-.-################+..-#####+-...  .       +####-             
           .#####-     .-+###############################################+-.     -####+             
           .######+++########+---.....--+#################++---------+#######++++######.            
            .+#########+--..   .+++++++++#################++++++++-.  ...--+#########+-             
              -+###+--.       -#####################################-       ..--###+-.              
                ...         .+###+-.. .-###################-. .-++###+.         ....                
                          .#####.   .-####+#############+####-.   -#####.                           
                        -#####.   .+####---#############--+####+.  .-#####-                         
                     .+####+.  -+#####+-.-###############-.-+#####+. .-+####-.                      
                   .+####-.    -#####-.  +###############+  .-#####-   .--####+.                    
                .-+###+-..     -####+.   -###############-    +####-     ..-+###+-.                 
             ..+####+-..       +#####.   .###############.   .#####-        .-+####+..              
       .+...+#####+..          +#####.    +#############+    .#####-           .+#####+...+.        
       .########-..            +#####.    -#############-    .#####-             .-########.        
       .######-.               +#####.    .#############.    .#####-               .-#####+         
        +####-.                +####+      -###########-      +####-                 -####+         
        -####.                 +####+      .+##########.      +####-                 -####-         
        -####.                 +####+       -#########-       +####-                 -####-         
        .####-.                +####+        +#######+.       +####-                 -####.         
        .####-.                -####+        .######+.        +####-                 +###+.         
         +###+.                -####-         -#####-.        +####-                 ####-          
         -###+.                -####-          -#-+-.         +####.                .####-          
         .####.                .####-           . .           +####.                .####.          
          +###-                .####-                         +####                 -###+.          
          -###+.                +###+                         +###+                 +###.           
          .+##+.                -###+                         +###-                .###+            
           .###.                .###+                        .+###.                -###.            
            -##-                 ####.                       .###+                 +##-             
            .##+.                +###.                       .###-                .##+.             
             .##-                .###.                       .###.                -##-              
              -#+.                ###-                       -##+                .##+               
              .+#-                -##-                       +##-                -#+.               
               .#+.               .###.                     .###.               .##.                
                -#-                +##.                     .##-                +#-                 
                 -#.               .##-                     -##.               .#-                  
                  -+                +##.                   .##-                +-                   
                   --               .##-                   -#+.               --                    
                    .                -#+.                 .+#-                .                     
                                      +#-                 -#-                                       
                                      .++.               .#+.                                       
                                       .+-               -+.                                        
                                        .+-             -#.                                         
                                         .-.           .+-.                                         
                                          ..          .-..                                          
                                                      ..                                                                   

                    Developed by Modaser Samir (MODZ)
                              v1.0.0
    """)

#apis
def check_external_apis(url):
    try:
        # =========================
        # Google Safe Browsing
        gsb_api = " " # Put your Google safe browing Api-key here

        gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_api}"

        gsb_payload = {
            "client": {
                "clientId": "url-scanner",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        gsb_res = requests.post(gsb_url, json=gsb_payload, timeout=5)

        if gsb_res.status_code == 200 and gsb_res.json():
            return "malicious"

        # =========================
        # VirusTotal
        vt_api = " " # Put your Virustotal Api-key here

        headers = {
            "x-apikey": vt_api
        }

        vt_url = f"https://www.virustotal.com/api/v3/urls"

        # encode URL
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        vt_res = requests.get(f"{vt_url}/{url_id}", headers=headers, timeout=5)

        if vt_res.status_code == 200:
            data = vt_res.json()

            malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]

            if malicious > 0:
                return "malicious"
            else:
                return "clean"

        return "unknown"

    except:
        return "unknown"
#typo squatting
def check_typos_csv(url, typo_file):
    domain = extract_domain(url)

    with open(typo_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        for row in reader:
            csv_domain = row['domain'].strip().lower()

            if domain == csv_domain:
                return {
                    "found": True,
                    "type": row['fuzzer']
                }

    return {
        "found": False,
        "type": None
    }
# =========================
def detect_homograph(domain):
    result = {"score": 0, "reasons": []}

    # =========================
    # 1. Punycode
    if "xn--" in domain:
        result["score"] += 30
        result["reasons"].append("Punycode detected (IDN attack)")

    # =========================
    # 2. Unicode characters
    try:
        domain.encode("ascii")
    except:
        result["score"] += 30
        result["reasons"].append("Non-ASCII characters detected")

    # =========================
    # 3. Mixed scripts detection
    scripts = set()

    for char in domain:
        try:
            name = unicodedata.name(char)
            if "LATIN" in name:
                scripts.add("latin")
            elif "CYRILLIC" in name:
                scripts.add("cyrillic")
            elif "GREEK" in name:
                scripts.add("greek")
            elif "ARABIC" in name:
                scripts.add("arabic")
        except:
            continue

    if len(scripts) > 1:
        result["score"] += 30
        result["reasons"].append(f"Mixed scripts detected: {scripts}")

    return result

    # =========================
def clean_expanded_url(url):
    parsed = urlparse(url)

    netloc = parsed.netloc.lower()


    if netloc.startswith("www."):
        netloc = netloc[4:]


    cleaned_url = urlunparse((
        parsed.scheme,
        netloc,
        parsed.path,
        parsed.params,
        parsed.query,
        parsed.fragment
    ))

    return cleaned_url
# LOADERS

def load_domains(file_path, column_name=None):
    data = set()
    with open(file_path, 'r', encoding='utf-8') as f:
        if column_name:
            reader = csv.DictReader(f)
            for row in reader:
                data.add(row[column_name].strip().lower())
        else:
            reader = csv.reader(f)
            for row in reader:
                data.add(row[0].strip().lower())
    return data

# =========================

def extract_domain(url):
    if not url.startswith("http"):
        url = "http://" + url
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}".lower()

# =========================

def expand_url(url):
    try:
        r = requests.get(url, timeout=3, allow_redirects=True)
        return r.url
    except:
        return url

# =========================
# OPEN REDIRECT HANDLER

def handle_redirects(url, phishing, tranco):
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    redirect_keys = ["redirect", "url", "next", "return"]

    for key in redirect_keys:
        if key in query_params:
            for val in query_params[key]:
                extracted = unquote(val)

                domain = extract_domain(extracted)

                # blacklist
                if domain in phishing:
                    return "phishing", extracted

                # whitelist
                if domain in tranco:
                    return "clean", extracted

                return "analyze", extracted

    return None, None

# =========================
# ANALYSIS

def analyze_url(url, keywords, suspicious_tlds):
    result = {"score": 0, "reasons": []}

    if not url.startswith("http"):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    ext = tldextract.extract(url)
    full_domain = domain
    main_domain = f"{ext.domain}.{ext.suffix}"
    homo = detect_homograph(domain)
    result["score"] += homo["score"]
    result["reasons"].extend(homo["reasons"])
    # =========================
    # =========================
    # Fake subdomain (FIXED)
    if any(k in full_domain for k in keywords) and main_domain not in full_domain.split(".")[0]:
        result["score"] += 30
        result["reasons"].append("Fake subdomain impersonation")

    # =========================
    if url.count("@") > 0:
        result["score"] += 90
        result["reasons"].append("Contains @")

    if "%" in url:
        result["score"] += 30
        result["reasons"].append("Encoded characters")

    if "//" in path:
        result["score"] += 30
        result["reasons"].append("Double slash")

    if url.count("?") > 1:
        result["score"] += 30
        result["reasons"].append("Multiple ?")

    if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
        result["score"] += 70
        result["reasons"].append("IP address")

    # subdomains
    sub_count = domain.count(".") - 1
    if sub_count == 4:
        result["score"] += 2
        result["reasons"].append("4 subdomains")
    elif sub_count > 4:
        result["score"] += 70
        result["reasons"].append("Too many subdomains")

    if ext.suffix in suspicious_tlds:
        result["score"] += 8
        result["reasons"].append("Suspicous top level domain")

    if domain.count("-") >= 2 :
        result["score"] += 8
        result["reasons"].append("Too many Hyphens")

    if len(url) <= 300:
        result["score"] += 0

    elif len(url) > 300:
        result["reasons"].append("Very long url")
    return result

# =========================
# MAIN SCAN

def scan_url(url, phishing, tranco, keywords, tlds, shorteners):

    print(f"\nChecking: {url}")

    domain = url
    main_domain = extract_domain(url)
    typo_check = check_typos_csv(url, "dnstwist.csv")
    if typo_check["found"]:
        print("Phishing (Typosquatting)")
        print(f"Type: {typo_check['type']}")
        return
    # =========================
    # 1. BLACKLIST
    if domain in phishing:
        print("Phishing (Blacklist)")
        return
    # =========================
    # 3. SHORTENER FIX
    if main_domain in shorteners:
        print("Expanding shortener...")
        expanded = expand_url(url)
        if expanded != url:
            print(f"Expanded to: {expanded}")
            cleaned = clean_expanded_url(expanded)
            cleaned = extract_domain(cleaned)
            return scan_url(cleaned, phishing, tranco, keywords, tlds, shorteners)
        elif expanded == url:
            print("Could not expand shortener")
            print("Suspicious Possible phishing")
            return
    # =========================
    # 2. WHITELIST
    cleaned_domain = clean_expanded_url(url)
    main_domain = extract_domain(cleaned_domain)

    # =========================
    # 4. OPEN REDIRECT FIX
    status, new_url = handle_redirects(url, phishing, tranco)

    if status == "phishing":
        print("Phishing (Redirect)")
        return

    elif status == "clean":
        print("Clean (Redirect to trusted)")
        return

    elif status == "analyze":
        print("Suspicious Possible phishing")
        return

    # =========================
    # 5. ANALYSIS
    analysis = analyze_url(url, keywords, tlds)
    score = analysis["score"]

    # =========================
    # FINAL DECISION
    if score >= 20:
        verdict = "Phishing"
    elif 1 <= score <= 19:
        verdict = "Suspicious"
        api_result = check_external_apis(url)

    else:
        # score == 0
        if main_domain in tranco:
            verdict = "Clean (Trusted Domain)"
        else:
            api_result = check_external_apis(url)

            if api_result == "malicious":
                verdict = "Phishing (API Confirmed)"
            else:
                verdict = "Clean"

    print(verdict)
    print(f"Score: {score}")
    print("Reasons:")
    for r in analysis["reasons"]:
        print("-", r)

# =========================

if __name__ == "__main__":
    print_banner()
    phishing = load_domains("phishing-urls.csv", "Domain")
    tranco = load_domains("tranco.csv")
    keywords = load_domains("possible_ph_keys.csv")
    tlds = load_domains("suspicious_tlds_list.csv", "metadata_tld")
    shorteners = load_domains("Shortners.csv", "URL_SHORTNERS")

    url = input("Enter URL: ").strip()

    if not re.match(r"^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/.*)?$", url):
        print("Invalid URL. Bye!")
    else:
        scan_url(url, phishing, tranco, keywords, tlds, shorteners)
