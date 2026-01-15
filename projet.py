import feedparser
import requests
import time
import re
import os
import json

def extract_rss(url, bulletin_type):
    """
    Extrait les informations d'un flux RSS ANSSI
    :param url: URL du flux RSS
    :param bulletin_type: 'Alerte' ou 'Avis'
    :return: liste de dictionnaires
    """
    feed = feedparser.parse(url)
    results = []
    for entry in feed.entries:
        data = {
            "titre": entry.title,
            "description": entry.description,
            "date": entry.published,
            "lien": entry.link,
            "type": bulletin_type
        }
        results.append(data)

    return results


CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"

def extract_cves_from_bulletin(bulletin_url):
    """
    Extrait les CVE depuis le JSON d'un bulletin ANSSI
    """
    json_url = bulletin_url + "json/"
    cves = set()

    try:
        response = requests.get(json_url, timeout=10)
        response.raise_for_status()
        data = response.json()

        # Extraction via la clé "cves"
        if "cves" in data:
            for cve in data["cves"]:
                if "name" in cve:
                    cves.add(cve["name"])

        # Extraction via regex (backup)
        regex_cves = re.findall(CVE_PATTERN, str(data))
        cves.update(regex_cves)

    except Exception as e:
        print(f"Erreur lors de l'accès à {json_url} : {e}")

    return list(cves)

def enrich_cve_mitre(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"

    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()

        cna = data.get("containers", {}).get("cna", {})

        # Description
        description = "N/A"
        descriptions = cna.get("descriptions", [])
        if descriptions:
            description = descriptions[0].get("value", "N/A")

        # CVSS + Severity
        cvss_score = "N/A"
        severity = "N/A"
        metrics = cna.get("metrics", [])

        if metrics:
            metric = metrics[0]
            for v in ["cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                if v in metric:
                    cvss_score = metric[v].get("baseScore", "N/A")
                    severity = metric[v].get("baseSeverity", "N/A")
                    break

        # CWE
        cwe = "N/A"
        problem_types = cna.get("problemTypes", [])
        if problem_types:
            desc = problem_types[0].get("descriptions", [])
            if desc:
                cwe = desc[0].get("cweId", desc[0].get("description", "N/A"))

        # Produits + versions
        produits = []
        affected = cna.get("affected", [])

        for p in affected:
            vendor = p.get("vendor", "Inconnu")
            product = p.get("product", "Inconnu")
            versions = [
                v.get("version")
                for v in p.get("versions", [])
                if v.get("status") == "affected"
            ]
            produits.append({
                "vendor": vendor,
                "product": product,
                "versions": versions
            })

        return {
            "CVE_ID": cve_id,
            "Description": description,
            "CVSS": cvss_score,
            "BaseSeverity": severity,
            "CWE": cwe,
            "Produits": produits
        }

    except Exception as e:
        print(f"Erreur MITRE {cve_id} : {e}")
        return None


def enrich_cve_epss(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"

    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()

        epss_data = data.get("data", [])
        if epss_data:
            return float(epss_data[0].get("epss", 0))
        else:
            return None

    except Exception as e:
        print(f"Erreur EPSS {cve_id} : {e}")
        return None



def load_bulletin(path, bulletin_type):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    return {
        "id": data.get("reference"),
        "titre": data.get("title"),
        "date": data.get("date"),
        "type": bulletin_type,
        "lien": data.get("link"),
        "cves": [c["name"] for c in data.get("cves", [])]
    }
    
def load_mitre_cve(cve_id):
    try:
        with open(os.path.join("mitre", cve_id), encoding="utf-8") as f:
            data = json.load(f)
    except:
        return None

    cna = data.get("containers", {}).get("cna", {})

    # Description
    description = "N/A"
    if cna.get("descriptions"):
        description = cna["descriptions"][0].get("value", "N/A")

    # CVSS + severity
    cvss = severity = "N/A"
    metrics = cna.get("metrics", [])
    if metrics:
        for v in ["cvssV3_1", "cvssV3_0", "cvssV2_0"]:
            if v in metrics[0]:
                cvss = metrics[0][v].get("baseScore", "N/A")
                severity = metrics[0][v].get("baseSeverity", "N/A")
                break

    # CWE
    cwe = "N/A"
    if cna.get("problemTypes"):
        desc = cna["problemTypes"][0].get("descriptions", [])
        if desc:
            cwe = desc[0].get("cweId", desc[0].get("description", "N/A"))

    # Produits
    produits = []
    for p in cna.get("affected", []):
        produits.append({
            "vendor": p.get("vendor"),
            "product": p.get("product"),
            "versions": [
                v.get("version")
                for v in p.get("versions", [])
                if v.get("status") == "affected"
            ]
        })

    return {
        "Description": description,
        "CVSS": cvss,
        "BaseSeverity": severity,
        "CWE": cwe,
        "Produits": produits
    }

    
def load_epss_cve(cve_id):
    try:
        with open(os.path.join("first", cve_id), encoding="utf-8") as f:
            data = json.load(f)
            epss_data = data.get("data", [])
            if epss_data:
                return epss_data[0].get("epss")
    except:
        pass
    return None
