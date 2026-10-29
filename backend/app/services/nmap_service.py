import re, subprocess, tempfile, xml.etree.ElementTree as ET
from pathlib import Path
TARGET_RE = re.compile(r"^[A-Za-z0-9_.:/-]+$")
class NmapError(RuntimeError): pass

def validate_target(target: str) -> str:
    target = target.strip()
    if not target or len(target) > 64 or not TARGET_RE.fullmatch(target): raise ValueError("Invalid target format.")
    return target

def run_nmap_discovery(target: str) -> list[dict]:
    target = validate_target(target)
    with tempfile.TemporaryDirectory() as tmp:
        xml_path = Path(tmp) / "nmap.xml"
        cmd = ["nmap", "-Pn", "-sV", "--open", "-oX", str(xml_path), target]
        try: result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
        except FileNotFoundError as e: raise NmapError("Nmap is not installed or not on PATH.") from e
        except subprocess.TimeoutExpired as e: raise NmapError("Nmap scan timed out after 120 seconds.") from e
        if result.returncode != 0: raise NmapError(result.stderr.strip() or "Nmap failed")
        return parse_nmap_xml(xml_path)

def parse_nmap_xml(path: Path) -> list[dict]:
    root = ET.parse(path).getroot(); out=[]
    for host in root.findall("host"):
        status=host.find("status"); address=host.find("address")
        if address is None: continue
        hn=host.find("./hostnames/hostname"); osn=host.find("./os/osmatch")
        ports=[]
        for p in host.findall("./ports/port"):
            st=p.find("state"); svc=p.find("service")
            version=" ".join(x for x in [(svc.get("product") if svc is not None else None),(svc.get("version") if svc is not None else None),(svc.get("extrainfo") if svc is not None else None)] if x) or None
            ports.append({"port":int(p.get("portid",0)),"protocol":p.get("protocol","tcp"),"state":st.get("state","unknown") if st is not None else "unknown","service":svc.get("name") if svc is not None else None,"version":version})
        out.append({"ip_address":address.get("addr"),"hostname":hn.get("name") if hn is not None else None,"os_name":osn.get("name") if osn is not None else None,"status":status.get("state","unknown") if status is not None else "unknown","ports":ports})
    return out
