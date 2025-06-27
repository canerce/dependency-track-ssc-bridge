from flask import Flask, request, jsonify
import requests, logging, urllib3, base64, io, json, os
from datetime import datetime, timezone
from time import sleep
urllib3.disable_warnings()
app = Flask(__name__)

logging.basicConfig(level=logging.INFO, format='level=%(levelname)s timestamp=%(asctime)s message=%(message)s', datefmt='%Y-%m-%dT%H:%M:%SZ')

SSC_URL = os.environ.get("SSC_URL")
SSC_TOKEN = os.environ.get("SSC_TOKEN")
DTRACK_URL = os.environ.get("DTRACK_URL")
DTRACK_TOKEN = os.environ.get("DTRACK_TOKEN")

if not SSC_URL or not SSC_TOKEN or not DTRACK_URL or not DTRACK_TOKEN:
    exit(1)

HEADERS_SSC = {
    "Authorization": f"FortifyToken " + base64.b64encode(SSC_TOKEN.encode("utf-8")).decode("utf-8"),
    "Accept": "application/json",
    "Content-Type": "application/json"
}

HEADERS_DTRACK = {
    "X-Api-Key": DTRACK_TOKEN,
    "Content-Type": "application/json"
}
ANALYSIS_MAP = {"NOT_SET":"Suspicious","EXPLOITABLE":"Exploitable","IN_TRIAGE":"Suspicious","RESOLVED":"Not an Issue","FALSE_POSITIVE":"Not an Issue","NOT_AFFECTED":"Not an Issue"}

def safe_request(method, url, headers=None, json=None, files=None, params=None, verify=False, retries=3):
    for attempt in range(retries):
        try:
            response = requests.request(method, url, headers=headers, json=json, files=files, params=params, verify=verify, timeout=10)
            response.raise_for_status()
            return response
        except Exception as e:
            logging.warning(f"source=request_retry level=warning attempt={attempt+1} url={url} error={e}")
            sleep(2 ** attempt)
    logging.error(f"source=request_retry level=error url={url} message=All attempts failed")
    return None

def safe_json(response):
    try:
        return response.json()
    except ValueError:
        logging.error(f"level=error timestamp={datetime.now(timezone.utc).isoformat()} message=Non-JSON response from {response.url} status_code={response.status_code}")
        return None

def get_ssc_version_id(name, version):
    query = f"project.name:\"{name}\" AND name:\"{version}\""
    res = safe_request("GET", f"{SSC_URL}/api/v1/projectVersions?qm=adv&q={query}&fulltextsearch=false&start=0&limit=200&withoutCount=false&includeInactive=false", headers=HEADERS_SSC, verify=False)
    if not res:
        return None
    data = safe_json(res)
    if data is None:
        return None
    data = data.get("data", [])
    if data:
        version_id = data[0]["id"]
        return version_id
    
def create_ssc_application(application, version):
    request_json = {
        "name": version,
        "description": "",
        "active": True,
        "committed": True,
        "project": {
            "name": application,
            "description": "",
            "issueTemplateId": "Prioritized-HighRisk-Project-Template"
        },
        "issueTemplateId": "Prioritized-HighRisk-Project-Template"
    }
    res = safe_request("POST", f"{SSC_URL}/api/v1/projectVersions", headers=HEADERS_SSC, json=request_json, verify=False)
    if res:
        if res.status_code == 201:
            logging.info(f"source=fortify application={application} version={version} message=New application created")
            version_id = res.json().get("data", {}).get("id", {})
            return version_id
        else:
            message = res.json().get("message", "")
            logging.error(f"source=fortify level=error application={application} version={version} message=Application creation failed: {message}")
            return False
    else:
        logging.error(f"source=fortify level=error application={application} version={version} message=Application creation failed")
        return False
    
def set_ssc_application_attributes(version_id):
    request_json = {
    "requests": [
            {
                "uri": f"{SSC_URL}/api/v1/projectVersions/{version_id}/attributes",
                "httpVerb": "PUT",
                "postData": [
                    {
                        "values": [
                            {
                                "guid": "Active"
                            }
                        ],
                        "attributeDefinitionId": 5
                    },
                    {
                        "values": [
                            {
                                "guid": "Internal"
                            }
                        ],
                        "attributeDefinitionId": 6
                    },
                    {
                        "values": [
                            {
                                "guid": "internalnetwork"
                            }
                        ],
                        "attributeDefinitionId": 7
                    },
                    {
                        "values": [
                            {
                                "guid": "App"
                            }
                        ],
                        "attributeDefinitionId": 8
                    },
                    {
                        "values": [
                            {
                                "guid": "Windows"
                            }
                        ],
                        "attributeDefinitionId": 9
                    }
                ]
            },
            {
                "uri": f"{SSC_URL}/api/v1/projectVersions/{version_id}/authEntities",
                "httpVerb": "PUT",
                "postData": [
                ]
            },
            {
                "uri": f"{SSC_URL}/api/v1/projectVersions/{version_id}?hideProgress=true",
                "httpVerb": "PUT",
                "postData": {
                    "committed": True
                }
            }
        ]
    }
    res = safe_request("POST", f"{SSC_URL}/api/v1/bulk", headers=HEADERS_SSC, json=request_json, verify=False)
    if res:
        if res.status_code == 200:
            logging.info(f"source=fortify version_id={version_id} message=Application attributes added")
            return res.json()
        else:
            message = res.json().get("message", "")
            logging.error(f"source=fortify level=error version_id={version_id} message=Application attribute adding failed: {message}")
            return False
    else:
        logging.error(f"source=fortify level=error version_id={version_id} message=Application attribute adding failed")
        return False
    
def get_ssc_version_name(version_id):
    res = safe_request("GET", f"{SSC_URL}/api/v1/projectVersions/{version_id}", headers=HEADERS_SSC, verify=False)
    if not res:
        return None
    data = safe_json(res)
    if data is None:
        return None
    data = data.get("data", {})
    if data:
        result = {"proj_name": data["project"]["name"], "proj_version": data["name"]}
        return result 

def get_ssc_issue_revision_id(version_id, issue_id):
    res = safe_request("GET", f"{SSC_URL}/api/v1/projectVersions/{version_id}/issues/{issue_id}?fields=revision", headers=HEADERS_SSC, verify=False)
    if not res:
        return None
    data = safe_json(res)
    if data is None:
        return None
    data = data.get("data", {})
    if data:
        return data.get("revision", {})
    
def get_ssc_issue_vuln_id(issue_id):
    res = safe_request("GET", f"{SSC_URL}/api/v1/issueDetails/{issue_id}", headers=HEADERS_SSC, verify=False)
    if not res:
        return None
    data = safe_json(res)
    if data is None:
        return None
    data = data.get("data", {})
    if data:
        return data.get("customAttributes", {}).get("externalId", None)
    
def fing_ssc_issues_by_library(library_name, severity, version_id):
    params = {
        "qm": "issues",
        "start": 0,
        "limit": 200,
        "withoutCount": False,
        "showshortfilenames": False,
        "showhidden": False,
        "showremoved": False,
        "showsuppressed": True,
        "filterset": "a243b195-0a59-3f8b-1403-d55b7a7d78e6",
        "fields": "projectVersionId,id,issueInstanceId,fullFileName,revision",
        "q": f"[analysis type]:\"cyclonedx\" AND analyzer:\"configuration\" AND [engine priority]:\"{severity}\" AND file:{library_name}",
        "filter": f"ISSUE[11111111-1111-1111-1111-111111111165]:Insecure Deployment\\: Unpatched Application,ISSUE[11111111-1111-1111-1111-111111111151]:CYCLONEDX"
    }
    res = safe_request("GET", f"{SSC_URL}/api/v1/projectVersions/{version_id}/issues", headers=HEADERS_SSC, params=params, verify=False)
    if not res:
        return None
    data = safe_json(res)
    if data is None:
        return None
    data = data.get("data", {})
    if data:
        return data

def get_ssc_project_customtags(version_id):
    params = {
        "start": 0,
        "limit": 1,
        "withoutCount": True,
        "fields": "guid,valueList",
        "q": f"primaryTag:true"
    }
    res = safe_request("GET", f"{SSC_URL}/api/v1/projectVersions/{version_id}/customTags", headers=HEADERS_SSC, params=params, verify=False)
    if not res:
        return None
    data = safe_json(res)
    if data is None:
        return None
    data = data.get("data", {})
    if data:
        return data[0]

def update_ssc_issue_state(version_id, issue_id, revision_id, suppressed=False, state=""):
    res_suppres, res_state = None, None
    if suppressed:
        action_json = {
            "type": "AUDIT_ISSUE",
            "values": {
                "issues": [{"id": issue_id, "revision": revision_id}],
                "suppressed": True
            }
        }
        res_suppres = safe_request("POST", f"{SSC_URL}/api/v1/projectVersions/{version_id}/issues/action", headers=HEADERS_SSC, json=action_json, verify=False)
        logging.info(f"source=fortify version_id={version_id} issue_id={issue_id} suppressed={suppressed} message=Issue state changed")
    else:
        customtags = get_ssc_project_customtags(version_id)
        if not revision_id or not customtags:
            return False
        tags = [tag["lookupIndex"] for tag in customtags["valueList"] if tag["lookupValue"] == ANALYSIS_MAP[state]]
        action_json = {
            "type": "AUDIT_ISSUE",
            "values": {
                "issues": [{"id": issue_id,"revision": revision_id}],
                "customTagAudit": [{"customTagGuid": customtags.get("guid", ""),"newCustomTagIndex": tags[0]}],
                "suppressed": False
            }
        }
        res_state = safe_request("POST", f"{SSC_URL}/api/v1/projectVersions/{version_id}/issues/action", headers=HEADERS_SSC, json=action_json, verify=False)
        logging.info(f"source=fortify version_id={version_id} issue_id={issue_id} suppressed={suppressed} state={ANALYSIS_MAP[state]} message=Issue state changed")
    if not res_state or not res_suppres:
        return False
    else:
        return True
    
def upload_ssc_bom(version_id, files):
    upload_headers = HEADERS_SSC.copy()
    upload_headers.pop("Content-Type", None)
    res = safe_request("POST", f"{SSC_URL}/api/v1/projectVersions/{version_id}/artifacts?engineType=CYCLONEDX", headers=upload_headers, files=files, verify=False)
    if res:
        if res.status_code == 201:
            logging.info(f"source=dtrack version_id={version_id} message=Bom file uploaded")
            return True
        else:
            message = res.json()["message"]
            logging.error(f"source=fortify level=error version_id={version_id} message=Bom file upload failed: {message}")
            return False
    else:
        logging.error(f"source=fortify level=error version_id={version_id} message=Bom file upload failed")
        return False
    
def check_dtrack_property_by_uuid(uuid):
    res = safe_request("GET", f"{DTRACK_URL}/api/v1/project/{uuid}/property", headers=HEADERS_DTRACK)
    if not res:
        return None
    properties = safe_json(res)
    if not properties:
        return None
    version_id_list = [p["propertyValue"] for p in properties if p["propertyName"] == "fortify.ssc.applicationId"]
    if len(version_id_list) > 0:
        return version_id_list[0] 
    else:
        return None
    
def check_dtrack_property_by_name(name, version):
    res = safe_request("GET", f"{DTRACK_URL}/api/v1/project?pageNumber=1&pageSize=100&name={name}&excludeInactive=true", headers=HEADERS_DTRACK)
    if not res:
        return None
    projects = safe_json(res)
    if not projects:
        return None
    for project in projects:
        if project["version"] == version:
            version_id_list = [p["propertyValue"] for p in project.get("properties", []) if p["propertyName"] == "fortify.ssc.applicationId"]
            if len(version_id_list) > 0:
                result = {"version_id": version_id_list[0] , "uuid": project["uuid"]}
                return result
            else:
                result = {"version_id": None , "uuid": project["uuid"]}
                return result
    
def set_dtrack_property(uuid, version_id):
    body = {
        "groupName": "integrations",
        "propertyName": "fortify.ssc.applicationId",
        "propertyValue": str(version_id),
        "propertyType": "STRING",
        "description": "FortifySSC"
    }
    res = safe_request("PUT", f"{DTRACK_URL}/api/v1/project/{uuid}/property", headers=HEADERS_DTRACK, json=body)
    if res:
        if res.status_code == 201:
            return True
        else:
            logging.error(f"source=dtrack level=error version_id={version_id} uuid={uuid} message=Property assign failed: {res.content}")
            return False
    else:
        logging.error(f"source=dtrack level=error version_id={version_id} uuid={uuid} message=Property assign failed")
        return False
    
def download_dtrack_bom(uuid):
    download_headers = HEADERS_DTRACK.copy()
    download_headers["accept"] = "application/vnd.cyclonedx+json"
    res = safe_request("GET", f"{DTRACK_URL}/api/v1/bom/cyclonedx/project/{uuid}?format=json&variant=withVulnerabilities&download=false", headers=download_headers)
    if res:
        if res.status_code == 200:
            content = res.json()
            json_str = json.dumps(content)
            file_like = io.BytesIO(json_str.encode('utf-8'))
            files = {"file": (f"{uuid}.json", file_like, "application/json")}
            logging.info(f"source=dtrack uuid={uuid} message=Bom file downloaded")
            return files
        else:
            logging.error(f"source=fortify level=error uuid={uuid} message=Bom file download failed: {res.content}")
            return False
    else:
        logging.error(f"source=fortify level=error uuid={uuid} message=Bom file download failed")
        return False


@app.route("/healthz", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy"}), 200

@app.route("/dtrack", methods=["POST"])
def dtrack_webhook():
    data = request.get_json()
    if data:
        source_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
        timestamp = datetime.now(timezone.utc).isoformat()
        event_type = data.get("notification", {}).get("group")
        if event_type == "BOM_PROCESSED":
            subject = data.get("notification", {}).get("subject", {})
            proj = subject.get("project", {})
            uuid, name, version = proj["uuid"], proj["name"], proj["version"]
            logging.info(f"source=dtrack ip={source_ip} timestamp={timestamp} event={event_type} project={name} version={version} uuid={uuid}")
            version_id = check_dtrack_property_by_uuid(uuid)
            if not version_id:
                version_id = get_ssc_version_id(name, version)
                if not version_id:
                    version_id = create_ssc_application(name, version)
                    set_ssc_application_attributes(version_id)
                set_dtrack_property(uuid, version_id)
            files = download_dtrack_bom(uuid)
            if files:
                upload_ssc_bom(version_id, files)
        elif event_type == "PROJECT_AUDIT_CHANGE":
            subject = data.get("notification", {}).get("subject", {})
            for proj in subject.get("affectedProjects", []):
                uuid, name, version = proj["uuid"], proj["name"], proj["version"]
                logging.info(f"source=dtrack ip={source_ip} timestamp={timestamp} event={event_type} project={name} version={version} uuid={uuid}")
                version_id = check_dtrack_property_by_uuid(uuid)
                if not version_id:
                    version_id = get_ssc_version_id(name, version)
                    if not version_id:
                        version_id = create_ssc_application(name, version)
                        set_ssc_application_attributes(version_id)
                    res = set_dtrack_property(uuid, version_id)
                    if not res:
                        continue
                component = subject.get("component", {})
                component_name = component.get("name", "")
                component_purl = component.get("purl", "")
                vulnerability = subject.get("vulnerability", {})
                vulnerability_severity = vulnerability.get("severity", "")
                vulnerability_id = vulnerability.get("vulnId", "")
                analysis = subject.get("analysis", {})
                analysis_suppressed = analysis.get("suppressed", False)
                analysis_state = analysis.get("state", "")
                issues = fing_ssc_issues_by_library(component_name, vulnerability_severity, version_id)
                if not issues:
                    continue
                for issue in issues:
                    ssc_issue_id = get_ssc_issue_vuln_id(issue["id"])
                    if issue["fullFileName"] == component_purl and vulnerability_id == ssc_issue_id:
                        update_ssc_issue_state(version_id, issue["id"], issue["revision"], analysis_suppressed, analysis_state)
    return jsonify({"status": "ok"})