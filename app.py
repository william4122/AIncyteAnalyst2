import streamlit as st
import json
import pandas as pd
from collections import Counter
import ollama
import os
from datetime import datetime
import re # For regular expressions to extract identifiers

st.set_page_config(page_title="AIncyte Analyst", layout="wide")
st.title("Incyte Analyst")

# Feedback file location, locally for POC
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FEEDBACK_LOG_PATH = os.path.join(BASE_DIR, "feedback_log.jsonl")

def log_feedback(feedback_entry):
    with open(FEEDBACK_LOG_PATH, "a") as f:
        f.write(json.dumps(feedback_entry) + "\n")

# --- NEW: Telemetry Type Definitions and Keyword Mappings ---
# Define the telemetry types and keywords associated with them
# This will be used by the router to identify the relevant telemetry
TELEMETRY_TYPES = {
    "connection": {
        "keywords": ["connection", "traffic", "ip", "port", "remoteaddr", "localaddr", "proto", "state", "threat"],
        "fields": ["remoteAddr", "localAddr", "remotePort", "localPort", "proto", "pid", "state", "eventTime", "ip_reputation"], # Add more as needed
        "default_analysis_fields": ["remoteAddr", "localAddr", "remotePort"] # Fields to analyze for common/unusual
    },
    "process": {
        "keywords": ["process", "processes", "pid", "commandline", "executable", "user", "parentprocess"],
        "fields": [
            "pid", "ppid", "uid", "agent_id", "device_id", "hostid", "hostname",
            "name", "path", "md5", "sha1", "sha256", "ssdeep", "size", "signed", "owner",
            "commandline", "processstarted", "event_time", "compromised", "failed",
            "parentprocessname", "grandparentprocessname"
        ],
        "default_analysis_fields": ["name", "parentprocessname", "commandline", "event_time"]
    },
    "applications": {
        "keywords": ["application", "app", "install", "software", "product", "version", "vendor"],
        "fields": [
            "name",
            "vendor",
            "product",
            "version",
            "publisher",
            "applicationid",
            "cpe23uri",
            "hostid",
            "hostname",
            "agent_id",
            "device_id",
            "installdate",
            "created_on",
            "event_time",
            "created_date",
            "hostscan_id"
        ],
        "default_analysis_fields": ["name", "vendor", "version"]
    },
    "memscan": {
        "keywords": [
            "memory", "memorydump", "process", "pid", "handle", "module", "dll", "injection",
            "hook", "runtime", "artifact", "volatile", "heap", "stack", "malware", "code",
            "shellcode", "payload", "forensics", "compromised"
        ],
        "fields": [
            "md5", "sha1", "sha256", "ssdeep",
            "pid", "process_name", "name", "path", "owner",
            "created_on", "created_date", "event_time", "realtime",
            "compromised", "threatname", "protection",
            "flagname", "flagcolor", "flagweight", "avratio", "avtotal", "avpositives"
        ],
        "default_analysis_fields": ["pid", "process_name", "md5", "threatname"]
    },
    "autostart": {
        "keywords": [
            "autostart", "startup", "registry", "autorun", "persistence",
            "service", "scheduledtask", "runkey", "logon", "startupfolder",
            "boot", "process", "malware"
        ],
        "fields": [
            "md5", "sha1", "sha256", "ssdeep",
            "name", "path", "commandline", "size", "value",
            "regpath", "autostarttype",
            "signed", "signature",
            "created_on", "created_date", "filecreated", "filemodified", "event_time",
            "compromised", "threatname",
            "flagname", "flagcolor", "flagweight",
            "avratio", "avtotal", "avpositives",
            "failed"
        ],
        "default_analysis_fields": ["name", "regpath", "autostarttype", "path", "threatname", "compromised"]
    },
    "driver": {
        "keywords": [
            "driver", "sysfile", "kernel", "device", "module", "signed", "unsigned",
            "driverload", "drivermodule", "rootkit", "kernelmode", "hook", "malware"
        ],
        "fields": [
            "md5", "sha1", "sha256", "ssdeep",
            "name", "path", "size",
            "signed", "signature",
            "created_on", "created_date", "filecreated", "filemodified", "event_time",
            "compromised", "threatname",
            "flagname", "flagcolor", "flagweight",
            "avratio", "avtotal", "avpositives",
            "failed"
        ],
        "default_analysis_fields": ["name", "path", "md5", "signed", "threatname", "compromised"]
    },
    "modules": {
        "keywords": [
            "module", "dll", "sharedlibrary", "library", "component", "loadedmodule",
            "injection", "process", "memory", "malware"
        ],
        "fields": [
            "md5", "sha256", "sha1", "ssdeep",
            "name", "path", "size",
            "signed", "signature",
            "created_on", "created_date", "filecreated", "filemodified", "event_time",
            "compromised", "threatname",
            "flagname", "flagcolor", "flagweight",
            "avratio", "avtotal", "avpositives",
            "failed",
            "pidcount"
        ],
        "default_analysis_fields": ["name", "path", "md5", "signed", "threatname", "compromised"]
    },
    "script": {
        "keywords": [
            "script", "powershell", "batch", "bash", "cmd", "shell", "execution",
            "payload", "code", "commandline", "automation", "malware"
        ],
        "fields": [
            "md5", "sha1", "sha256", "ssdeep",
            "pid", "ppid", "name", "path", "size", "type",
            "commandline", "content",
            "created_on", "created_date", "event_time",
            "compromised", "threatname", "flagname", "flagcolor", "flagweight",
            "avratio", "avtotal", "avpositives",
            "failed",
            "hostid", "hostname", "device_id"
        ],
        "default_analysis_fields": ["name", "path", "pid", "commandline", "threatname", "compromised"]
    },
    "account": {
        "keywords": [
            "account", "user", "login", "logon", "privilege", "domain", "authentication",
            "credential", "session", "access", "logonserver"
        ],
        "fields": [
            "uid", "name", "fullname", "domain", "hostid", "hostname",
            "accountid", "logontype", "logoncount", "logonserver",
            "created_on", "event_time",
            "tenant", "item_id", "agent_id",
            "seq_no", "item_type",
            "hostscan_id", "instance_id"
        ],
        "default_analysis_fields": ["uid", "name", "domain", "logontype", "logonserver"]
    },
    "artifact": {
        "keywords": [
            "artifact", "file", "payload", "dropped", "execution", "evidence",
            "forensic", "autostart", "startup", "binary", "implant"
        ],
        "fields": [
            "md5", "sha1", "sha256", "ssdeep",
            "name", "path", "size", "signed", "signature",
            "filecreated", "filemodified", "modifiedon", "created_on", "created_date", "event_time", "executedon",
            "compromised", "threatname", "failed",
            "flagname", "flagcolor", "flagweight",
            "avratio", "avtotal", "avpositives",
            "artifacttype",
            "hostid", "hostname", "device_id", "agent_id"
        ],
        "default_analysis_fields": ["name", "path", "md5", "artifacttype", "event_time", "compromised"]
    }
}

# --- Refactored and Generalized Analytical Functions ---

def get_field_from_row(row, field_path):
    """Safely gets a nested field from a row (dict-like)."""
    parts = field_path.split('.')
    val = row
    for part in parts:
        if isinstance(val, dict):
            val = val.get(part)
        elif isinstance(val, pd.Series) and part in val: # For Pandas Series/Rows
             val = val.get(part)
        else:
            return None # Or raise an error, depending on desired behavior
        if val is None:
            return None
    return val

def apply_filters_general(query_text, telemetry_type_name):
    """Generates a list of filter functions based on query and telemetry type."""
    filters = []
    type_info = TELEMETRY_TYPES.get(telemetry_type_name, {})
    fields = type_info.get("fields", [])

    query_lower = query_text.lower()

    # General threat score filter (if applicable to the telemetry type)
    if "high threat" in query_lower and "ip_reputation" in fields:
        filters.append(lambda row: get_field_from_row(row, "ip_reputation.threat_score") is not None and get_field_from_row(row, "ip_reputation.threat_score") >= 0.9)

    # Protocol filters (specific to connections)
    if telemetry_type_name == "connections":
        if "udp" in query_lower:
            filters.append(lambda row: row.get("proto", "").lower() == "udp")
        elif "tcp" in query_lower:
            filters.append(lambda row: row.get("proto", "").lower() == "tcp")

    # Example: Process-specific filters
    if telemetry_type_name == "processes":
        if "system user" in query_lower:
            filters.append(lambda row: row.get("owner", "").lower() == "system" or row.get("user", "").lower() == "system") # Added owner check
        if "powershell" in query_lower:
            filters.append(lambda row: "powershell" in row.get("commandline", "").lower())
        if "malware" in query_lower or "compromised" in query_lower:
             filters.append(lambda row: row.get("compromised", False) == True or (row.get("threatname") is not None and row.get("threatname") != ""))

    # Example: Application-specific filters
    if telemetry_type_name == "applications":
        if "microsoft" in query_lower or "msft" in query_lower:
            filters.append(lambda row: row.get("vendor", "").lower() == "microsoft corporation")
        if "cve" in query_lower or "vulnerability" in query_lower:
            filters.append(lambda row: row.get("cvecount", 0) > 0)
            
    # Example: Autostarts filters
    if telemetry_type_name == "autostarts":
        if "regpath" in query_lower and "run" in query_lower:
            filters.append(lambda row: "run" in row.get("regpath", "").lower())
        if "persistence" in query_lower:
            filters.append(lambda row: row.get("autostarttype", "").lower() == "scheduledtask" or row.get("regpath", "").lower().startswith("hklm\\software\\microsoft\\windows\\currentversion\\run"))

    # Add more filters for other telemetry types here based on their fields and common queries
    # Make sure to check if the field exists in the row before accessing it.

    return filters

def filter_df_general(query_text, df, telemetry_type_name):
    """Applies filters to a DataFrame based on query and telemetry type."""
    filters = apply_filters_general(query_text, telemetry_type_name)
    for f in filters:
        # Using a copy to avoid SettingWithCopyWarning if original df is used elsewhere
        df = df[df.apply(f, axis=1)].copy()
    return df

def summarize_rows_general(filtered_df, telemetry_type_name, max_rows=10):
    """Generates concise summaries of rows based on telemetry type."""
    summaries = []
    type_info = TELEMETRY_TYPES.get(telemetry_type_name, {})
    
    # Generic fields that are often useful (must be present in the type's fields)
    common_fields_for_summary = [
        "name", "path", "hostname", "event_time", "user", "owner",
        "commandline", "version", "product", "vendor", "threatname", "compromised"
    ]

    for _, row in filtered_df.head(max_rows).iterrows():
        summary_parts = []

        if telemetry_type_name == "connections":
            rep = row.get("ip_reputation", {})
            summary_parts.append(f"{row.get('proto', 'N/A')} connection from {row.get('localAddr', 'N/A')} to {row.get('remoteAddr', 'N/A')}:{row.get('remotePort', 'N/A')}")
            summary_parts.append(f"(score: {get_field_from_row(row, 'ip_reputation.threat_score') or 0}, tags: {get_field_from_row(row, 'ip_reputation.tags') or '-'})")
        elif telemetry_type_name == "processes":
            summary_parts.append(f"Process '{row.get('name', 'N/A')}' (PID: {row.get('pid', 'N/A')}) launched by {row.get('owner', row.get('user', 'N/A'))}")
            if row.get("commandline"):
                summary_parts.append(f"Command: '{row.get('commandline')}'")
            if row.get("threatname"):
                summary_parts.append(f"Threat: {row.get('threatname')}")
        elif telemetry_type_name == "applications":
            summary_parts.append(f"Application '{row.get('name', 'N/A')}' by {row.get('vendor', 'N/A')} version {row.get('version', 'N/A')}")
            if row.get("cvecount"):
                summary_parts.append(f"(CVEs: {row.get('cvecount')})")
        elif telemetry_type_name == "autostarts":
            summary_parts.append(f"Autostart '{row.get('name', 'N/A')}' ({row.get('autostarttype', 'N/A')}) at {row.get('regpath', row.get('path', 'N/A'))}")
            if row.get("threatname"):
                summary_parts.append(f"Threat: {row.get('threatname')}")
        elif telemetry_type_name == "drivers":
            summary_parts.append(f"Driver '{row.get('name', 'N/A')}' ({row.get('md5', 'N/A')}) at {row.get('path', 'N/A')}")
            if row.get("signed") == False:
                 summary_parts.append("(Unsigned)")
            if row.get("threatname"):
                summary_parts.append(f"Threat: {row.get('threatname')}")
        elif telemetry_type_name == "modules":
            summary_parts.append(f"Module '{row.get('name', 'N/A')}' ({row.get('md5', 'N/A')}) loaded from {row.get('path', 'N/A')}")
            if row.get("signed") == False:
                summary_parts.append("(Unsigned)")
            if row.get("threatname"):
                summary_parts.append(f"Threat: {row.get('threatname')}")
        elif telemetry_type_name == "scripts":
            summary_parts.append(f"Script '{row.get('name', 'N/A')}' (Type: {row.get('type', 'N/A')}) from {row.get('path', 'N/A')}")
            if row.get("commandline"):
                summary_parts.append(f"Command: '{row.get('commandline')}'")
            if row.get("threatname"):
                summary_parts.append(f"Threat: {row.get('threatname')}")
        elif telemetry_type_name == "accounts":
            summary_parts.append(f"Account '{row.get('name', 'N/A')}' (Domain: {row.get('domain', 'N/A')}) logged on as {row.get('logontype', 'N/A')}")
            if row.get("logoncount"):
                summary_parts.append(f"Logon count: {row.get('logoncount')}")
        elif telemetry_type_name == "memory":
            summary_parts.append(f"Memory artifact for process '{row.get('process_name', 'N/A')}' ({row.get('pid', 'N/A')}) - {row.get('name', 'N/A')}")
            if row.get("threatname"):
                summary_parts.append(f"Threat: {row.get('threatname')}")
        # Add summarization logic for other telemetry types here
        else: # Generic summarization if specific logic isn't defined or for "data", "raw", "artifact" etc.
            # Try to build a summary from common fields present in the row
            for field in common_fields_for_summary:
                if field in row and pd.notna(row[field]): # Use pd.notna for NaN checks
                    summary_parts.append(f"{field}: {row[field]}")
            if not summary_parts and row is not None: # Fallback to showing raw row if no specific fields found
                # Ensure the row is a dict or can be converted to one
                try:
                    row_dict = row.to_dict() if isinstance(row, pd.Series) else row
                    summary_parts.append(f"Raw entry: {json.dumps(row_dict, default=str)}") # default=str to handle non-serializable types
                except Exception:
                    summary_parts.append(f"Raw entry: {row}")


        summaries.append(" ".join(summary_parts))
    return summaries


def handle_statistical_questions_general(query_text, df, telemetry_type_name):
    """Handles statistical questions based on telemetry type and available fields."""
    output = []
    query_lower = query_text.lower()
    type_info = TELEMETRY_TYPES.get(telemetry_type_name, {})
    default_analysis_fields = type_info.get("default_analysis_fields", [])

    # Check for specific IP/identifier in query for "unusual"
    # This logic is for any type that has a 'name' or 'remoteAddr' field to check for rarity
    identifier_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9\-\._]+\.[a-zA-Z]{2,6})\b', query_lower) # Matches IP or simple domain/filename
    
    if "is" in query_lower and "unusual" in query_lower and identifier_match:
        target_identifier = identifier_match.group(0)
        
        # Determine which field to check for rarity based on telemetry type
        field_to_check = None
        if telemetry_type_name == "connections" and "remoteAddr" in df.columns:
            field_to_check = "remoteAddr"
        elif telemetry_type_name in ["processes", "applications", "modules", "drivers", "autostarts", "scripts", "accounts"] and "name" in df.columns:
            field_to_check = "name"
        
        if field_to_check:
            count = (df[field_to_check].astype(str).str.lower() == target_identifier.lower()).sum() # Convert to string for consistent comparison
            if count > 0:
                output.append(f"'{target_identifier}' seen {count} times in {field_to_check} for {telemetry_type_name}.")
                if count <= 2: # Define 'unusual' as seen 2 or fewer times
                    output.append(f"Based on its low count ({count}), '{target_identifier}' appears unusual in this dataset.")
                else:
                    output.append(f"Based on its count ({count}), '{target_identifier}' does not appear unusual in this dataset.")
            else:
                output.append(f"'{target_identifier}' not found in {field_to_check} for {telemetry_type_name}.")
        else:
            output.append(f"Cannot perform 'unusual' check for '{target_identifier}' in {telemetry_type_name} as no relevant field was found.")


    # General "rare entries" logic (can be adapted for any unique identifier)
    if "rare connections" in query_lower or "rare entries" in query_lower:
        # Prioritize 'name' field for most types, 'remoteAddr' for connections
        field_to_check_for_rare = None
        if telemetry_type_name == "connections" and "remoteAddr" in df.columns:
            field_to_check_for_rare = "remoteAddr"
        elif "name" in df.columns: # Most other types have a 'name'
            field_to_check_for_rare = "name"
        elif "path" in df.columns: # Fallback for types like Drivers/Modules that might be named by path
            field_to_check_for_rare = "path"


        if field_to_check_for_rare:
            counts = df[field_to_check_for_rare].value_counts()
            rare_entries = counts[counts <= 2].index.tolist()
            if rare_entries:
                output.append(f"Rare {field_to_check_for_rare} entries (seen 2 or fewer times) in {telemetry_type_name}:")
                for entry in rare_entries[:5]: # Show top 5 rare entries
                    output.append(f"- {entry} (seen {counts[entry]} times)")
            else:
                output.append(f"No rare {field_to_check_for_rare} entries found in {telemetry_type_name}.")
        else:
            output.append(f"Cannot perform 'rare entries' check for {telemetry_type_name} as no suitable field was found.")


    # Common analysis for default fields
    for field in default_analysis_fields:
        # Check if "common <field>" or "most frequent <field>" is in the query
        if f"common {field.lower()}" in query_lower or f"most frequent {field.lower()}" in query_lower:
            if field in df.columns:
                top = Counter(df[field]).most_common(5)
                if top:
                    output.append(f"Top 5 common {field} in {telemetry_type_name}:")
                    output += [f"- {val} ({count} times)" for val, count in top]
                else:
                    output.append(f"No common {field} found in {telemetry_type_name}.")
            else:
                output.append(f"'{field}' field not found in {telemetry_type_name} data for common analysis.")
    return output

# --- NEW/ENHANCED: Telemetry Router Function ---
def identify_query_scope(query_text):
    """
    Identifies the most likely telemetry type(s) and any global identifiers (like hostname)
    based on keywords in the query.
    Returns a dictionary:
    {
        "target_types": list of identified telemetry type names,
        "global_filters": {"hostname": "extracted_hostname", "pid": "extracted_pid", ...}
    }
    """
    query_lower = query_text.lower()
    target_types = []
    global_filters = {}

    # 1. Identify specific telemetry types mentioned
    for type_name, info in TELEMETRY_TYPES.items():
        if any(keyword in query_lower for keyword in info["keywords"]):
            target_types.append(type_name)

    # 2. Extract global identifiers (e.g., hostname, IP, PID)
    # Hostname pattern (e.g., HOST-A, server-1, workstation-abc.domain.com, or common IP)
    # More robust hostname/IP extraction needed for production
    host_match = re.search(r'\b(host-\w+|[a-zA-Z0-9\-\._]+\.(?:com|org|net|io|local)|(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\b', query_lower)
    if host_match:
        extracted_id = host_match.group(0)
        # Check if it's an IP or a hostname-like string
        if re.match(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', extracted_id):
            global_filters["ip_address"] = extracted_id # For potential correlation by IP
        else:
            global_filters["hostname"] = extracted_id

    # PID extraction (e.g., "pid 1234", "process 5678")
    pid_match = re.search(r'\b(?:pid|process)\s+(\d+)\b', query_lower)
    if pid_match:
        global_filters["pid"] = int(pid_match.group(1))

    # 3. Heuristics for Correlation Queries or Default Behavior
    # If no specific types are mentioned but a global filter is present, imply correlation
    if not target_types and global_filters:
        # If a hostname/IP is mentioned without specific type, assume ALL relevant types
        # for that host/IP. This is the core of cross-telemetry correlation.
        target_types = list(TELEMETRY_TYPES.keys()) # Try all types
        st.info("No specific telemetry type mentioned, but global identifier found. Attempting to correlate across all relevant telemetry types.")
    elif not target_types and "threat" in query_lower:
        # If 'threat' is mentioned without specific type, default to connections
        target_types.append("connections")
    elif not target_types:
        # If absolutely no keywords or global filters, perhaps default to 'connections' or prompt user.
        # For now, if no types are identified, we'll indicate this in the main logic.
        pass
    
    return {
        "target_types": target_types,
        "global_filters": global_filters
    }

# --- NEW: Global Filter Application ---
def apply_global_filters(telemetry_dfs_dict, global_filters):
    """
    Applies global filters (e.g., hostname, IP, PID) across all relevant DataFrames.
    Returns a new dictionary of filtered DataFrames.
    """
    filtered_dfs = {}
    
    for type_name, df in telemetry_dfs_dict.items():
        current_filtered_df = df.copy() # Work on a copy

        if global_filters.get("hostname") and "hostname" in current_filtered_df.columns:
            current_filtered_df = current_filtered_df[current_filtered_df["hostname"].astype(str).str.lower() == global_filters["hostname"].lower()].copy()

        if global_filters.get("ip_address"): # This is a bit tricky for global as IPs are often local/remote specific
            # For IPs, we might need to check multiple fields depending on telemetry type
            if type_name == "connections" and ("remoteAddr" in current_filtered_df.columns or "localAddr" in current_filtered_df.columns):
                current_filtered_df = current_filtered_df[
                    (current_filtered_df["remoteAddr"].astype(str) == global_filters["ip_address"]) |
                    (current_filtered_df["localAddr"].astype(str) == global_filters["ip_address"])
                ].copy()
            # You would need similar logic for other types if they contain IP fields (e.g., DNS telemetry 'resolved_ip')

        if global_filters.get("pid") and "pid" in current_filtered_df.columns:
            current_filtered_df = current_filtered_df[current_filtered_df["pid"] == global_filters["pid"]].copy()

        # Add more global filters as needed (e.g., time ranges, user IDs)

        if not current_filtered_df.empty: # Only keep if something remains after filtering
            filtered_dfs[type_name] = current_filtered_df
            
    return filtered_dfs


# --- Streamlit UI and Main Logic ---

st.sidebar.header("Upload Telemetry")
uploaded_files = st.sidebar.file_uploader("Upload NDJSON Telemetry Files (e.g., connections.ndjson, processes.ndjson)", type=["ndjson"], accept_multiple_files=True)

# Store all loaded dataframes in a dictionary
telemetry_dfs = {}

if uploaded_files:
    for uploaded_file in uploaded_files:
        # Attempt to infer telemetry type from filename
        file_name_lower = uploaded_file.name.lower()
        inferred_type = None
        for type_name in TELEMETRY_TYPES.keys():
            if type_name in file_name_lower:
                inferred_type = type_name
                break
        
        if not inferred_type:
            st.warning(f"Could not infer telemetry type for {uploaded_file.name}. Please ensure filename contains a type keyword (e.g., 'connections.ndjson').")
            continue # Skip this file for now

        raw_lines = uploaded_file.read().decode("utf-8").strip().split("\n")
        try:
            # json_normalize flattens nested JSON structures which is good for ip_reputation
            df = pd.json_normalize(data=[json.loads(line) for line in raw_lines])

            # Ensure 'hostname' column is consistent across DFs if it exists
            if 'hostname' in df.columns:
                df['hostname'] = df['hostname'].astype(str)
            # Ensure 'pid' is numeric if it exists
            if 'pid' in df.columns:
                df['pid'] = pd.to_numeric(df['pid'], errors='coerce')


            telemetry_dfs[inferred_type] = df
            st.sidebar.success(f"Loaded {len(df)} {inferred_type} events from {uploaded_file.name}.")
        except json.JSONDecodeError as e:
            st.sidebar.error(f"Error decoding JSON from {uploaded_file.name}: {e}")
        except Exception as e:
            st.sidebar.error(f"Error processing {uploaded_file.name}: {e}")


if telemetry_dfs:
    st.subheader("Loaded Telemetry Overview")
    for type_name, df in telemetry_dfs.items():
        st.write(f"**{type_name.capitalize()} ({len(df)} entries)**")
        st.dataframe(df.head(5), use_container_width=True) # Show first 5 rows

    query = st.text_input("Ask a question about the telemetry:")

    if query:
        # Identify the relevant telemetry type(s) and global filters
        query_scope = identify_query_scope(query)
        target_types = query_scope["target_types"]
        global_filters = query_scope["global_filters"]

        if not target_types:
            st.warning("Could not clearly identify a specific telemetry type or correlation intent for your question. Please rephrase or include more context.")
            st.info("Currently supported telemetry types are: " + ", ".join([t.capitalize() for t in TELEMETRY_TYPES.keys()]))
        else:
            st.info(f"Query detected for telemetry types: **{', '.join([t.capitalize() for t in target_types])}**")
            if global_filters:
                st.info(f"Applying global filters: {global_filters}")

            # Apply global filters first to all relevant DFs
            globally_filtered_dfs = apply_global_filters(telemetry_dfs, global_filters)
            
            # Filter globally filtered DFs to only include target_types that were actually loaded
            # and have data after global filtering
            relevant_dfs_for_analysis = {
                t: globally_filtered_dfs[t] 
                for t in target_types 
                if t in globally_filtered_dfs and not globally_filtered_dfs[t].empty
            }

            if not relevant_dfs_for_analysis:
                st.warning("No relevant telemetry data found after applying filters. Please adjust your query or ensure correct files are loaded.")
            else:
                with st.spinner(f"Analyzing telemetry for {', '.join(relevant_dfs_for_analysis.keys())} and querying Incyte Analyst..."):
                    
                    combined_stat_output = []
                    combined_summaries = []
                    all_referenced_fields = []
                    all_referenced_rows = []

                    for type_name, current_df in relevant_dfs_for_analysis.items():
                        if not current_df.empty:
                            st.markdown(f"**Analyzing {type_name.capitalize()} Telemetry...**")
                            
                            stat_output = handle_statistical_questions_general(query, current_df, type_name)
                            # Apply type-specific filters to the already globally-filtered DataFrame
                            filtered_df = filter_df_general(query, current_df, type_name)
                            summaries = summarize_rows_general(filtered_df, type_name)

                            if stat_output:
                                combined_stat_output.append(f"--- {type_name.capitalize()} Statistical Analysis ---\n" + "\n".join(stat_output))
                            if summaries:
                                combined_summaries.append(f"--- Relevant {type_name.capitalize()} Telemetry (first {min(len(filtered_df), 10)} entries) ---\n" + "\n".join(summaries))
                            
                            all_referenced_fields.extend(TELEMETRY_TYPES[type_name].get("fields", []))
                            all_referenced_rows.extend(filtered_df.head(10).to_dict(orient="records"))
                    
                    context_parts = []
                    if combined_stat_output:
                        context_parts.append("\n\n".join(combined_stat_output))
                    if combined_summaries:
                        context_parts.append("\n\n".join(combined_summaries))
                    
                    context = "\n\n".join(context_parts)
                    
                    if not context:
                        # Fallback if no specific analysis found, provide a sample of each relevant DF
                        fallback_context_parts = []
                        for type_name, df in relevant_dfs_for_analysis.items():
                            if not df.empty:
                                fallback_context_parts.append(f"Sample of {type_name.capitalize()} Telemetry (first 5 entries):\n" + df.head(5).to_json(orient="records", indent=2))
                        context = "\n\n".join(fallback_context_parts)
                        if not context:
                             context = "No relevant telemetry data found for analysis." # Last resort
                        else:
                             st.info("No specific pre-analysis found for your query. Providing raw samples.")

                    prompt = f"""
You are a senior cybersecurity analyst mentoring a junior. You have access to various types of endpoint telemetry data.
Based on the user's query and the provided relevant telemetry context, analyze the situation and provide thoughtful, step-by-step investigation recommendations.
If the query involves correlation, explain the links between different telemetry types.

Relevant telemetry context:

{context}

User question: {query}

Analysis:
"""
                    try:
                        response = ollama.chat(model="llama3", messages=[{"role": "user", "content": prompt}])
                        model_response = response["message"]["content"]

                        st.markdown("### 🧠 Analysis")
                        st.write(model_response)

                        # Collect feedback
                        with st.expander("Was this answer helpful?"):
                            feedback_col1, feedback_col2 = st.columns([1, 4])
                            with feedback_col1:
                                user_feedback = st.radio("Your feedback:", ["👍", "👎"], horizontal=True, key="feedback_radio")
                            with feedback_col2:
                                correction_tags = st.multiselect(
                                    "Common issues (optional):",
                                    ["irrelevant response", "missed threat", "too vague", "false positive", "inaccurate enrichment"],
                                    key="feedback_tags"
                                )
                                correction_suggestion = st.text_area("Optional suggestion for improvement", key="feedback_textbox")

                            if st.button("Submit Feedback", key="feedback_submit"):
                                feedback_entry = {
                                    "timestamp": datetime.utcnow().isoformat(),
                                    "user_query": query,
                                    "model_response": model_response,
                                    "identified_telemetry_types": list(relevant_dfs_for_analysis.keys()), # Log all identified types
                                    "global_filters_applied": global_filters,
                                    "referenced_fields": list(set(all_referenced_fields)), # Unique list of all referenced fields
                                    "referenced_rows": all_referenced_rows, # Can be large, consider sampling
                                    "user_feedback": "thumbs_up" if user_feedback == "👍" else "thumbs_down",
                                    "correction_tags": correction_tags,
                                    "correction_suggestion": correction_suggestion
                                }
                                log_feedback(feedback_entry)
                                st.success("✅ Feedback submitted. Thank you!")
                    except Exception as e:
                        st.error(f"Error communicating with Ollama: {e}. Please ensure Ollama is running and 'llama3' model is available.")

else:
    st.info("Upload NDJSON telemetry files to begin analysis.")