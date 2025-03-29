import datetime
import os
import psutil
import matplotlib.pyplot as plt
import PySimpleGUI as sg
from evtx import PyEvtxParser
from lxml import etree
from collections import Counter

# ---------------------------
# Configuration & Known Patterns
# ---------------------------

# Known LOLBins (exact names for matching)
known_lolbins = [
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "wmic.exe", "powershell.exe",
    "certutil.exe", "bitsadmin.exe", "schtasks.exe", "cmd.exe", "cscript.exe",
    "wscript.exe", "installutil.exe", "cmstp.exe", "msbuild.exe"
]

# Suspicious command-line patterns (all lower-case)
suspicious_patterns = [
    "-encodedcommand", "iex(", "downloadstring", "invoke-webrequest",
    "base64", "-enc", "-nop", "-w hidden"
]

# A list of common safe parent processes (lower-case)
safe_parents = ["explorer.exe", "services.exe", "svchost.exe", "wininit.exe"]

# ---------------------------
# Helper Functions for Live Monitoring
# ---------------------------

def is_exact_lolbin(process_name):
    return process_name.lower() in known_lolbins

def is_suspicious_cmdline(cmdline):
    # cmdline may be a list; join into a single string for matching
    cmd = " ".join(cmdline).lower() if cmdline else ""
    return any(pattern in cmd for pattern in suspicious_patterns)

def get_process_chain(proc):
    """Retrieve the parent chain as a list of process names."""
    chain = []
    try:
        parent = proc.parent()
        while parent:
            chain.append(parent.name().lower())
            parent = parent.parent()
    except Exception:
        pass
    return chain

def get_network_connections(proc):
    """Retrieve a list of active network connections (remote addresses) for a process."""
    connections = []
    try:
        # 'inet' returns both TCP and UDP connections.
        for conn in proc.connections(kind='inet'):
            # Filter out local/loopback addresses
            if conn.raddr and conn.raddr.ip not in ("127.0.0.1", "::1"):
                connections.append(f"{conn.raddr.ip}:{conn.raddr.port}")
    except Exception:
        pass
    return connections

def further_analysis_live(proc):
    # Basic info
    name = proc.info.get('name', "N/A")
    pid = proc.info.get('pid', "N/A")
    cmdline_list = proc.info.get('cmdline', [])
    cmdline = " ".join(cmdline_list) if cmdline_list else ""
    
    # Process chain analysis
    chain = get_process_chain(proc)
    chain_str = " -> ".join(chain) if chain else "N/A"
    
    # Behavior analysis: check command line
    behavior_note = "Suspicious command line detected" if is_suspicious_cmdline(cmdline_list) else ""
    
    # Parent analysis: check if immediate parent is safe
    try:
        parent = proc.parent()
        parent_name = parent.name().lower() if parent else "N/A"
    except Exception:
        parent_name = "Unavailable"
    parent_note = ""
    if parent_name and parent_name not in safe_parents:
        parent_note = f"Unusual parent: {parent_name}"
    else:
        parent_note = "Parent appears normal"
    
    # Network connection logging:
    net_conns = get_network_connections(proc)
    if not net_conns:
        # Check parent's connections if none found
        try:
            parent = proc.parent()
            if parent:
                net_conns = get_network_connections(parent)
        except Exception:
            pass

    # If still none, check the process chain for sshd.exe occurrences
    if not net_conns:
        sshd_count = chain.count("sshd.exe")
        if sshd_count >= 2:
            net_info = "Active SSH connection established (via sshd chain)"
        else:
            net_info = "No active remote connections"
    else:
        net_info = ", ".join(net_conns)
    
    # Combine notes
    notes = "; ".join(filter(None, [behavior_note, parent_note]))
    if not notes:
        notes = "No additional issues"
    
    return {
        "name": name,
        "pid": pid,
        "cmdline": cmdline,
        "chain": chain_str,
        "net_info": net_info,
        "notes": notes
    }

# ---------------------------
# Live Process Monitoring Mode
# ---------------------------

def live_monitor():
    sg.theme("DarkTeal2")
    layout = [
        [sg.Text("Live Process Monitoring", font=("Arial", 16, "bold"))],
        [sg.Multiline(size=(100, 20), key='-MONITOR-', autoscroll=True, disabled=True)],
        [sg.Button("Stop", font=("Arial", 12, "bold"))]
    ]
    window = sg.Window("Live Process Monitor", layout, finalize=True)
    
    alerted = set()       # Track processes already alerted on (by PID, name)
    sshd_alerted = set()  # Track sshd processes for popup alerts
    
    while True:
        event, _ = window.read(timeout=500)
        if event in (sg.WIN_CLOSED, "Stop"):
            break
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                name = proc.info.get('name')
                pid = proc.info.get('pid')
                cmdline_list = proc.info.get('cmdline', [])
                if not name:
                    continue

                # --- New: Check if an sshd.exe process is detected and popup an alert ---
                if name.lower() == "sshd.exe":
                    key = (pid, name)
                    if key not in sshd_alerted:
                        sshd_alerted.add(key)
                        sg.PopupNoWait("ALERT: sshd process detected!",
                                       f"sshd.exe (PID: {pid}) is running.\nAn active SSH connection might be established.",
                                       keep_on_top=True)
                
                alert_triggered = False
                reason = ""
                # Check for known LOLBin (exact match)
                if is_exact_lolbin(name):
                    reason = "Known LOLBin detected"
                    alert_triggered = True
                # Or check for suspicious command line behavior
                elif is_suspicious_cmdline(cmdline_list):
                    reason = "Suspicious command line usage"
                    alert_triggered = True
                
                if alert_triggered:
                    key = (pid, name)
                    if key not in alerted:
                        alerted.add(key)
                        analysis = further_analysis_live(proc)
                        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        message = (
                            f"[{timestamp}] ALERT: {analysis['name']} (PID: {analysis['pid']})\n"
                            f"   Reason: {reason}\n"
                            f"   Command Line: {analysis['cmdline']}\n"
                            f"   Process Chain: {analysis['chain']}\n"
                            f"   Network Info: {analysis['net_info']}\n"
                            f"   Analysis Notes: {analysis['notes']}\n\n"
                        )
                        window['-MONITOR-'].print(message)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    window.close()

# ---------------------------
# EVTX Log Analysis Mode (Enhanced)
# ---------------------------

def parse_evtx(event):
    sys_tag = event.find("System", event.nsmap)
    event_id = sys_tag.find("EventID", event.nsmap)
    event_ts = sys_tag.find("TimeCreated", event.nsmap)
    event_data = event.find("EventData", event.nsmap)
    record = {"ts": event_ts.values()[0], "eid": event_id.text}
    for data in event_data.getchildren():
        record[data.attrib["Name"]] = data.text
    return record

def open_evtx_file(logs_folder):
    parser = PyEvtxParser(logs_folder)
    for record in parser.records():
        yield etree.fromstring(bytes(record['data'], encoding='utf8'))

def is_evtx_cmdline_suspicious(cmdline):
    # Lowercase and check for suspicious patterns
    cmd = cmdline.lower() if cmdline else ""
    return any(pattern in cmd for pattern in suspicious_patterns)

def detect_suspicious_activity_in_evtx(logs_folder):
    detected_records = []
    for log_entry in open_evtx_file(logs_folder):
        try:
            record = parse_evtx(log_entry)
            # Process creation events (Event ID 4688) with a command line present
            if record["eid"] == "4688" and record.get("CommandLine"):
                new_proc = record.get("NewProcessName", "")
                base_proc = os.path.basename(new_proc).lower()
                cmdline = record.get("CommandLine", "").lower()
                parent = record.get("ParentProcessName", "").lower() if record.get("ParentProcessName") else ""
                
                flag = False
                reason = ""
                # Flag if a known LOLBin is used
                if base_proc in known_lolbins:
                    flag = True
                    reason = "Known LOLBin detected"
                # Or if the command line is suspicious
                elif is_evtx_cmdline_suspicious(cmdline):
                    flag = True
                    reason = "Suspicious command line"
                
                if flag:
                    # Further analysis: check if parent process is unusual
                    note = ""
                    if parent and parent not in safe_parents:
                        note = f"Unusual parent process: {parent}"
                    record["analysis_note"] = note
                    record["reason"] = reason
                    detected_records.append(record)
        except Exception:
            pass
    return detected_records

def plot_evtx_results(detected_records):
    # Count occurrences by the detected executable name (using its base name)
    names = [os.path.basename(record.get("NewProcessName", "")).lower() for record in detected_records]
    counts = Counter(names)
    
    plt.figure(figsize=(10, 6))
    plt.bar(counts.keys(), counts.values(), color='#5FD85F')
    plt.xlabel("Detected Executable")
    plt.ylabel("Frequency")
    plt.title("Detected Suspicious Executions from EVTX Log")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

def evtx_analysis():
    sg.theme("DaTopanga")
    layout = [
        [sg.Text("EVTX Log Analysis", size=(35, 1), font=("Arial", 16, "bold"))],
        [sg.FileBrowse('Select EVTX Log', key="-evtxlogfile-", tooltip='Select Security.evtx', font=("Arial", 12))],
        [sg.Button('Analyse Data', expand_x=True, tooltip='Analyze and Plot Data', font=("Arial", 12))],
        [sg.Button('Back', expand_x=True, tooltip='Return to Main Menu', font=("Arial", 12))]
    ]
    window = sg.Window('EVTX Log Analyser', layout, size=(650, 220))
    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, 'Back'):
            break
        if event == 'Analyse Data':
            logs_folder = values["-evtxlogfile-"]
            if not logs_folder:
                sg.popup("Please select an EVTX file.", font=("Arial", 12))
                continue
            detected_records = detect_suspicious_activity_in_evtx(logs_folder)
            if detected_records:
                details = [
                    [record["ts"],
                     record.get("ParentProcessName", "N/A"),
                     record.get("CommandLine", "N/A"),
                     os.path.basename(record.get("NewProcessName", "N/A")),
                     record.get("reason", ""),
                     record.get("analysis_note", "")]
                    for record in detected_records
                ]
                header = "Timestamp | Parent Process | Command Line | Detected Executable | Reason | Analysis Note"
                popup_content = [header] + [f"{d[0]} | {d[1]} | {d[2]} | {d[3]} | {d[4]} | {d[5]}" for d in details]
                sg.PopupScrolled("Detected Suspicious Executions", *popup_content,
                                 title="Suspicious Activity", size=(100, 25))
                plot_evtx_results(detected_records)
            else:
                sg.Popup("No suspicious activity detected in the log.", font=("Arial", 12))
    window.close()

# ---------------------------
# Main Menu
# ---------------------------

def main_menu():
    sg.theme("DaTopanga")
    layout = [
        [sg.Text("Select Analysis Mode", font=("Arial", 16, "bold"))],
        [sg.Button("Live Process Monitoring", font=("Arial", 12, "bold"), size=(30, 1))],
        [sg.Button("EVTX Log Analysis", font=("Arial", 12, "bold"), size=(30, 1))],
        [sg.Button("Quit", font=("Arial", 12, "bold"), size=(30, 1))]
    ]
    window = sg.Window("Enhanced LOLBin Analysis Tool", layout, size=(450, 250))
    while True:
        event, _ = window.read()
        if event in (sg.WIN_CLOSED, "Quit"):
            break
        elif event == "Live Process Monitoring":
            window.hide()
            live_monitor()
            window.un_hide()
        elif event == "EVTX Log Analysis":
            window.hide()
            evtx_analysis()
            window.un_hide()
    window.close()

# ---------------------------
# Main Execution
# ---------------------------

if __name__ == "__main__":
    main_menu()
