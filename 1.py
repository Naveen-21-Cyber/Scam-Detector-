import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import re
import json
import os
from textblob import TextBlob
import threading
from datetime import datetime

# ---------------------- Constants ----------------------
APP_TITLE = "🔍 Scam Message Detector Pro"
APP_VERSION = "1.1.0"
CUSTOM_PATTERN_FILE = "custom_patterns.json"
SCAN_HISTORY_FILE = "scan_history.json"
THEME_CONFIG_FILE = "theme_config.json"

# ---------------------- Data Management ----------------------
default_patterns = [
    {"pattern": r"(free\s+money|win\s+cash|lottery\s+winner)", "description": "Suspicious money-related offer", "severity": "high"},
    {"pattern": r"(click\s+here|urgent\s+action\s+required|limited\s+time\s+offer)", "description": "Urgency or clickbait phrases", "severity": "medium"},
    {"pattern": r"(account\s+locked|verify\s+your\s+identity|security\s+breach)", "description": "Fake account warning", "severity": "medium"},
    {"pattern": r"(bitcoin|crypto|investment\s+opportunity).+(urgent|high\s+return)", "description": "Suspicious investment scheme", "severity": "high"},
    {"pattern": r"(password|credit\s+card|ssn).+(update|confirm|verify)", "description": "Request for sensitive information", "severity": "high"},
    {"pattern": r"(unusual|suspicious)\s+activity", "description": "Fear-based tactics", "severity": "medium"},
    {"pattern": r"([^\s@]+@[^\s@]+\.[^\s@]+).+(password|login)", "description": "Email credential phishing", "severity": "high"},
    {"pattern": r"(\$|USD).+(\d{3,}|\d+,\d+)", "description": "Large money amounts", "severity": "medium"},
    {"pattern": r"(IRS|government|tax\s+authority).+(arrest|lawsuit|penalty)", "description": "Government impersonation threat", "severity": "high"},
    {"pattern": r"(tech\s+support|Microsoft|Apple|Windows).+(error|virus|malware)", "description": "Tech support scam", "severity": "high"},
    {"pattern": r"(CEO|manager|supervisor).+(request|urgent|favor)", "description": "Business email compromise (BEC)", "severity": "high"},
    {"pattern": r"(wire\s+transfer|gift\s+cards|payment\s+in\s+crypto)", "description": "Scam payment methods", "severity": "high"},
    {"pattern": r"(confirm\s+receipt|send\s+details|follow\s+instructions)", "description": "Social engineering manipulation", "severity": "medium"},
    {"pattern": r"(you\s+have\s+been\s+hacked|pay\s+ransom|encrypt\s+your\s+files)", "description": "Ransomware-related message", "severity": "high"},
    {"pattern": r"(Congratulations|you\s+have\s+been\s+selected|eligible\s+winner)", "description": "Prize/lottery scam wording", "severity": "medium"},
    {"pattern": r"(this\s+message\s+is\s+confidential|do\s+not\s+share)", "description": "Fake confidentiality to build trust", "severity": "medium"},
    {"pattern": r"(bank\s+account|routing\s+number).+(update|send|confirm)", "description": "Bank credential phishing", "severity": "high"},
    {"pattern": r"(Amazon|PayPal|Netflix|Spotify).+(verify|update|reactivate)", "description": "Brand impersonation phishing", "severity": "high"},
    {"pattern": r"(tracking\s+number|delivery\s+failed|shipping\s+update)", "description": "Fake package delivery scam", "severity": "medium"},
    {"pattern": r"(video\s+of\s+you|embarrassing\s+footage|private\s+recording)", "description": "Sextortion scam", "severity": "high"},
    {"pattern": r"(voice\s+recording|video\s+message).+(CEO|manager|director)", "description": "Deepfake executive impersonation", "severity": "high"},
    {"pattern": r"(invoice|billing\s+statement|payment\s+overdue).+(PDF|attached|due\s+date)", "description": "Fake invoice scam", "severity": "high"},
    {"pattern": r"(I\s+love\s+you|we\s+will\s+meet\s+soon|send\s+money\s+for\s+visa)", "description": "Romance scam language", "severity": "high"},
    {"pattern": r"(loan\s+approval|low\s+interest\s+rate|debt\s+forgiveness)", "description": "Debt relief or loan scam", "severity": "medium"},
    {"pattern": r"(reset\s+your\s+password|verify\s+login\s+attempt)", "description": "Fake account recovery", "severity": "medium"},
    {"pattern": r"(donate\s+now|help\s+earthquake\s+victims|relief\s+fund)", "description": "Fake charity or disaster relief", "severity": "medium"},
    {"pattern": r"(work\s+from\s+home|easy\s+money|quick\s+interview|HR\s+department)", "description": "Job recruitment scam", "severity": "medium"},
    {"pattern": r"(your\s+subscription\s+is\s+ending|cancel\s+now|auto-renewal)", "description": "Subscription cancellation scam", "severity": "medium"},
    {"pattern": r"(court\s+notice|legal\s+action|warrant\s+issued)", "description": "Legal threat phishing", "severity": "high"},
    {"pattern": r"(binary\s+trading|metatrader|guaranteed\s+returns)", "description": "Fake trading platform pitch", "severity": "high"},
    {"pattern": r"(download\s+this\s+app|install\s+security\s+tool)", "description": "Malicious software link", "severity": "high"},
    {"pattern": r"(shared\s+a\s+file\s+with\s+you|view\s+document\s+online)", "description": "Cloud-based phishing bait", "severity": "high"},
    {"pattern": r"(enter\s+your\s+OTP|verify\s+code\s+sent\s+to\s+your\s+phone)", "description": "MFA interception scam", "severity": "high"},
    {"pattern": r"(send\s+1\s+BTC\s+get\s+2\s+back|limited\s+ETH\s+airdrop)", "description": "Crypto giveaway fraud", "severity": "high"},
    {"pattern": r"(we\s+recorded\s+you|pay\s+to\s+prevent\s+leak|send\s+crypto\s+to\s+this\s+address)", "description": "Extortion scam", "severity": "high"},
    {"pattern": r"(your\s+package\s+contains\s+illegal\s+items|customs\s+intercepted)", "description": "Courier scam", "severity": "high"},
    {"pattern": r"(complete\s+this\s+survey\s+to\s+win|claim\s+your\s+reward)", "description": "Survey-based phishing", "severity": "medium"},
    {"pattern": r"(login\.g00gle\.com|paypa1\.com)", "description": "Spoofed domains for phishing", "severity": "high"},
    {"pattern": r"(flight\s+cancelled|booking\s+issue|urgent\s+travel\s+update)", "description": "Fake airline notification", "severity": "medium"},
    {"pattern": r"(support\s+ticket\s+#[0-9]+|reference\s+number\s+#[0-9]+)", "description": "Fake support ticket reference", "severity": "medium"},
    {"pattern": r"(scan\s+(the\s+)?QR\s+code|open\s+attached\s+PDF|see\s+details\s+in\s+file)", "description": "QR code or document-based scam", "severity": "high"},
    {"pattern": r"(call\s+this\s+number|recorded\s+message|urgent\s+voicemail|press\s+1\s+to\s+connect)", "description": "Voice phishing (vishing) attempt", "severity": "medium"},
    {"pattern": r"(I\s+noticed\s+you\s+recently\s+tried|we\s+analyzed\s+your\s+profile|custom\s+offer\s+just\s+for\s+you)", "description": "AI-personalized scam message", "severity": "medium"},
    {"pattern": r"(cl[i1]ck|r[e3]s[e3]t|ver[i1]fy|🪙|💰|🔐)", "description": "Obfuscated or emoji-enhanced phishing terms", "severity": "medium"},
    {"pattern": r"(join\s+our\s+telegram\s+channel|WhatsApp\s+group\s+invite|message\s+me\s+on\s+Signal)", "description": "Cross-platform social scam invite", "severity": "medium"},
    {"pattern": r"(PAN\s+card\s+blocked|income\s+tax\s+raid|Aadhaar\s+verification\s+required)", "description": "Indian tax or identity scam", "severity": "high"},
    {"pattern": r"(IRS\s+audit|stimulus\s+check\s+issue|SSN\s+suspended)", "description": "US-based government scam", "severity": "high"},
    {"pattern": r"(your\s+password\s+was\s+leaked|you\s+have\s+been\s+hacked\s+|data\s+found\s+on\s+the\s+dark\s+web)", "description": "Dark web exposure threat or spear phishing", "severity": "high"},
    {"pattern": r"(your\s+credentials\s+were\s+found\s+on\s+the\s+dark\s+web)", "description": "Dark web data leak threat", "severity": "high"},
    {"pattern": r"(we\s+found\s+your\s+email\s+in\s+a\s+data\s+breach)", "description": "Phishing using breach scare tactic", "severity": "high"},
    {"pattern": r"(purchase\s+history\s+was\s+leaked\s+on\s+the\s+dark\s+web)", "description": "Fake leak of sensitive personal data", "severity": "high"},
    {"pattern": r"(download\s+your\s+exposed\s+data\s+report\s+here)", "description": "Malicious link pretending to show breach report", "severity": "high"},
    {"pattern": r"(your\s+email\s+has\s+been\s+sold\s+on\s+dark\s+forums)", "description": "Threat of email sale on black markets", "severity": "high"},
    {"pattern": r"(we\s+have\s+access\s+to\s+your\s+camera\s+and\s+files)", "description": "Extortion threat related to dark web hacking", "severity": "high"},
    {"pattern": r"(FBI\s+cyber\s+unit\s+has\s+flagged\s+your\s+account)", "description": "Fake FBI cybercrime warning", "severity": "high"},
    {"pattern": r"(digital\s+arrest\s+warrant\s+has\s+been\s+issued)", "description": "Scam involving digital arrest threat", "severity": "high"},
    {"pattern": r"(you\s+are\s+under\s+investigation\s+for\s+cybercrime)", "description": "Impersonation of cybercrime investigation", "severity": "high"},
    {"pattern": r"(court\s+order\s+issued\s+against\s+your\s+IP\s+address)", "description": "Fake court order about IP misuse", "severity": "high"},
    {"pattern": r"(law\s+enforcement\s+has\s+tracked\s+illegal\s+downloads\s+to\s+your\s+system)", "description": "Torrent/IP fraud accusation scam", "severity": "high"},
    {"pattern": r"(pay\s+now\s+to\s+avoid\s+arrest\s+or\sjail\s+time)", "description": "Extortion scam using law enforcement threats", "severity": "high"}
]


class DataManager:
    def __init__(self):
        self.custom_patterns = self.load_custom_patterns()
        self.scan_history = self.load_scan_history()
        self.theme_config = self.load_theme_config()
        
    def load_custom_patterns(self):
        if os.path.exists(CUSTOM_PATTERN_FILE):
            try:
                with open(CUSTOM_PATTERN_FILE, "r") as f:
                    return json.load(f)
            except json.JSONDecodeError:
                messagebox.showerror("Error", "Custom patterns file is corrupted. Loading defaults.")
                return []
        return []

    def save_custom_patterns(self, patterns):
        with open(CUSTOM_PATTERN_FILE, "w") as f:
            json.dump(patterns, f, indent=2)
        self.custom_patterns = patterns

    def load_scan_history(self):
        if os.path.exists(SCAN_HISTORY_FILE):
            try:
                with open(SCAN_HISTORY_FILE, "r") as f:
                    return json.load(f)
            except:
                return []
        return []
    
    def save_scan_history(self, history):
        with open(SCAN_HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=2)
        self.scan_history = history
    
    def add_to_history(self, text, findings, risk_level):
        history_entry = {
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "text": text[:100] + ("..." if len(text) > 100 else ""),
            "risk_level": risk_level,
            "findings_count": len(findings)
        }
        self.scan_history.insert(0, history_entry)
        # Keep only the latest 100 entries
        if len(self.scan_history) > 100:
            self.scan_history = self.scan_history[:100]
        self.save_scan_history(self.scan_history)
    
    def load_theme_config(self):
        default_theme = {
            "theme_mode": "light",
            "custom_colors": {
                "background": "#f4f4f4",
                "text": "#333333",
                "button": "#4a76a8"
            }
        }
        
        if os.path.exists(THEME_CONFIG_FILE):
            try:
                with open(THEME_CONFIG_FILE, "r") as f:
                    return json.load(f)
            except:
                return default_theme
        return default_theme
    
    def save_theme_config(self, config):
        with open(THEME_CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
        self.theme_config = config

# ---------------------- Analysis Logic ----------------------
class ScamAnalyzer:
    def __init__(self, data_manager):
        self.data_manager = data_manager
    
    def check_grammar_and_spelling(self, text):
        """Check text for grammar and spelling errors"""
        try:
            blob = TextBlob(text)
            return any(w != c for w, c in zip(blob.words, blob.correct().words))
        except:
            # If TextBlob fails, don't count it as a spelling issue
            return False

    def evaluate_risk_level(self, detected):
        """Determine overall risk level based on detected patterns"""
        if not detected:
            return "None", "green"
            
        severities = [p["severity"] for p in detected]
        high_count = severities.count("high")
        medium_count = severities.count("medium")
        
        if high_count >= 2:
            return "Critical", "#FF0000"  # Bright red
        elif high_count == 1:
            return "High", "#FF4500"  # OrangeRed
        elif medium_count >= 2:
            return "Medium", "#FFA500"  # Orange
        elif medium_count == 1:
            return "Low", "#FFD700"  # Gold
        else:
            return "Very Low", "#FF0526"  # Yellow

    def analyze_message(self, text):
        """Analyze message for scam indicators"""
        findings = []
        
        # Check against all patterns (default + custom)
        all_patterns = default_patterns + self.data_manager.custom_patterns
        for p in all_patterns:
            if re.search(p["pattern"], text, re.IGNORECASE):
                findings.append(p)

        # Check for additional indicators
        
        # 1. Grammar and spelling check
        if self.check_grammar_and_spelling(text):
            findings.append({
                "description": "Contains poor grammar or spelling mistakes",
                "severity": "low",
                "pattern": "grammar_check"
            })
        
        # 2. Too many exclamation marks
        if text.count('!') > 3:
            findings.append({
                "description": "Excessive exclamation marks (!)",
                "severity": "low",
                "pattern": "exclamation_check"
            })
            
        # 3. ALL CAPS text sections
        if re.search(r'\b[A-Z]{4,}\b', text):
            findings.append({
                "description": "Contains words in ALL CAPS (shouting)",
                "severity": "low",
                "pattern": "caps_check"
            })
            
        # 4. URL shorteners
        if re.search(r'(bit\.ly|tinyurl\.com|goo\.gl|t\.co)/\w+', text):
            findings.append({
                "description": "Contains URL shorteners (often used to hide suspicious links)",
                "severity": "medium",
                "pattern": "url_shortener_check"
            })
            
        # 5. Check for too many numbers in text (possible scam codes/IDs)
        if len(re.findall(r'\d', text)) > len(text) / 5:  # More than 20% digits
            findings.append({
                "description": "Unusually high number of digits",
                "severity": "low",
                "pattern": "digit_ratio_check"
            })
            
        return findings

    def get_recommendations(self, findings):
        """Generate recommendations based on findings"""
        recommendations = []
        
        if any(p["severity"] == "high" for p in findings):
            recommendations.append("❌ Do not respond to this message")
            recommendations.append("⚠️ Do not click on any links in this message")
            recommendations.append("🔒 Do not provide any personal information")
            
        if any("account" in p["description"].lower() for p in findings):
            recommendations.append("🔐 Contact the company directly through official channels to verify")
            
        if any("money" in p["description"].lower() for p in findings):
            recommendations.append("💰 Remember: If it sounds too good to be true, it probably is")
            
        return recommendations


# ---------------------- UI ----------------------
class ScamDetectorApp:
    def __init__(self, root):
        self.root = root
        self.data_manager = DataManager()
        self.analyzer = ScamAnalyzer(self.data_manager)
        
        self.root.title(APP_TITLE)
        self.root.geometry("900x750")
        
        # Create menu
        self.create_menu()
        
        # Set up theme
        self.apply_theme()
        
        # Set up tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Create main tabs
        self.scanner_tab = ttk.Frame(self.notebook)
        self.pattern_manager_tab = ttk.Frame(self.notebook)
        self.history_tab = ttk.Frame(self.notebook)
        self.settings_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.scanner_tab, text=" 🔍 Scanner ")
        self.notebook.add(self.pattern_manager_tab, text=" ⚙️ Pattern Manager ")
        self.notebook.add(self.history_tab, text=" 📜 History ")
        self.notebook.add(self.settings_tab, text=" 🛠️ Settings ")
        
        # Set up each tab
        self.setup_scanner_tab()
        self.setup_pattern_manager_tab()
        self.setup_history_tab()
        self.setup_settings_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set(f"Version {APP_VERSION} | {len(default_patterns)} default patterns | {len(self.data_manager.custom_patterns)} custom patterns")
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def create_menu(self):
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Import Patterns", command=self.import_patterns)
        file_menu.add_command(label="Export Patterns", command=self.export_patterns)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Usage Guide", command=self.show_help)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def apply_theme(self):
        # Apply theme based on settings
        theme_mode = self.data_manager.theme_config["theme_mode"]
        colors = self.data_manager.theme_config["custom_colors"]
        
        if theme_mode == "dark":
            bg_color = "#333333"
            fg_color = "#FFFFFF"
            button_color = "#4a76a8"
        else:
            bg_color = colors["background"]
            fg_color = colors["text"]
            button_color = colors["button"]
        
        style = ttk.Style()
        style.theme_use("clam")  # Use a theme that supports customization
        
        # Configure common elements
        style.configure("TFrame", background=bg_color)
        style.configure("TLabel", background=bg_color, foreground=fg_color)
        style.configure("TButton", background=button_color, foreground=fg_color)
        style.configure("TCheckbutton", background=bg_color, foreground=fg_color)
        style.configure("TRadiobutton", background=bg_color, foreground=fg_color)
        style.configure("TEntry", fieldbackground=bg_color, foreground=fg_color)
        style.configure("TCombobox", fieldbackground=bg_color, foreground=fg_color)
        style.configure("TNotebook", background=bg_color, foreground=fg_color)
        style.configure("TNotebook.Tab", background=bg_color, foreground=fg_color)
        
        # Configure the text widgets
        text_bg = "#2B2B2B" if theme_mode == "dark" else "#FFFFFF"
        text_fg = "#FFFFFF" if theme_mode == "dark" else "#000000"
        
        self.root.configure(bg=bg_color)
        
        # Store these for use in creating widgets
        self.text_bg = text_bg
        self.text_fg = text_fg
    
    def setup_scanner_tab(self):
        frame = self.scanner_tab
        
        # Input section
        input_frame = ttk.LabelFrame(frame, text="Message to Analyze")
        input_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        ttk.Label(input_frame, text="Paste the suspicious message below:").pack(anchor="w", padx=5, pady=(5, 0))
        
        self.message_input = scrolledtext.ScrolledText(
            input_frame, 
            height=8, 
            wrap=tk.WORD, 
            font=("Segoe UI", 11),
            bg=self.text_bg,
            fg=self.text_fg
        )
        self.message_input.pack(fill="both", expand=True, padx=5, pady=5)
        self.message_input.bind("<KeyRelease>", lambda e: self.live_preview())
        
        button_frame = ttk.Frame(input_frame)
        button_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Button(button_frame, text="Clear", command=self.clear_input).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Sample Scam", command=self.load_sample).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🔍 Analyze Message", command=self.analyze).pack(side=tk.RIGHT, padx=5)
        
        # Result section
        result_frame = ttk.LabelFrame(frame, text="Analysis Results")
        result_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Risk level indicator
        risk_frame = ttk.Frame(result_frame)
        risk_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(risk_frame, text="Risk Level:", font=("Segoe UI", 12, "bold")).pack(side=tk.LEFT, padx=5)
        self.risk_label = ttk.Label(risk_frame, text="None", font=("Segoe UI", 12, "bold"), foreground="green")
        self.risk_label.pack(side=tk.LEFT, padx=5)
        
        # Results notebook
        results_notebook = ttk.Notebook(result_frame)
        results_notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Findings tab
        findings_frame = ttk.Frame(results_notebook)
        results_notebook.add(findings_frame, text="Findings")
        
        self.result_text = tk.Text(
            findings_frame, 
            height=10, 
            wrap=tk.WORD, 
            font=("Segoe UI", 11),
            bg=self.text_bg,
            fg=self.text_fg
        )
        self.result_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.result_text.config(state="disabled")
        
        # Recommendations tab
        rec_frame = ttk.Frame(results_notebook)
        results_notebook.add(rec_frame, text="Recommendations")
        
        self.rec_text = tk.Text(
            rec_frame, 
            height=10, 
            wrap=tk.WORD, 
            font=("Segoe UI", 11),
            bg=self.text_bg,
            fg=self.text_fg
        )
        self.rec_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.rec_text.config(state="disabled")
    
    def setup_pattern_manager_tab(self):
        frame = self.pattern_manager_tab
        
        # Add pattern section
        add_frame = ttk.LabelFrame(frame, text="Add New Pattern")
        add_frame.pack(fill="x", padx=10, pady=5)
        
        # Create a grid for the form
        ttk.Label(add_frame, text="Pattern (Regex):").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        ttk.Label(add_frame, text="Description:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        ttk.Label(add_frame, text="Severity:").grid(row=2, column=0, sticky="e", padx=5, pady=5)
        
        self.pattern_entry = ttk.Entry(add_frame, width=60)
        self.pattern_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        self.desc_entry = ttk.Entry(add_frame, width=60)
        self.desc_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        
        self.severity_var = tk.StringVar()
        self.severity_combo = ttk.Combobox(
            add_frame, 
            textvariable=self.severity_var, 
            values=["low", "medium", "high"], 
            state="readonly", 
            width=20
        )
        self.severity_combo.set("medium")
        self.severity_combo.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        
        ttk.Button(add_frame, text="Add Pattern", command=self.add_pattern).grid(
            row=3, column=1, sticky="e", padx=5, pady=5
        )
        
        # List patterns section
        patterns_frame = ttk.LabelFrame(frame, text="Custom Patterns")
        patterns_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Add a label about the patterns
        ttk.Label(patterns_frame, text="Your custom patterns:").pack(anchor="w", padx=5, pady=(5,0))
        
        # Create a treeview for the patterns
        columns = ("description", "pattern", "severity")
        self.patterns_tree = ttk.Treeview(patterns_frame, columns=columns, show="headings")
        
        # Define headings
        self.patterns_tree.heading("description", text="Description")
        self.patterns_tree.heading("pattern", text="Pattern")
        self.patterns_tree.heading("severity", text="Severity")
        
        # Define columns
        self.patterns_tree.column("description", width=250)
        self.patterns_tree.column("pattern", width=350)
        self.patterns_tree.column("severity", width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(patterns_frame, orient=tk.VERTICAL, command=self.patterns_tree.yview)
        self.patterns_tree.configure(yscroll=scrollbar.set)
        
        # Pack the treeview and scrollbar
        self.patterns_tree.pack(side=tk.LEFT, fill="both", expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill="y", pady=5)
        
        # Buttons for pattern management
        button_frame = ttk.Frame(patterns_frame)
        button_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Button(button_frame, text="Remove Selected", command=self.remove_selected).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Edit Selected", command=self.edit_selected).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Test Pattern", command=self.test_pattern).pack(side=tk.RIGHT, padx=5)
        
        # Populate the treeview
        self.update_patterns_tree()
        
    def setup_history_tab(self):
        frame = self.history_tab
        
        # Create a treeview for the scan history
        columns = ("date", "text", "risk_level", "findings")
        self.history_tree = ttk.Treeview(frame, columns=columns, show="headings")
        
        # Define headings
        self.history_tree.heading("date", text="Date & Time")
        self.history_tree.heading("text", text="Message Excerpt")
        self.history_tree.heading("risk_level", text="Risk Level")
        self.history_tree.heading("findings", text="Findings")
        
        # Define columns
        self.history_tree.column("date", width=150)
        self.history_tree.column("text", width=350)
        self.history_tree.column("risk_level", width=100)
        self.history_tree.column("findings", width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.history_tree.yview)
        self.history_tree.configure(yscroll=scrollbar.set)
        
        # Pack the treeview and scrollbar
        self.history_tree.pack(side=tk.LEFT, fill="both", expand=True, padx=10, pady=10)
        scrollbar.pack(side=tk.RIGHT, fill="y", pady=10)
        
        # Buttons for history management
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(button_frame, text="Clear History", command=self.clear_history).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Export History", command=self.export_history).pack(side=tk.RIGHT, padx=5)
        
        # Populate the treeview
        self.update_history_tree()
    
    def setup_settings_tab(self):
        frame = self.settings_tab
        
        # Theme settings
        theme_frame = ttk.LabelFrame(frame, text="Theme Settings")
        theme_frame.pack(fill="x", padx=10, pady=5)
        
        self.theme_var = tk.StringVar(value=self.data_manager.theme_config["theme_mode"])
        ttk.Radiobutton(theme_frame, text="Light Mode", variable=self.theme_var, value="light", command=self.update_theme).pack(anchor="w", padx=20, pady=5)
        ttk.Radiobutton(theme_frame, text="Dark Mode", variable=self.theme_var, value="dark", command=self.update_theme).pack(anchor="w", padx=20, pady=5)
        
        # Advanced settings
        adv_frame = ttk.LabelFrame(frame, text="Advanced Settings")
        adv_frame.pack(fill="x", padx=10, pady=5)
        
        self.auto_analyze_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(adv_frame, text="Live analysis while typing", variable=self.auto_analyze_var).pack(anchor="w", padx=20, pady=5)
        
        # About section
        about_frame = ttk.LabelFrame(frame, text="About")
        about_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        about_text = f"""
        {APP_TITLE} v{APP_VERSION}
        
        A tool to help identify potential scams in messages.
        
        Features:
        • Analyzes text for common scam patterns
        • Custom pattern management
        • Scan history tracking
        • Theme customization
        
        Default patterns: {len(default_patterns)}
        Custom patterns: {len(self.data_manager.custom_patterns)}
        """
        
        about_label = ttk.Label(about_frame, text=about_text, justify=tk.LEFT)
        about_label.pack(padx=20, pady=20)
    
    # ---------------------- Functionality ----------------------
    def analyze(self):
        text = self.message_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Empty Input", "Please enter a message to analyze.")
            return
        
        # Use a thread for potentially slow operations
        threading.Thread(target=self._analyze_thread, args=(text,), daemon=True).start()
        self.status_var.set("Analyzing message...")
    
    def _analyze_thread(self, text):
        findings = self.analyzer.analyze_message(text)
        risk_level, color = self.analyzer.evaluate_risk_level(findings)
        recommendations = self.analyzer.get_recommendations(findings)
        
        # Add to history
        self.data_manager.add_to_history(text, findings, risk_level)
        
        # Update UI in the main thread
        self.root.after(0, lambda: self._update_results(findings, risk_level, color, recommendations))
        self.root.after(0, self.update_history_tree)
    
    def _update_results(self, findings, risk_level, color, recommendations):
        # Update risk level indicator
        self.risk_label.config(text=risk_level, foreground=color)
        
        # Update findings text
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        
        if not findings:
            self.result_text.insert(tk.END, "✅ No scam indicators detected. The message appears to be safe.\n\n")
            self.result_text.insert(tk.END, "However, always remain cautious with unexpected messages.")
        else:
            self.result_text.insert(tk.END, f"⚠️ {len(findings)} potential scam indicators found:\n\n")
            
            # Group findings by severity
            high = [p for p in findings if p["severity"] == "high"]
            medium = [p for p in findings if p["severity"] == "medium"]
            low = [p for p in findings if p["severity"] == "low"]
            
            if high:
                self.result_text.insert(tk.END, "High Severity:\n")
                for p in high:
                    self.result_text.insert(tk.END, f"• {p['description']}\n")
                self.result_text.insert(tk.END, "\n")
                
            if medium:
                self.result_text.insert(tk.END, "Medium Severity:\n")
                for p in medium:
                    self.result_text.insert(tk.END, f"• {p['description']}\n")
                self.result_text.insert(tk.END, "\n")
                
            if low:
                self.result_text.insert(tk.END, "Low Severity:\n")
                for p in low:
                    self.result_text.insert(tk.END, f"• {p['description']}\n")
        
        self.result_text.config(state="disabled")
        
        # Update recommendations text
        self.rec_text.config(state="normal")
        self.rec_text.delete("1.0", tk.END)
        
        if not recommendations:
            self.rec_text.insert(tk.END, "No specific recommendations for this message.\n\n")
            self.rec_text.insert(tk.END, "General advice:\n")
            self.rec_text.insert(tk.END, "• Be cautious with unexpected messages\n")
            self.rec_text.insert(tk.END, "• Don't click links unless you're certain of their source\n")
            self.rec_text.insert(tk.END, "• Never share sensitive information via email or messages")
        else:
            self.rec_text.insert(tk.END, "Based on the analysis, we recommend:\n\n")
            for rec in recommendations:
                self.rec_text.insert(tk.END, f"{rec}\n")
        
        self.rec_text.config(state="disabled")
        
        # Update status bar
        self.status_var.set(f"Analysis complete: {risk_level} risk level detected")
    
    def live_preview(self):
        """Provide live risk assessment while typing"""
        if not self.auto_analyze_var.get():
            return
            
        text = self.message_input.get("1.0", tk.END).strip()
        if not text:
            self.risk_label.config(text="None", foreground="green")
            return
        
        # Simple previews for responsiveness, without full analysis
        findings = self.analyzer.analyze_message(text)
        risk_level, color = self.analyzer.evaluate_risk_level(findings)
        self.risk_label.config(text=f"{risk_level}", foreground=color)
    
    def update_patterns_tree(self):
        """Update the patterns treeview"""
        # Clear the tree
        for item in self.patterns_tree.get_children():
            self.patterns_tree.delete(item)
        
        # Populate with custom patterns
        for i, p in enumerate(self.data_manager.custom_patterns):
            values = (p["description"], p["pattern"], p["severity"])
            self.patterns_tree.insert("", tk.END, iid=str(i), values=values)
    
    def update_history_tree(self):
        """Update the history treeview"""
        # Clear the tree
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        # Populate with history entries
        for i, entry in enumerate(self.data_manager.scan_history):
            values = (
                entry["date"],
                entry["text"],
                entry["risk_level"],
                f"{entry['findings_count']} findings"
            )
            self.history_tree.insert("", tk.END, iid=str(i), values=values)
    
    def add_pattern(self):
        """Add a new custom pattern"""
        pattern = self.pattern_entry.get().strip()
        desc = self.desc_entry.get().strip()
        severity = self.severity_var.get()
        
        if not pattern or not desc:
            messagebox.showerror("Input Error", "Please fill in all pattern fields.")
            return
        
        # Validate the regex pattern
        try:
            re.compile(pattern)
        except re.error as e:
            messagebox.showerror("Invalid Regex", f"The pattern is not valid regex: {str(e)}")
            return
        
        # Add the pattern
        custom_patterns = self.data_manager.custom_patterns
        custom_patterns.append({
            "pattern": pattern,
            "description": desc,
            "severity": severity
        })
        
        self.data_manager.save_custom_patterns(custom_patterns)
        self.update_patterns_tree()
        
        # Clear the form
        self.pattern_entry.delete(0, tk.END)
        self.desc_entry.delete(0, tk.END)
        self.severity_combo.set("medium")
        
        self.status_var.set(f"Pattern added: {desc}")
    
    def remove_selected(self):
        """Remove the selected pattern"""
        selection = self.patterns_tree.selection()
        if not selection:
            messagebox.showinfo("No Selection", "Please select a pattern to remove.")
            return
        
        # Confirm deletion
        if not messagebox.askyesno("Confirm Deletion", "Are you sure you want to delete the selected pattern?"):
            return
        
        # Get the index from the tree and remove from data
        index = int(selection[0])
        custom_patterns = self.data_manager.custom_patterns
        del custom_patterns[index]
        
        self.data_manager.save_custom_patterns(custom_patterns)
        self.update_patterns_tree()
        
        self.status_var.set("Pattern removed")
    
    def edit_selected(self):
        """Edit the selected pattern"""
        selection = self.patterns_tree.selection()
        if not selection:
            messagebox.showinfo("No Selection", "Please select a pattern to edit.")
            return
        
        # Get the pattern data
        index = int(selection[0])
        pattern = self.data_manager.custom_patterns[index]
        
        # Open an edit dialog
        edit_window = tk.Toplevel(self.root)
        edit_window.title("Edit Pattern")
        edit_window.geometry("600x250")
        edit_window.transient(self.root)
        edit_window.grab_set()
        
        # Create the form
        ttk.Label(edit_window, text="Pattern (Regex):").grid(row=0, column=0, sticky="e", padx=10, pady=10)
        ttk.Label(edit_window, text="Description:").grid(row=1, column=0, sticky="e", padx=10, pady=10)
        ttk.Label(edit_window, text="Severity:").grid(row=2, column=0, sticky="e", padx=10, pady=10)
        
        edit_pattern = ttk.Entry(edit_window, width=50)
        edit_pattern.grid(row=0, column=1, padx=10, pady=10)
        edit_pattern.insert(0, pattern["pattern"])
        
        edit_desc = ttk.Entry(edit_window, width=50)
        edit_desc.grid(row=1, column=1, padx=10, pady=10)
        edit_desc.insert(0, pattern["description"])
        
        edit_severity = tk.StringVar(value=pattern["severity"])
        edit_severity_combo = ttk.Combobox(
            edit_window, 
            textvariable=edit_severity, 
            values=["low", "medium", "high"], 
            state="readonly", 
            width=20
        )
        edit_severity_combo.grid(row=2, column=1, padx=10, pady=10, sticky="w")
        
        # Save button
        def save_edit():
            try:
                re.compile(edit_pattern.get().strip())
                
                # Update the pattern
                custom_patterns = self.data_manager.custom_patterns
                custom_patterns[index] = {
                    "pattern": edit_pattern.get().strip(),
                    "description": edit_desc.get().strip(),
                    "severity": edit_severity.get()
                }
                
                self.data_manager.save_custom_patterns(custom_patterns)
                self.update_patterns_tree()
                
                self.status_var.set("Pattern updated")
                edit_window.destroy()
                
            except re.error as e:
                messagebox.showerror("Invalid Regex", f"The pattern is not valid regex: {str(e)}")
        
        ttk.Button(edit_window, text="Save", command=save_edit).grid(row=3, column=1, sticky="e", padx=10, pady=10)
    
    def test_pattern(self):
        """Test the selected pattern against a sample text"""
        selection = self.patterns_tree.selection()
        if not selection:
            messagebox.showinfo("No Selection", "Please select a pattern to test.")
            return
        
        # Get the pattern data
        index = int(selection[0])
        pattern = self.data_manager.custom_patterns[index]
        
        # Open a test dialog
        test_window = tk.Toplevel(self.root)
        test_window.title("Test Pattern")
        test_window.geometry("600x300")
        test_window.transient(self.root)
        test_window.grab_set()
        
        # Create the form
        ttk.Label(test_window, text=f"Testing pattern: {pattern['pattern']}").pack(anchor="w", padx=10, pady=(10, 0))
        ttk.Label(test_window, text="Enter text to test against:").pack(anchor="w", padx=10, pady=(10, 0))
        
        test_text = scrolledtext.ScrolledText(test_window, height=6, wrap=tk.WORD)
        test_text.pack(fill="x", padx=10, pady=5)
        
        result_var = tk.StringVar(value="Results will appear here.")
        result_label = ttk.Label(test_window, textvariable=result_var, font=("Segoe UI", 10))
        result_label.pack(anchor="w", padx=10, pady=10)
        
        # Test button
        def run_test():
            text = test_text.get("1.0", tk.END).strip()
            if not text:
                result_var.set("Please enter some text to test.")
                return
            
            try:
                matches = re.findall(pattern["pattern"], text, re.IGNORECASE)
                if matches:
                    result_var.set(f"✅ Pattern matched {len(matches)} times: {', '.join(matches)}")
                    result_label.config(foreground="green")
                else:
                    result_var.set("❌ No matches found.")
                    result_label.config(foreground="red")
            except re.error as e:
                result_var.set(f"Error in pattern: {str(e)}")
                result_label.config(foreground="red")
        
        ttk.Button(test_window, text="Test Pattern", command=run_test).pack(side=tk.RIGHT, padx=10, pady=10)
    
    def clear_input(self):
        """Clear the message input"""
        self.message_input.delete("1.0", tk.END)
        self.risk_label.config(text="None", foreground="green")
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state="disabled")
        self.rec_text.config(state="normal")
        self.rec_text.delete("1.0", tk.END)
        self.rec_text.config(state="disabled")
    
    def load_sample(self):
        """Load a sample scam message"""
        samples = [
            """URGENT: Your account has been compromised! Click here to verify your identity: http://bit.ly/2xScam
            You must ACT NOW or your account will be LOCKED permanently. We need your SSN and credit card details to verify.""",
            
            """Congratulations! You've won $5,000,000 in the INTERNATIONAL LOTTERY! 
            To claim your prize, send $500 for processing fees to Mr. Smith at account #12345678. URGENT: Respond within 24 HOURS!""",
            
            """Dear customer, we detected unusual activity on your account. Please update your password and credit card information by clicking: 
            https://tinyurl.com/bank-verify Your account will be suspended if you don't verify within 24 hours."""
        ]
        
        # Choose a random sample
        import random
        sample = random.choice(samples)
        
        # Load it into the input field
        self.message_input.delete("1.0", tk.END)
        self.message_input.insert("1.0", sample)
        
        # Trigger the live preview
        self.live_preview()
    
    def clear_history(self):
        """Clear the scan history"""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all scan history?"):
            self.data_manager.save_scan_history([])
            self.update_history_tree()
            self.status_var.set("Scan history cleared")
    
    def export_history(self):
        """Export the scan history to a CSV file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export History"
        )
        
        if not filename:
            return
        
        try:
            with open(filename, "w", newline="") as f:
                import csv
                writer = csv.writer(f)
                writer.writerow(["Date", "Message Excerpt", "Risk Level", "Findings Count"])
                
                for entry in self.data_manager.scan_history:
                    writer.writerow([
                        entry["date"],
                        entry["text"],
                        entry["risk_level"],
                        entry["findings_count"]
                    ])
            
            self.status_var.set(f"History exported to {filename}")
            messagebox.showinfo("Export Complete", f"History successfully exported to {filename}")
        
        except Exception as e:
            messagebox.showerror("Export Error", f"Could not export history: {str(e)}")
    
    def import_patterns(self):
        """Import custom patterns from a JSON file"""
        filename = filedialog.askopenfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Import Patterns"
        )
        
        if not filename:
            return
        
        try:
            with open(filename, "r") as f:
                imported_patterns = json.load(f)
            
            # Validate the patterns
            if not isinstance(imported_patterns, list):
                raise ValueError("File does not contain a valid pattern list")
            
            for p in imported_patterns:
                if not all(key in p for key in ["pattern", "description", "severity"]):
                    raise ValueError("One or more patterns are missing required fields")
                
                if p["severity"] not in ["low", "medium", "high"]:
                    raise ValueError(f"Invalid severity level: {p['severity']}")
                
                # Test if the pattern is valid regex
                re.compile(p["pattern"])
            
            # Ask to replace or merge
            if self.data_manager.custom_patterns:
                choice = messagebox.askyesnocancel(
                    "Import Options", 
                    "Do you want to merge with existing patterns?\n"
                    "Yes = Merge, No = Replace, Cancel = Abort"
                )
                
                if choice is None:  # Cancel
                    return
                
                if choice:  # Yes - merge
                    merged = self.data_manager.custom_patterns + imported_patterns
                    self.data_manager.save_custom_patterns(merged)
                else:  # No - replace
                    self.data_manager.save_custom_patterns(imported_patterns)
            else:
                # No existing patterns, just save
                self.data_manager.save_custom_patterns(imported_patterns)
            
            self.update_patterns_tree()
            count = len(imported_patterns)
            self.status_var.set(f"Imported {count} patterns successfully")
            messagebox.showinfo("Import Complete", f"Successfully imported {count} patterns")
        
        except Exception as e:
            messagebox.showerror("Import Error", f"Could not import patterns: {str(e)}")
    
    def export_patterns(self):
        """Export custom patterns to a JSON file"""
        if not self.data_manager.custom_patterns:
            messagebox.showinfo("No Patterns", "There are no custom patterns to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Export Patterns"
        )
        
        if not filename:
            return
        
        try:
            with open(filename, "w") as f:
                json.dump(self.data_manager.custom_patterns, f, indent=2)
            
            self.status_var.set(f"Patterns exported to {filename}")
            messagebox.showinfo("Export Complete", f"Successfully exported {len(self.data_manager.custom_patterns)} patterns")
        
        except Exception as e:
            messagebox.showerror("Export Error", f"Could not export patterns: {str(e)}")
    
    def update_theme(self):
        """Update the theme based on user selection"""
        theme_mode = self.theme_var.get()
        
        # Update the config
        config = self.data_manager.theme_config
        config["theme_mode"] = theme_mode
        self.data_manager.save_theme_config(config)
        
        # Apply the theme
        self.apply_theme()
        
        # Show a message
        messagebox.showinfo(
            "Theme Changed", 
            f"Theme changed to {theme_mode.title()} mode.\n"
            "Some changes will take effect after restarting the application."
        )
    
    def show_help(self):
        """Show the usage guide"""
        help_window = tk.Toplevel(self.root)
        help_window.title("Usage Guide")
        help_window.geometry("700x500")
        help_window.transient(self.root)
        
        help_text = scrolledtext.ScrolledText(
            help_window, 
            wrap=tk.WORD,
            font=("Segoe UI", 11),
            bg=self.text_bg,
            fg=self.text_fg
        )
        help_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        guide = """
        # Scam Message Detector - Usage Guide
        
        ## Scanner Tab
        
        1. Paste the suspicious message in the input field.
        2. Click "Analyze Message" or wait for live analysis.
        3. Review the risk level and findings.
        4. Check the recommendations for what to do next.
        
        ## Pattern Manager Tab
        
        1. View existing custom patterns in the list.
        2. Add new patterns with:
           - Regex pattern (e.g., "suspicious\\s+word")
           - Description of what it detects
           - Severity level (low/medium/high)
        3. Edit or remove existing patterns.
        4. Test patterns against sample text.
        
        ## History Tab
        
        - View a history of your previous scans.
        - Export history to CSV for record keeping.
        - Clear history if needed.
        
        ## Settings Tab
        
        - Change between light and dark themes.
        - Toggle live analysis.
        - View information about the application.
        
        ## Tips for Creating Patterns
        
        - Use `\\s+` for spaces to match different spacing.
        - Use `|` for OR conditions (e.g., "word1|word2").
        - Use `.+` to match any text between words.
        - Use `\\b` for word boundaries.
        - Test your patterns before adding them.
        
        Remember: This tool is meant to assist you in identifying potential scams, but it's not perfect. Always use your judgment.
        """
        
        help_text.insert("1.0", guide)
        help_text.config(state="disabled")
    
    def show_about(self):
        """Show about dialog"""
        messagebox.showinfo(
            "About", 
            f"{APP_TITLE} v{APP_VERSION}\n\n"
            "A tool to help identify potential scams in messages.\n\n"
            "Features:\n"
            "• Advanced pattern matching\n"
            "• Custom pattern management\n"
            "• Scan history tracking\n"
            "• Detailed recommendations\n\n"
            "Created for educational purposes."
        )

# ---------------------- Run App ----------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = ScamDetectorApp(root)
    root.mainloop()