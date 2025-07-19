import customtkinter as ctk
import ipaddress
import tkinter
from tkinter import messagebox

# Set appearance and color theme
ctk.set_appearance_mode("System")  # Modes: "System" (default), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (default), "green", "dark-blue"

class SubnetCalculator(ctk.CTk):
    def show_tooltip(self, text):
        self.tooltip_label.configure(text=text)
        self.tooltip_label.place(relx=0.5, rely=0.01, anchor="n")
        self.tooltip_label.lift()  # Bring tooltip to front

    def hide_tooltip(self):
        self.tooltip_label.place_forget()
    def sanitize_subnet_prefix(self, prefix_str):
        # Remove spaces, tabs, and non-digit characters
        prefix_str = prefix_str.strip().replace(' ', '').replace('\t', '')
        import re
        prefix_str = re.sub(r'[^0-9]', '', prefix_str)
        return prefix_str

    def sanitize_lookup_ip(self, ip_str):
        # Use same logic as sanitize_ip
        return self.sanitize_ip(ip_str)
    def sanitize_ip(self, ip_str):
        # Remove spaces, tabs, and any non-IP characters except . : and hex
        ip_str = ip_str.strip().replace(' ', '').replace('\t', '')
        # Only allow digits, a-f, A-F, ., :, and ::
        import re
        ip_str = re.sub(r'[^0-9a-fA-F\.:]', '', ip_str)
        return ip_str

    def sanitize_mask(self, mask_str):
        # Remove spaces, tabs, and any non-mask characters except . and digits
        mask_str = mask_str.strip().replace(' ', '').replace('\t', '')
        import re
        mask_str = re.sub(r'[^0-9\.]', '', mask_str) if not mask_str.isdigit() else mask_str
        return mask_str
    def __init__(self):
        super().__init__()
        self.title("Subnet Calculator")
        self.geometry("1000x900")
        self.resizable(True, True)
        self.tooltip_label = ctk.CTkLabel(self, text="", fg_color="yellow", text_color="black", font=("Arial", 12, "bold"), corner_radius=8, padx=10, pady=5)
        self.tooltip_label.place_forget()

        # Remove theme colors, revert to static colors

        # Keyboard shortcuts
        self.bind('<Control-c>', lambda e: self.copy_to_clipboard("Network:"))
        self.bind('<Control-e>', lambda e: self.export_results())
        self.bind('<Control-r>', lambda e: self.calculate())

        # Top menu bar
        self.menu_bar = tkinter.Menu(self)
        self.config(menu=self.menu_bar)
        file_menu = tkinter.Menu(self.menu_bar, tearoff=0)
        file_menu.add_command(label="Export Results", command=self.export_results)
        file_menu.add_command(label="Export as CSV", command=self.export_csv)
        file_menu.add_command(label="Export as JSON", command=self.export_json)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)
        self.menu_bar.add_cascade(label="File", menu=file_menu)

        edit_menu = tkinter.Menu(self.menu_bar, tearoff=0)
        edit_menu.add_command(label="Copy Network", command=lambda: self.copy_to_clipboard("Network:"))
        edit_menu.add_command(label="Copy Netmask", command=lambda: self.copy_to_clipboard("Netmask:"))
        edit_menu.add_command(label="Clear All Fields", command=self.clear_all_fields)
        edit_menu.add_command(label="Reset History", command=self.reset_history)
        self.menu_bar.add_cascade(label="Edit", menu=edit_menu)

        view_menu = tkinter.Menu(self.menu_bar, tearoff=0)
        view_menu.add_command(label="Light Theme", command=lambda: self.set_theme("Light"))
        view_menu.add_command(label="Dark Theme", command=lambda: self.set_theme("Dark"))
        view_menu.add_command(label="System Theme", command=lambda: self.set_theme("System"))
        self.menu_bar.add_cascade(label="View", menu=view_menu)

        tools_menu = tkinter.Menu(self.menu_bar, tearoff=0)
        tools_menu.add_command(label="Validate IP", command=self.validate_ip)
        tools_menu.add_command(label="Validate Mask", command=self.validate_mask)
        tools_menu.add_command(label="Show Subnets", command=self.show_subnets)
        self.menu_bar.add_cascade(label="Tools", menu=tools_menu)

        help_menu = tkinter.Menu(self.menu_bar, tearoff=0)
        help_menu.add_command(label="Help", command=self.show_help)
        help_menu.add_command(label="How to Use", command=self.show_how_to_use)
        help_menu.add_command(label="About", command=self.show_about)
        self.menu_bar.add_cascade(label="Help", menu=help_menu)

        # Main horizontal layout (single instance)
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(padx=40, pady=20, fill="both", expand=True)
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=3)
        self.main_frame.grid_columnconfigure(1, weight=2)

        # Left panel: input, actions, output
        self.left_frame = ctk.CTkFrame(self.main_frame, corner_radius=12, border_width=2, border_color="#444444")
        self.left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 20), pady=0)
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=3)
        self.left_frame.grid_rowconfigure(0, weight=0)
        self.left_frame.grid_rowconfigure(1, weight=0)
        self.left_frame.grid_rowconfigure(2, weight=0)
        self.left_frame.grid_rowconfigure(3, weight=1)
        self.left_frame.grid_rowconfigure(4, weight=0)
        self.left_frame.grid_columnconfigure(0, weight=1)
        self.left_frame.grid_columnconfigure(1, weight=1)

        # Input section (left, row 0, col 0)
        input_section = ctk.CTkFrame(self.left_frame, corner_radius=8, border_width=1, border_color="#333333")
        input_section.grid(row=0, column=0, sticky="nsew", padx=10, pady=(10,5))
        input_header = ctk.CTkLabel(input_section, text="Network Input", font=("Segoe UI", 16, "bold"), text_color="#00aaff")
        input_header.grid(row=0, column=0, sticky="w", pady=(0,8))
        ip_label = ctk.CTkLabel(input_section, text="IP Address or CIDR Notation:", font=("Segoe UI", 12, "bold"))
        ip_label.grid(row=1, column=0, sticky="w", pady=(0,5))
        self.ip_entry = ctk.CTkEntry(input_section, placeholder_text="192.168.1.0 or 192.168.1.0/24 or 2001:db8::")
        self.ip_entry.grid(row=2, column=0, sticky="ew")
        self.ip_entry.bind("<Enter>", lambda e: self.show_tooltip("Enter a valid IPv4/IPv6 address or CIDR (e.g. 192.168.1.0/24)."))
        self.ip_entry.bind("<Leave>", lambda e: self.hide_tooltip())
        self.ip_error = ctk.CTkLabel(input_section, text="", text_color="red")
        self.ip_error.grid(row=3, column=0, sticky="w")

        mask_label = ctk.CTkLabel(input_section, text="Prefix Length or Netmask (e.g. 24 or 255.255.255.0):", font=("Segoe UI", 12, "bold"))
        mask_label.grid(row=4, column=0, sticky="w", pady=(10,5))
        self.mask_entry = ctk.CTkEntry(input_section, placeholder_text="24 or 255.255.255.0")
        self.mask_entry.grid(row=5, column=0, sticky="ew")
        self.mask_entry.bind("<Enter>", lambda e: self.show_tooltip("Enter a prefix length (e.g. 24 for IPv4, 64 for IPv6) or a netmask (IPv4 only)."))
        self.mask_entry.bind("<Leave>", lambda e: self.hide_tooltip())
        self.mask_error = ctk.CTkLabel(input_section, text="", text_color="red")
        self.mask_error.grid(row=6, column=0, sticky="w")

        ipver_label = ctk.CTkLabel(input_section, text="IP Version:", font=("Segoe UI", 12, "bold"))
        ipver_label.grid(row=7, column=0, sticky="w", pady=(10,5))
        self.ipver_option = ctk.CTkOptionMenu(input_section, values=["IPv4", "IPv6"])
        self.ipver_option.set("IPv4")
        self.ipver_option.grid(row=8, column=0, sticky="ew")
        self.ipver_option.bind("<Enter>", lambda e: self.show_tooltip("Choose IPv4 or IPv6."))
        self.ipver_option.bind("<Leave>", lambda e: self.hide_tooltip())
        input_section.grid_columnconfigure(0, weight=1)
        help_btn = ctk.CTkButton(input_section, text="?", width=30, command=self.show_help)
        help_btn.grid(row=9, column=0, sticky="e", pady=(10,0))

        # Validation feedback as user types
        self.ip_entry.bind('<KeyRelease>', self.validate_ip)
        self.mask_entry.bind('<KeyRelease>', self.validate_mask)

        # Subnetting section (right of input, row 0, col 1)
        subnet_section = ctk.CTkFrame(self.left_frame, corner_radius=8, border_width=1, border_color="#333333")
        subnet_section.grid(row=0, column=1, sticky="nsew", padx=(0,10), pady=(10,5))
        subnet_header = ctk.CTkLabel(subnet_section, text="Subnetting", font=("Segoe UI", 15, "bold"), text_color="#00aaff")
        subnet_header.grid(row=0, column=0, sticky="w", pady=(5,2))
        subnet_label = ctk.CTkLabel(subnet_section, text="Subnet Prefix Length:", font=("Segoe UI", 12, "bold"))
        subnet_label.grid(row=1, column=0, sticky="w", pady=(0,5))
        self.subnet_entry = ctk.CTkEntry(subnet_section, placeholder_text="e.g. 26 or 64")
        self.subnet_entry.grid(row=2, column=0, sticky="ew")
        self.subnet_entry.bind("<Enter>", lambda e: self.show_tooltip("Enter subnet prefix length. Must be greater than main network's prefix."))
        self.subnet_entry.bind("<Leave>", lambda e: self.hide_tooltip())
        subnet_btn = ctk.CTkButton(subnet_section, text="Show Subnets", command=self.show_subnets)
        subnet_btn.grid(row=2, column=1, padx=(10,0))
        subnet_btn.bind("<Enter>", lambda e: self.show_tooltip("Show all subnets for the given prefix length."))
        subnet_btn.bind("<Leave>", lambda e: self.hide_tooltip())
        subnet_section.grid_columnconfigure(0, weight=1)
        self.subnet_output = ctk.CTkTextbox(subnet_section, height=80)
        self.subnet_output.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(10,0))
        self.subnet_output.configure(state="disabled")

        # Action section (row 1, col 0:2)
        action_section = ctk.CTkFrame(self.left_frame, corner_radius=8, border_width=1, border_color="#333333")
        action_section.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=(0,5))
        action_header = ctk.CTkLabel(action_section, text="Actions", font=("Segoe UI", 15, "bold"), text_color="#00aaff")
        action_header.pack(anchor="w", padx=5, pady=(5,2))
        calc_btn = ctk.CTkButton(action_section, text="Calculate (Ctrl+R)", command=self.calculate)
        calc_btn.pack(pady=5, fill="x")
        calc_btn.bind("<Enter>", lambda e: self.show_tooltip("Calculate subnet info. Shortcut: Ctrl+R"))
        calc_btn.bind("<Leave>", lambda e: self.hide_tooltip())

        # IP Lookup section (row 2, col 0:2)
        lookup_section = ctk.CTkFrame(self.left_frame, corner_radius=8, border_width=1, border_color="#333333")
        lookup_section.grid(row=2, column=0, columnspan=2, sticky="ew", padx=10, pady=(0,5))
        lookup_header = ctk.CTkLabel(lookup_section, text="IP Lookup", font=("Segoe UI", 15, "bold"), text_color="#00aaff")
        lookup_header.grid(row=0, column=0, sticky="w", pady=(5,2))
        lookup_label = ctk.CTkLabel(lookup_section, text="IP Lookup:", font=("Segoe UI", 12, "bold"))
        lookup_label.grid(row=1, column=0, sticky="w", pady=(0,5))
        self.lookup_entry = ctk.CTkEntry(lookup_section, placeholder_text="e.g. 192.168.1.5 or 2001:db8::1")
        self.lookup_entry.grid(row=2, column=0, sticky="ew")
        self.lookup_entry.bind("<Enter>", lambda e: self.show_tooltip("Enter an IP address to check if it is in the network."))
        self.lookup_entry.bind("<Leave>", lambda e: self.hide_tooltip())
        lookup_btn = ctk.CTkButton(lookup_section, text="Check IP", command=self.check_ip)
        lookup_btn.grid(row=2, column=1, padx=(10,0))
        lookup_btn.bind("<Enter>", lambda e: self.show_tooltip("Check if the entered IP is in the calculated network."))
        lookup_btn.bind("<Leave>", lambda e: self.hide_tooltip())
        lookup_section.grid_columnconfigure(0, weight=1)
        self.lookup_output = ctk.CTkLabel(lookup_section, text="")
        self.lookup_output.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(10,0))

        # Output section (row 3, col 0:2)
        output_section = ctk.CTkFrame(self.left_frame, corner_radius=8, border_width=1, border_color="#333333")
        output_section.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=10, pady=(0,10))
        self.left_frame.grid_rowconfigure(3, weight=1)
        output_header = ctk.CTkLabel(output_section, text="Results", font=("Segoe UI", 15, "bold"), text_color="#00aaff")
        output_header.pack(anchor="w", padx=10, pady=(10,2))
        output_frame = ctk.CTkFrame(output_section, corner_radius=6, fg_color="#222222")
        output_frame.pack(padx=10, pady=10, fill="both", expand=True)
        labels = [
            "Network:",
            "Netmask:",
            "Wildcard Mask:",
            "Broadcast Address:",
            "Total Hosts:",
            "Host Range:"
        ]
        self.output_vars = {}
        self.copy_buttons = {}
        for i, text in enumerate(labels):
            lbl = ctk.CTkLabel(output_frame, text=text, font=("Segoe UI", 12, "bold"), text_color="#cccccc")
            lbl.grid(row=0, column=i, sticky="w", padx=(5,2), pady=4)
            lbl.bind("<Enter>", lambda e, t=text: self.show_tooltip(f"{t} - See calculated value."))
            lbl.bind("<Leave>", lambda e: self.hide_tooltip())
            var = ctk.StringVar(value="-")
            val_lbl = ctk.CTkLabel(output_frame, textvariable=var, font=("Segoe UI", 12))
            val_lbl.grid(row=1, column=i, sticky="w", padx=(2,5), pady=4)
            copy_btn = ctk.CTkButton(output_frame, text="Copy (Ctrl+C)", width=90, command=lambda t=text: self.copy_to_clipboard(t))
            copy_btn.grid(row=2, column=i, padx=(2,5), pady=4)
            copy_btn.bind("<Enter>", lambda e, t=text: self.show_tooltip(f"Copy {t} to clipboard. Shortcut: Ctrl+C"))
            copy_btn.bind("<Leave>", lambda e: self.hide_tooltip())
            self.output_vars[text] = var
            self.copy_buttons[text] = copy_btn
        export_btn = ctk.CTkButton(output_frame, text="Export Results (Ctrl+E)", command=self.export_results)
        export_btn.grid(row=3, column=0, columnspan=len(labels), pady=(10,0), sticky="ew")
        export_btn.bind("<Enter>", lambda e: self.show_tooltip("Export results to text file. Shortcut: Ctrl+E"))
        export_btn.bind("<Leave>", lambda e: self.hide_tooltip())

        # Network Visualization section (row 4, col 0:2)
        viz_section = ctk.CTkFrame(self.left_frame, corner_radius=8, border_width=1, border_color="#333333")
        viz_section.grid(row=4, column=0, columnspan=2, sticky="nsew", padx=10, pady=(0,5))
        self.left_frame.grid_rowconfigure(4, weight=2)
        viz_label = ctk.CTkLabel(viz_section, text="Network Visualization", font=("Segoe UI", 15, "bold"), text_color="#00aaff")
        viz_label.pack(anchor="w", padx=5, pady=(5,2))
        self.viz_canvas = tkinter.Canvas(viz_section, height=120, bg="#181830", highlightthickness=2, highlightbackground="#00aaff")
        self.viz_canvas.pack(fill="both", expand=True, padx=10, pady=10)

        # Right panel: history
        history_frame = ctk.CTkFrame(self.main_frame, corner_radius=12, border_width=2, border_color="#444444")
        history_frame.grid(row=0, column=1, sticky="nsew", padx=(20,0), pady=10)
        self.main_frame.grid_columnconfigure(1, weight=2)
        history_header = ctk.CTkLabel(history_frame, text="Recent Calculations", font=("Segoe UI", 17, "bold"), text_color="#00aaff")
        history_header.pack(anchor="w", padx=10, pady=(10,2))
        self.history_list = ctk.CTkTextbox(history_frame, height=400, font=("Segoe UI", 12), fg_color="#222222", text_color="#cccccc")
        self.history_list.pack(fill="both", expand=True, padx=10, pady=10)
        self.history = []
    def validate_ip(self, event=None):
        ip_str = self.ip_entry.get().strip()
        if '/' in ip_str:
            try:
                ipaddress.ip_network(ip_str, strict=False)
                self.ip_error.configure(text="")
            except Exception:
                self.ip_error.configure(text="Invalid CIDR notation or IP address.")
        else:
            try:
                ipaddress.ip_address(ip_str)
                self.ip_error.configure(text="")
            except Exception:
                self.ip_error.configure(text="Invalid IP address.")

    def validate_mask(self, event=None):
        mask_str = self.mask_entry.get().strip()
        ipver = self.ipver_option.get()
        if not mask_str:
            self.mask_error.configure(text="")
            return
        if mask_str.isdigit():
            try:
                prefix = int(mask_str)
                if ipver == "IPv4" and not (0 <= prefix <= 32):
                    raise ValueError
                if ipver == "IPv6" and not (0 <= prefix <= 128):
                    raise ValueError
                self.mask_error.configure(text="")
            except Exception:
                self.mask_error.configure(text="Invalid prefix length.")
        else:
            if ipver == "IPv4":
                try:
                    ipaddress.IPv4Network(f"0.0.0.0/{mask_str}")
                    self.mask_error.configure(text="")
                except Exception:
                    self.mask_error.configure(text="Invalid netmask.")
            else:
                self.mask_error.configure(text="IPv6 does not support netmask notation.")
        # ...existing code...
    def clear_all_fields(self):
        self.ip_entry.delete(0, 'end')
        self.mask_entry.delete(0, 'end')
        self.subnet_entry.delete(0, 'end')
        self.lookup_entry.delete(0, 'end')
        for var in self.output_vars.values():
            var.set('-')
        self.subnet_output.configure(state="normal")
        self.subnet_output.delete("1.0", "end")
        self.subnet_output.configure(state="disabled")
        self.lookup_output.configure(text="")
        self.viz_canvas.delete("all")

    def reset_history(self):
        self.history = []
        self.history_list.configure(state="normal")
        self.history_list.delete("1.0", "end")
        self.history_list.configure(state="disabled")

    def show_how_to_use(self):
        how_text = (
            "How to Use Subnet Calculator\n\n"
            "1. Enter an IP address or CIDR notation in the Network Input section.\n"
            "2. Enter a prefix length or netmask.\n"
            "3. Select IPv4 or IPv6.\n"
            "4. Click 'Calculate' or use Ctrl+R to compute results.\n"
            "5. View results in the Results section.\n"
            "6. Use Subnetting to split the network into subnets.\n"
            "7. Use IP Lookup to check if an IP is in the network.\n"
            "8. Export results using the File menu or Export buttons.\n"
            "9. Copy results using the Copy buttons or Edit menu.\n"
            "10. Change theme in the View menu.\n"
            "11. Use Tools menu for quick actions.\n"
            "12. See recent calculations in the right panel.\n"
        )
        messagebox.showinfo("How to Use", how_text)

    def show_about(self):
        about_text = (
            "Subnet Calculator v1.0\n\n"
            "Created by GitHub Copilot.\n"
            "Features:\n"
            "- IPv4/IPv6 support\n"
            "- Subnetting\n"
            "- IP lookup\n"
            "- Export to TXT/CSV/JSON\n"
            "- Copy to clipboard\n"
            "- Responsive, modern UI\n"
        )
        messagebox.showinfo("About", about_text)
    def set_theme(self, mode):
        ctk.set_appearance_mode(mode)
        messagebox.showinfo("Theme Switched", f"Theme set to {mode} mode.")
    def copy_to_clipboard(self, label):
        value = self.output_vars[label].get()
        self.clipboard_clear()
        self.clipboard_append(value)
        messagebox.showinfo("Copied", f"Copied '{label} {value}' to clipboard.")

    def export_results(self):
        import datetime
        results = []
        for label, var in self.output_vars.items():
            results.append(f"{label} {var.get()}")
        # Add subnet and lookup info if present
        if hasattr(self, "subnet_output"):
            self.subnet_output.configure(state="normal")
            subnet_text = self.subnet_output.get("1.0", "end").strip()
            self.subnet_output.configure(state="disabled")
            if subnet_text:
                results.append("\nSubnets:\n" + subnet_text)
        if hasattr(self, "lookup_output"):
            lookup_text = self.lookup_output.cget("text")
            if lookup_text:
                results.append("\nIP Lookup:\n" + lookup_text)
        # Save to file
        filename = f"subnet_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, "w") as f:
                f.write("\n".join(results))
            messagebox.showinfo("Exported", f"Results exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Could not export results.\nError: {e}")

    def export_csv(self):
        import csv, datetime
        filename = f"subnet_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        try:
            with open(filename, "w", newline='') as f:
                writer = csv.writer(f)
                for label, var in self.output_vars.items():
                    writer.writerow([label, var.get()])
                # Subnet info
                if hasattr(self, "subnet_output"):
                    self.subnet_output.configure(state="normal")
                    subnet_text = self.subnet_output.get("1.0", "end").strip()
                    self.subnet_output.configure(state="disabled")
                    if subnet_text:
                        writer.writerow(["Subnets", subnet_text])
                if hasattr(self, "lookup_output"):
                    lookup_text = self.lookup_output.cget("text")
                    if lookup_text:
                        writer.writerow(["IP Lookup", lookup_text])
            messagebox.showinfo("Exported", f"Results exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Could not export CSV.\nError: {e}")

    def export_json(self):
        import json, datetime
        filename = f"subnet_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        data = {label: var.get() for label, var in self.output_vars.items()}
        if hasattr(self, "subnet_output"):
            self.subnet_output.configure(state="normal")
            subnet_text = self.subnet_output.get("1.0", "end").strip()
            self.subnet_output.configure(state="disabled")
            if subnet_text:
                data["Subnets"] = subnet_text
        if hasattr(self, "lookup_output"):
            lookup_text = self.lookup_output.cget("text")
            if lookup_text:
                data["IP Lookup"] = lookup_text
        try:
            with open(filename, "w") as f:
                json.dump(data, f, indent=2)
            messagebox.showinfo("Exported", f"Results exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Could not export JSON.\nError: {e}")

    def calculate(self):
        ip_input = self.ip_entry.get().strip()
        mask_input = self.mask_entry.get().strip()
        ipver = self.ipver_option.get()
        # CIDR notation support
        if '/' in ip_input:
            try:
                net = ipaddress.ip_network(ip_input, strict=False)
                ipver = "IPv4" if isinstance(net, ipaddress.IPv4Network) else "IPv6"
                network_addr = f"{net.network_address}/{net.prefixlen}"
                self.output_vars["Network:"].set(network_addr)
                if ipver == "IPv4":
                    wildcard = str(ipaddress.IPv4Address(~int(net.netmask) & 0xFFFFFFFF))
                    broadcast = str(net.broadcast_address)
                    hosts = list(net.hosts())
                    total_hosts = len(hosts)
                    host_range = f"{hosts[0]} - {hosts[-1]}" if hosts else "N/A"
                    self.output_vars["Wildcard Mask:"].set(wildcard)
                    self.output_vars["Broadcast Address:"].set(broadcast)
                    self.output_vars["Total Hosts:"].set(str(total_hosts))
                    self.output_vars["Host Range:"].set(host_range)
                    self.output_vars["Netmask:"].set(str(net.netmask))
                else:
                    self.output_vars["Wildcard Mask:"].set("N/A")
                    self.output_vars["Broadcast Address:"].set("N/A")
                    self.output_vars["Total Hosts:"].set(str(net.num_addresses - 2 if net.num_addresses > 2 else 0))
                    hosts = list(net.hosts())
                    host_range = f"{hosts[0]} - {hosts[-1]}" if hosts else "N/A"
                    self.output_vars["Host Range:"].set(host_range)
                    self.output_vars["Netmask:"].set("N/A")
                self.current_network = net
                # Add to history
                hist_entry = f"{network_addr} | Hosts: {self.output_vars['Total Hosts:'].get()}"
                self.history.append(hist_entry)
                if len(self.history) > 10:
                    self.history = self.history[-10:]
                self.history_list.configure(state="normal")
                self.history_list.delete("1.0", "end")
                for item in reversed(self.history):
                    self.history_list.insert("end", item + "\n")
                self.history_list.configure(state="disabled")
                self.update_visualization()
                return
            except Exception as e:
                messagebox.showerror("Invalid Input", f"Please enter a valid CIDR notation or IP address.\nError: {e}")
                return
        # ...existing code for non-CIDR input...
        ip_str = self.sanitize_ip(ip_input)
        mask_str = self.sanitize_mask(mask_input)
        try:
            if ipver == "IPv4":
                ip_obj = ipaddress.IPv4Address(ip_str)
            else:
                ip_obj = ipaddress.IPv6Address(ip_str)
        except Exception:
            messagebox.showerror("Invalid Input", f"Please enter a valid {ipver} address.")
            return

        # Validate mask/prefix
        prefix = None
        netmask = None
        if mask_str.isdigit():
            try:
                prefix = int(mask_str)
                if ipver == "IPv4" and not (0 <= prefix <= 32):
                    raise ValueError
                if ipver == "IPv6" and not (0 <= prefix <= 128):
                    raise ValueError
                if ipver == "IPv4":
                    netmask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
            except Exception:
                messagebox.showerror("Invalid Input", f"Prefix length must be valid for {ipver}.")
                return
        else:
            if ipver == "IPv4":
                try:
                    netmask = mask_str
                    # Validate netmask
                    prefix = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
                except Exception:
                    messagebox.showerror("Invalid Input", "Please enter a valid netmask (e.g. 255.255.255.0) or prefix length.")
                    return
            else:
                messagebox.showerror("Invalid Input", "IPv6 does not support netmask notation. Use prefix length.")
                return

        # Build network string
        network_str = f"{ip_str}/{prefix}"
        try:
            net = ipaddress.ip_network(network_str, strict=False)
            # Compute values
            network_addr = f"{net.network_address}/{net.prefixlen}"
            if ipver == "IPv4":
                wildcard = str(ipaddress.IPv4Address(~int(net.netmask) & 0xFFFFFFFF))
                broadcast = str(net.broadcast_address)
                hosts = list(net.hosts())
                total_hosts = len(hosts)
                host_range = f"{hosts[0]} - {hosts[-1]}" if hosts else "N/A"
                self.output_vars["Wildcard Mask:"].set(wildcard)
                self.output_vars["Broadcast Address:"].set(broadcast)
                self.output_vars["Total Hosts:"].set(str(total_hosts))
                self.output_vars["Host Range:"].set(host_range)
                self.output_vars["Netmask:"].set(str(net.netmask))
            else:
                self.output_vars["Wildcard Mask:"].set("N/A")
                self.output_vars["Broadcast Address:"].set("N/A")
                self.output_vars["Total Hosts:"].set(str(net.num_addresses - 2 if net.num_addresses > 2 else 0))
                hosts = list(net.hosts())
                host_range = f"{hosts[0]} - {hosts[-1]}" if hosts else "N/A"
                self.output_vars["Host Range:"].set(host_range)
                self.output_vars["Netmask:"].set("N/A")

            self.output_vars["Network:"].set(network_addr)

            # Store network for subnetting and lookup
            self.current_network = net

            # Add to history
            hist_entry = f"{network_addr} | Hosts: {self.output_vars['Total Hosts:'].get()}"
            self.history.append(hist_entry)
            if len(self.history) > 10:
                self.history = self.history[-10:]
            self.history_list.configure(state="normal")
            self.history_list.delete("1.0", "end")
            for item in reversed(self.history):
                self.history_list.insert("end", item + "\n")
            self.history_list.configure(state="disabled")
            self.update_visualization()
        except Exception as e:
            messagebox.showerror("Invalid Input", f"Please enter a valid network and mask.\nError: {e}")
    def update_visualization(self):
        self.viz_canvas.delete("all")
        if not hasattr(self, "current_network"):
            return
        net = self.current_network
        ipver = self.ipver_option.get()
        # Draw a larger bar representing the network and host range
        width = self.viz_canvas.winfo_width() or 600
        bar_height = 60
        self.viz_canvas.create_rectangle(20, 30, width-20, 30+bar_height, fill="#4444aa", outline="#00aaff", width=3)
        # Mark network address
        self.viz_canvas.create_text(30, 60, anchor="w", fill="#00aaff", font=("Segoe UI", 13, "bold"), text=str(net.network_address))
        # Mark broadcast (IPv4) or last address (IPv6)
        if ipver == "IPv4":
            self.viz_canvas.create_text(width-30, 60, anchor="e", fill="#00aaff", font=("Segoe UI", 13, "bold"), text=str(net.broadcast_address))
        else:
            self.viz_canvas.create_text(width-30, 60, anchor="e", fill="#00aaff", font=("Segoe UI", 13, "bold"), text=str(list(net.hosts())[-1]) if net.num_addresses > 1 else str(net.network_address))
        # Mark host range
        hosts = list(net.hosts())
        if hosts:
            self.viz_canvas.create_text(width//2, 60, anchor="center", fill="yellow", font=("Segoe UI", 13, "bold"), text=f"{hosts[0]} ... {hosts[-1]}")

    def show_subnets(self):
        if not hasattr(self, "current_network"):
            messagebox.showerror("Error", "Please calculate a network first.")
            return
        subnet_prefix = self.sanitize_subnet_prefix(self.subnet_entry.get())
        ipver = self.ipver_option.get()
        try:
            subnet_prefix = int(subnet_prefix)
            if ipver == "IPv4":
                max_prefix = 32
            else:
                max_prefix = 128
            if not (self.current_network.prefixlen < subnet_prefix <= max_prefix):
                raise ValueError
        except Exception:
            messagebox.showerror("Invalid Input", f"Enter a valid subnet prefix length greater than the main network's prefix and less than or equal to {max_prefix}.")
            return
        subnets = list(self.current_network.subnets(new_prefix=subnet_prefix))
        self.subnet_output.configure(state="normal")
        self.subnet_output.delete("1.0", "end")
        if not subnets:
            self.subnet_output.insert("end", "No subnets found.\n")
        else:
            for i, sn in enumerate(subnets, 1):
                hosts = list(sn.hosts())
                if ipver == "IPv4":
                    host_range = f"{hosts[0]} - {hosts[-1]}" if hosts else "N/A"
                else:
                    host_range = f"{hosts[0]} - {hosts[-1]}" if hosts else "N/A"
                self.subnet_output.insert("end", f"Subnet {i}: {sn} | Hosts: {len(hosts)} | Range: {host_range}\n")
        self.subnet_output.configure(state="disabled")

    def check_ip(self):
        if not hasattr(self, "current_network"):
            messagebox.showerror("Error", "Please calculate a network first.")
            return
        ip_lookup = self.sanitize_lookup_ip(self.lookup_entry.get())
        ipver = self.ipver_option.get()
        try:
            if ipver == "IPv4":
                ip_obj = ipaddress.IPv4Address(ip_lookup)
            else:
                ip_obj = ipaddress.IPv6Address(ip_lookup)
        except Exception:
            self.lookup_output.configure(text="Invalid IP address.")
            return
        if ip_obj in self.current_network:
            if ipver == "IPv4" and ip_obj == self.current_network.network_address:
                msg = f"{ip_obj} is the network address."
            elif ipver == "IPv4" and ip_obj == self.current_network.broadcast_address:
                msg = f"{ip_obj} is the broadcast address."
            else:
                msg = f"{ip_obj} is a valid host in the network."
        else:
            msg = f"{ip_obj} is NOT in the network."
        self.lookup_output.configure(text=msg)
    def show_help(self):
        help_text = (
            "Subnet Calculator Help\n\n"
            "- Enter an IP address or CIDR in the Network Input section.\n"
            "- Enter a prefix length or netmask.\n"
            "- Select IPv4 or IPv6.\n"
            "- Click Calculate or use Ctrl+R.\n"
            "- Use Subnetting to split the network.\n"
            "- Use IP Lookup to check if an IP is in the network.\n"
            "- Export results using File menu or Export buttons.\n"
            "- Copy results using Copy buttons or Edit menu.\n"
            "- Change theme in View menu.\n"
            "- Use Tools menu for quick actions.\n"
            "- See recent calculations in the right panel.\n"
        )
        messagebox.showinfo("Help", help_text)

if __name__ == "__main__":
    app = SubnetCalculator()
    app.mainloop()
