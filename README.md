
# Subnet Calculator

**A modern, user-friendly GUI tool for calculating and visualizing IPv4/IPv6 subnets. Easily analyze networks, split into subnets, and check IPs for IT professionals, students, and enthusiasts.**


# Join the discord if you need help 

[https://fnbubbles420.org/discordinvite](https://fnbubbles420.org/discordinvite)

---

## 🚀 Features

- **IPv4 & IPv6 support**: Calculate subnets for both address types.
- **CIDR and netmask input**: Accepts both CIDR notation (e.g. `192.168.1.0/24`) and netmask (e.g. `255.255.255.0`).
- **Subnetting**: Split a network into smaller subnets with a chosen prefix length.
- **IP Lookup**: Check if an IP address belongs to the calculated network.
- **Export results**: Save results as TXT, CSV, or JSON for easy sharing or analysis.
- **Copy to clipboard**: Quickly copy results for use elsewhere.
- **Recent calculations history**: View your last 10 calculations.
- **Network visualization**: See a graphical representation of your network and host range.
- **Theme switching**: Choose between Light, Dark, or System themes.
- **Keyboard shortcuts**: Fast access to common actions.

---

## 🖥️ Requirements

- Python 3.11+ (Tested on Python 3.11.9)
- [customtkinter](https://github.com/TomSchimansky/CustomTkinter)

Install dependencies:

```bash
pip install customtkinter>=5.2.2
```

---

## 📦 Installation

1. **Clone this repository:**
    ```bash
    git clone https://github.com/KernFerm/Subnet-Calculator.git
    cd subnet-calculator
    ```
2. **Install dependencies:**
    ```bash
    pip install customtkinter
    ```
3. **Run the app:**
    ```bash
    python subnet_calculator.py
    ```

---

## 📝 How to Use

1. **Enter an IP address or CIDR notation** in the Network Input section (e.g. `192.168.1.0` or `192.168.1.0/24` or `2001:db8::`).
2. **Enter a prefix length** (e.g. `24` for IPv4, `64` for IPv6) or a netmask (IPv4 only).
3. **Select IP version** (IPv4 or IPv6).
4. Click **Calculate** or press `Ctrl+R` to compute results.
5. View results in the Results section:
    - Network address
    - Netmask
    - Wildcard mask
    - Broadcast address (IPv4)
    - Total hosts
    - Host range
6. Use **Subnetting** to split the network into subnets:
    - Enter a subnet prefix length greater than the main network's prefix.
    - Click **Show Subnets** to view all subnets and their host ranges.
7. Use **IP Lookup** to check if an IP is in the network.
8. **Export results** using the File menu or Export buttons (TXT, CSV, JSON).
9. **Copy results** using the Copy buttons or Edit menu.
10. **Change theme** in the View menu.
11. **See recent calculations** in the right panel.

---

## ⌨️ Keyboard Shortcuts

- `Ctrl+C`: Copy Network
- `Ctrl+E`: Export Results
- `Ctrl+R`: Calculate

---

## 📤 Export Formats

- **TXT**: Human-readable results
- **CSV**: For spreadsheets
- **JSON**: For scripts and automation

---

## ❓ Troubleshooting

- If the app does not start, ensure you have Python 3.11.9 and `customtkinter` installed.
- For display issues, try switching themes in the View menu.
- For errors with IP or mask input, check the format and refer to the help section in the app.

---

## 🤝 Contributing

Contributions, suggestions, and bug reports are welcome! Please open an issue or submit a pull request.

---

## 📄 License
```
Learning License
===============

This software is provided for educational and personal learning purposes only. 
You are free to use, modify, and share this code for non-commercial, instructional, & self-study activities.

Restrictions:
- Commercial use, distribution, or resale is not permitted.
- No warranty is provided; use at your own risk.
- Please credit the original author if sharing or adapting the code.

For other uses, please contact the author for permission.
```

