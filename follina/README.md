# Follina (CVE-2022-30190)

**Code execution through Microsoft Word and Microsoft Support Diagnostic Tool (MSDT).**

**Objective:** Create a honeynet using MHN-Admin. Present your findings as if you were requested to give a brief report of the current state of Internet security. Assume that your audience is a current employer who is questioning why the company should allocate anymore resources to the IT security team.

Create a vulnerability lab to simulate the Follina vulnerability.

## Follina Deployment

To deploy the lab, I used two VirtualBox instances - one with Kali Linux and one with Windows 11.

**Kali Linux:** https://www.kali.org/get-kali/#kali-virtual-machines

<img src="assets/vbox_import_kali.gif">
<figcaption align = "center"><b>Importing Kali Linux on VirtualBox</b></figcaption>

**Microsoft Windows 11:** https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/

<img src="assets/vbox_import_windows.gif">
<figcaption align = "center"><b>Importing Windows 11 on VirtualBox</b></figcaption>

On the Windows 11 virtual machine, I installed the Office Deployment Tool.

**Microsoft Office Deployment Tool:** https://www.microsoft.com/en-us/download/details.aspx?id=49117

I used the command `setup.exe /configure configuration-Orrice2021Enterprise.xml` to install Microsoft Office.

## Notes

Written up with information guided by Chuck Keith's and John Hammond's online educational content.
