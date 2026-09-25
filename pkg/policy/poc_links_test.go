package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
)

// Links that pocPattern matches but that are not exploits.
func TestIsPoCRejectsAdvisoryCopiesAndIndexPages(t *testing.T) {
	for _, u := range []string{
		// Packet Storm copies of vendor advisories, as they appear in NVD references
		"http://packetstormsecurity.com/files/153799/Kernel-Live-Patch-Security-Notice-LSN-0053-1.html",
		"http://packetstormsecurity.com/files/165748/Kernel-Live-Patch-Security-Notice-LNS-0091-1.html",
		"http://packetstormsecurity.com/files/152415/Slackware-Security-Advisory-httpd-Updates.html",
		"http://packetstormsecurity.com/files/154198/FreeBSD-Security-Advisory-FreeBSD-SA-19-03.wpa.html",
		"http://packetstormsecurity.com/files/133986/FreeBSD-Security-Advisory-IRET-Handler-Privilege-Escalation.html",
		"http://packetstormsecurity.com/files/163721/VMware-Security-Advisory-2021-0028.4.html",
		"http://packetstormsecurity.com/files/167574/Asterisk-Project-Security-Advisory-AST-2022-006.html",
		"http://packetstormsecurity.com/files/169687/OpenSSL-Security-Advisory-20221101.html",
		"http://packetstormsecurity.com/files/155744/Siemens-Security-Advisory-SPPA-T3000-Code-Execution.html",
		"https://packetstormsecurity.com/files/105054/Secunia-Security-Advisory-46005.html",
		"http://packetstormsecurity.com/files/118733/Red-Hat-Security-Advisory-2012-1558-01.html",
		"http://packetstormsecurity.com/files/109064/Gentoo-Linux-Security-Advisory-201201-15.html",
		"https://packetstormsecurity.com/files/162712/USN-4961-1.txt",
		"http://packetstormsecurity.com/files/119543/Security-Notice-For-CA-ARCserve-Backup.html",
		// the same kinds of copies under titles not present in the current database
		"https://packetstormsecurity.com/files/156000/Ubuntu-Security-Notice-USN-4263-1.html",
		"https://packetstormsecurity.com/files/156001/Debian-Security-Advisory-4613-1.html",
		"https://packetstormsecurity.com/files/156002/Mandriva-Linux-Security-Advisory-2013-150.html",
		"https://packetstormsecurity.com/files/156003/HP-Security-Bulletin-HPSBMU03380-1.html",
		"https://packetstormsecurity.com/files/156004/Apple-Security-Advisory-2019-3-25-1.html",
		"https://packetstormsecurity.com/files/156005/Cisco-Security-Advisory-20190508-asa.html",
		"https://packetstormsecurity.com/files/156006/openSUSE-Security-Announcement-2011-001.html",
		"HTTPS://PACKETSTORMSECURITY.COM/files/156007/RED-HAT-SECURITY-ADVISORY-2020-0001-01.html",
		"https://packetstormsecurity.com/files/156008/SUSE-Security-Announcement-SUSE-SA-2011-001.html", // plain SUSE, not openSUSE
		// Packet Storm index pages
		"https://packetstormsecurity.com/files/author/8433/",
		"https://packetstormsecurity.com/files/date/2012-12-14/",
		"https://packetstormsecurity.com/files/tags/exploit/",
		// Exploit-DB pages other than an exploit
		"https://www.exploit-db.com/",
		"https://www.exploit-db.com",
		"https://www.exploit-db.com/author/?a=8844",
		"https://www.exploit-db.com/docs/47790",
		"https://www.exploit-db.com/docs/english/17254-connection-string-parameter-pollution-attacks.pdf",
		"https://www.exploit-db.com/papers/47535",
		"https://www.exploit-db.com/ghdb/4613/",
		"https://www.exploit-db.com/google-hacking-database/4613",
		"https://www.exploit-db.com/search?cve=2021-44228",
		// more Exploit-DB index shapes: nothing after the name, only a fragment, a query or
		// fragment on the home page, and the bare exploits index
		"https://www.exploit-db.com/papers",
		"https://www.exploit-db.com/search",
		"https://www.exploit-db.com/papers#x",
		"https://www.exploit-db.com/?utm=x",
		"https://www.exploit-db.com/#top",
		"https://www.exploit-db.com/exploits/",
		"https://www.exploit-db.com/exploits",
	} {
		assert.True(t, pocPattern.MatchString(u), "pocPattern should match %s", u)
		assert.False(t, isPoC(u), u)
	}
}

// Exploits, researcher advisories and titles that only look like advisory copies stay PoC links.
func TestIsPoCKeepsExploitsAndResearcherAdvisories(t *testing.T) {
	for _, u := range []string{
		"https://packetstormsecurity.com/files/170000/Example-Exploit.html",
		"https://packetstormsecurity.com/files/167317/Microsoft-Office-MSDT-Follina-Proof-Of-Concept.html",
		"http://packetstormsecurity.com/files/164418/Apache-HTTP-Server-2.4.49-Path-Traversal-Remote-Code-Execution.html",
		// researcher advisories: exploitation details inside
		"https://packetstormsecurity.com/files/157878/Qualys-Security-Advisory-Qmail-Remote-Code-Execution.html",
		"http://packetstormsecurity.com/files/135273/Qualys-Security-Advisory-OpenSSH-Overflow-Leak.html",
		"http://packetstormsecurity.com/files/125869/Deutsche-Telekom-CERT-Advisory-DTC-A-20140324-001.html",
		"http://packetstormsecurity.com/files/122719/TWSL2013-025.txt",
		// "Update", "Security" or a vendor's name in an exploit title
		"http://packetstormsecurity.com/files/149700/Webmin-Package-Updates-Command-Injection.html",
		"http://packetstormsecurity.com/files/136979/Sitecore-Experience-Platform-8.1-Update-3-Cross-Site-Scripting.html",
		"http://packetstormsecurity.com/files/131588/Malwarebytes-Anti-Malware-Anti-Exploit-Update-Remote-Code-Execution.html",
		"http://packetstormsecurity.com/files/133978/Microsoft-Windows-Server-2012-Group-Policy-Security-Feature-Bypass.html",
		"http://packetstormsecurity.com/files/156200/Cisco-Adaptive-Security-Appliance-Path-Traversal.html",
		"http://packetstormsecurity.com/files/133000/Apple-Safari-Remote-Code-Execution.html",
		"http://packetstormsecurity.com/files/131422/Ubuntu-Apport-kernel_crashdump-Symlink.html",
		"http://packetstormsecurity.com/files/139241/Nginx-Debian-Based-Distros-Root-Privilege-Escalation.html",
		"http://packetstormsecurity.com/files/134484/Gentoo-QEMU-Local-Privilege-Escalation.html",
		"http://packetstormsecurity.com/files/134000/Katello-Red-Hat-Satellite-users-update_roles-Missing-Authorization.html",
		"http://packetstormsecurity.com/files/176000/CentOS-Stream-9-Missing-Kernel-Security-Fix.html",
		"http://packetstormsecurity.com/files/176001/Solaris-10-dtprintinfo-libXm-libXpm-Security-Issues.html",
		// a vendor name later in the slug, not right after /files/<id>/, is not an advisory copy
		"https://packetstormsecurity.com/files/1/Bypassing-Cisco-Security-Advisory-Checks.html",
		// no title in the link, a per-CVE listing, a direct download
		"http://packetstormsecurity.com/files/120923",
		"http://packetstormsecurity.com/files/123454/",
		"https://packetstormsecurity.com/files/cve/CVE-2013-6365",
		"http://packetstormsecurity.com/files/download/136089/mcafeevses-bypass.html",
		// Exploit-DB exploits
		"https://www.exploit-db.com/exploits/52134",
		"https://www.exploit-db.com/exploits/16770/",
		"http://www.exploit-db.com/exploit.php?id=10165",
		"https://www.exploit-db.com/raw/25024",
		"https://www.exploit-db.com/download/47655",
		"https://www.exploit-db.com/shellcodes/46281",
		"http://www.exploit-db.com/sploits/Bonsai-SQL_Injection_in_Cacti.pdf",
		// the other sources are untouched
		"https://www.rapid7.com/db/modules/exploit/windows/http/ektron_xslt_exec",
		"https://www.seebug.org/vuldb/ssvid-71154",
		"https://0day.today/exploit/29277",
		"https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/exploits/unix/webapp/cacti_graphimage_exec.rb",
		"https://github.com/guiimoraes/CVE-2025-15467",
	} {
		assert.True(t, isPoC(u), u)
	}
}

func TestFirstPoCSkipsAdvisoryCopies(t *testing.T) {
	m := grype.Match{
		Vulnerability: grype.Vulnerability{URLs: []string{
			"http://packetstormsecurity.com/files/155743/Slackware-Security-Advisory-wavpack-Updates.html",
		}},
		RelatedVulnerabilities: []grype.RelatedVulnerability{{URLs: []string{
			"http://packetstormsecurity.com/files/153799/Kernel-Live-Patch-Security-Notice-LSN-0053-1.html",
			"https://www.exploit-db.com/exploits/47082",
		}}},
	}
	assert.Equal(t, "https://www.exploit-db.com/exploits/47082", firstPoC(m))

	onlyCopies := grype.Match{Vulnerability: grype.Vulnerability{URLs: []string{
		"http://packetstormsecurity.com/files/152415/Slackware-Security-Advisory-httpd-Updates.html",
		"https://www.exploit-db.com/",
	}}}
	assert.Equal(t, "", firstPoC(onlyCopies))
	assert.False(t, collectFacts(onlyCopies, nil).hasExploit())
}
