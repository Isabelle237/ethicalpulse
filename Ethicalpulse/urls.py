from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('EthicalpulsApp.urls')),
    
    # Scanning Tools URLs
    path('nmap_scan/', include('EthicalpulsApp.nmap_scan.urls')),
    path('nikto_scan/', include('EthicalpulsApp.nikto_scan.urls')),
    path('aircrack_scan/', include('EthicalpulsApp.aircrack_scan.urls')),
    path('wifite_scan/', include('EthicalpulsApp.wifite_scan.urls')),
    path('snort_scan/', include('EthicalpulsApp.snort_scan.urls')),
    path('wireshark_scan/', include('EthicalpulsApp.wireshark_scan.urls')),
    path('reconng_scan/', include('EthicalpulsApp.reconng_scan.urls')),
    path('john_scan/', include('EthicalpulsApp.john_scan.urls')),
    path('metasploit_scan/', include('EthicalpulsApp.metasploit_scan.urls')),
    path('zap_scan/', include('EthicalpulsApp.zap_scan.urls')),
    path('sqlmap_scan/', include('EthicalpulsApp.sqlmap_scan.urls')),
    path('beef_scan/', include('EthicalpulsApp.beef_scan.urls')),
    path('hashcat_scan/', include('EthicalpulsApp.hashcat_scan.urls')),
    path('ghidra_scan/', include('EthicalpulsApp.ghidra_scan.urls')),
    path('vulnerabilities/', include('EthicalpulsApp.vulnerabilities.urls')),
    path('scans/', include('EthicalpulsApp.scans.urls')),
] + static(settings.STATIC_URL, document_root=settings.STATICFILES_DIRS[0])