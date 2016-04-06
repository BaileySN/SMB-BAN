# SMB-BAN

Dies ist eine kleine Anleitung wie man einen Dateiserver dazu bringt Infizierte Clients zu sperren und dem Admin per Mail zu benachrichtigen.

Somit kann man in einer Firma leichter nachvollziehen wer von den Clients betroffen ist, und Ihn vom Netzwerk und Zugriff auf die Daten am Server sperren.

Diese Anleitung ist angelehnt an den [HEISE Artikel](http://www.heise.de/security/artikel/Erpressungs-Trojaner-wie-Locky-aussperren-3120956.html) und wird verwendet um den Crypto-Trojaner Locky bzw. Ransomware zu hindern den ganzen Server zu verschlüsseln.

*Ich gehe davon aus dass die Packete Samba inkl. vfs Module und fail2ban bereits am System installiert sind.*

## Samba

In smb.conf wird folgendes unter [global] hinzugefügt, um das Audit zu konfigurieren.
<pre>
[global]
        full_audit:failure = none
        full_audit:success = pwrite write rename
        full_audit:prefix = IP=%I|USER=%u|MACHINE=%m|VOLUME=%S
        full_audit:facility = local7
        full_audit:priority = NOTICE
</pre>

Und in jeder Freigabe [share]  wird noch *vfs objects = full_audit* hinzugefügt.
<pre>
[share]
        vfs objects = full_audit
</pre>


## fail2ban

**TeslaCrypt 3 hat laut Meldung auch die Endung .mp3, falls dies auf andere Dateien auch zutrifft müsste man die Zeile  in /etc/fail2ban/filter.d/samba.conf löschen.**
```samba.conf
smbd.*\:\ IP=<HOST>\|.*\.mp3$
```


Die Datei fail2ban/filter.d/samba.conf nach */etc/fail2ban/filter.d/samba.conf* kopieren und die nötigen Rechte setzen.

**Tipp:** Da sich die Dateiendungen bei Ransomware, Locky oder TeslaCrypt 2/3 ständig ändern, wäre es von Vorteil statt nur die vorgegebenen Dateiendungen zu Prüfen einfach alles Sperren und nur bestimmte Freigeben.


Die Datei samba.conf unter *fail2ban/samba.conf* anpassen und zum aktivieren nach */etc/fail2ban/jail.d/samba.conf* kopieren.
Bei **Wheezy** den Inhalt in **jail.conf** eintragen.

### kurze Beschreibung der Datei *jail.d/samba.conf*

```conf
[samba]
filter = samba
enabled = true
action = iptables-multiport[name=samba, port="135,139,445,137,138", protocol=tcp]
         mail[name=samba, dest=admin@MYDOMAIN.DE] # dest=E-Mail Adresse vom Admin
logpath = /var/log/syslog

# Beim ersten versuch die Regel ausführen (Beim ersten Versuch den Benutzer sofort sperren)
maxretry = 1

# 10 Minuten in den Logs zurück schauen (Wert in Sekunden)
findtime = 600

# Benutzer für einen Tag sperren (Wert in Sekunden)
bantime = 86400
```

Bei Wheezy muss man dies in die jail.conf eintragen.

## Test

Samba und Fail2ban neustarten.

In dem überwachendem Verzeichnis / Freigabe mit Windows oder einem Client eine datei mit der Endung .locky erstellen und der Server müsste dich für einen Tag sperren.

Dies Sperrt aber den Benutzer an diesem Share / Server, falls es mehrere sind müsste dies dort auch eingerichtet werden.
