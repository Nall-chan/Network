# IPSymcon Network
===

Modul für IP-Symcon ab Version 4.3 ermöglicht es auf Events von Geräten zu reagieren, die eine Anfrage ins Netzwerk per DHCP oder dem Bootstrap Protocol stellen.
So lässt sich zum Beispiel auf das Drücken eines Dashbuttons reagieren oder auf das Anmelden eines Geräts, wie ein Smartphone, in einem LAN.

## Dokumentation

**Inhaltsverzeichnis**

1. [Funktionsumfang](#1-funktionsumfang)  
2. [Voraussetzungen](#2-voraussetzungen)  
3. [Installation](#3-installation)  
4. [Funktionsreferenz](#4-funktionsreferenz)
5. [Konfiguration](#5-konfiguration)  
6. [Anhang](#6-anhang)  

## 1. Funktionsumfang

Viele Geräte besitzen keine feste IP Adresse, sondern fragen diese im LAN an z.B. über das [Bootstrap Protocol](https://de.m.wikipedia.org/wiki/Bootstrap_Protocol "Bootstrap Protocol") oder über [DHCP](https://de.m.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol "DHCP") (Dynamic Host Configuration Protocol).
Dabei senden diese Geräte eine Anfrage in das Netzwerk und warten dann auf die Zuweisung einer IP Adresse durch einen Server. Das IP-Symcon Network Modul registriert solche Anfragen von Geräten und kann dann ein Event in IP-Symcon auslösen. 
Auf diese Weise ist es z.B. möglich auf das Drücken eine Dashbuttons zu reagieren oder das Einbuchen eines Smartphones in ein WLAN.

#### DHCP

Sobald ein Gerät über [DHCP](https://de.m.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol "DHCP") (Dynamic Host Configuration Protocol) bei einem DHCP Server eine Anfrage in das Netzwerk stellt, wird dies von IP-Symcon erkannt.
Dies kann genutzt werden um z.B. eine Anwesenheitserkennung Aufgrund vom Einbuchen vom Geräten in eine WLAN zu nutzten.


#### Bootstrap

Manche Geräte nutzten auch das [Bootstrap Protocol](https://de.m.wikipedia.org/wiki/Bootstrap_Protocol "Bootstrap Protocol") auch hier kann IP-Symcon auf die Anfrage anhand der MAC Adresse des Geräts reagieren.

## 2. Voraussetzungen

 - IPS 4.3
 - Das Gerät, das ein Event in IP-Symcon auslösen soll, bezieht die IP Adresse dynamisch per DHCP oder Bootstrap (z.B. Dashbutton, Smartphone)

## 3. Installation

### a. Vorbereitungen für einen Dashbutton
 Zuerst muss der Dash Button mit der dazu gehörigen Amazon App von Amazon einrichtet werden. 
 In der Amazon App auf das Menü drücken

![Setup1](docs/setup1.png?raw=true "Setup1") 

Mein Konto auswählen

![Setup2](docs/setup2.png?raw=true "Setup2") 

Bei Dash-Geräte auf _Ein neues Gerät einrichten_ drücken 

![Setup3](docs/setup3.png?raw=true "Setup3") 

 im Anschluss den Anweisungen im Bildschirm der App folgen bzw. der Anleitung von Amazon [Einrichtung des Dashbuttons](https://www.amazon.de/gp/help/customer/display.html?nodeId=201746340 "Einrichten Ihres Dash Button-Gerätes") folgen.
 
 Wenn in einer Fritzbox eine Mitteilung eingerichtet ist bekommt man nun eine Email geschickt.
 
 ![FritzboxMessage](docs/fritzboxmessage.png?raw=true "FritzboxMessage") 
 
 Die MAC Adresse notieren wir hier um diese dann später in IP-Symcon im Modul eintragen zu können. Man kann auch noch in der Fritzbox bzw. den verwendeten DHCP Server so Einrichten, das stets die gleiche IP Adresse an den Dash Button vergeben wird.
 Falls keine Mitteilung in Fritzbox oder einen anderen Router eingerichtet wurde, muss man im DHCP Server bzw. der Fritzbox nachschauen welches Gerät zuletzt eine neue IP Adresse zugewiesen bekommen hat. Dies ist dann der Dashbutton, hier ist die MAC Adresse zu notieren, diese brauchen wir für IP-Symcon.
 
 Jedes mal wenn der Dash Button gedrückt wird nun zur Zeit eine Bestellung ausgeführt. Wir können dann in IP-Symcon nachvollziehen wann eine Bestellung gesendet wurde indem wir die Variable loggen. Wenn wir den Dash Button _nicht für eine Bestellung benutzten wollen_, sondern damit z.B. eine Lampe schalten wollen, müssen wir den _Zugang des Dash Buttons zum Internet_ _**sperren**_,
 damit der Dashbutton nicht bei jedem Druck einen Artikel bestellt.
 
 Siehe auch
 [Internetnutzung in der Fritzbox einschränken](https://avm.de/service/fritzbox/fritzbox-7390/wissensdatenbank/publication/show/8_Internetnutzung-mit-Kindersicherung-einschraenken/ "Internet Nutzung einschränken").
 
 
 Dazu kann man den Zugang der MAC bzw. IP-Adresse zum Internet im Router _sperren_.
 
 In einer Fritzbox wechseln wir hierzu auf
 
  ![FritzboxMenu](docs/fritzmenu.png?raw=true "FritzboxMenu") 
  
  Dort wählen wir nun die passende IP Adresse aus und setzten diese auf _**Gesperrt**_
  
   ![FritzboxGesperrt1](docs/fritzboxgesperrt1.png?raw=true "FritzboxGesperrt1") 
   
   ![FritzboxGesperrt](docs/fritzboxgesperrt.png?raw=true "FritzboxGesperrt") 
 
 Nun sollte bei einem Druck auf den Knopf die Leuchte erst ein paar Mal weiß und dann ein paar Mal rot leuchten, ist dies der Fall so sendet der Dash Button eine Anfrage in das LAN, eine Internet Verbindung wird aber keine aufgebaut und daher auch nichts bestellt.



### b. Laden des Moduls

Die IP-Symcon (min Ver. 4.3) Konsole öffnen. Im Objektbaum unter Kerninstanzen die Instanz __*Modules*__ durch einen doppelten Mausklick öffnen.

![Modules](docs/Modules.png?raw=true "Modules")

In der _Modules_ Instanz rechts oben auf den Button __*Hinzufügen*__ drücken.

![Modules](docs/Hinzufuegen.png?raw=true "Hinzufügen")
 
In dem sich öffnenden Fenster folgende URL hinzufügen:

![Modules](docs/RepositoryURL.png?raw=true "URL Repository") 

	
    `https://github.com/Nall-chan/IPSNetwork`  
    
und mit _OK_ bestätigen.    
    

    
Anschließend erscheint ein Eintrag für das Modul in der Liste der Instanz _Modules_  

    
### c. Einrichtung in IPS

In IP-Symcon wird von jedes Gerät das ein Event auslösen soll eine seperate Instanz angelegt. Der Mulicast Socket wird
automatisch mit angelegt. Um die Instanz zu erstellen wechseln wir in die Kategorie, unter der wir die Instanz platzieren wollen
und erstellen mit *CTRL+1* eine neue Instanz. Bei Gerät geben wir __*DHCP Sniffer*__ an. Bei Protocoll wählen wir das Protokoll aus, bei einem Dashbutton z.B. _DHCP & Bootp_.
Unter _MAC Adress_ wird die MAC Adresse des Geräts eingetragen.
	
## 4. Funktionsreferenz

### Dashbutton

Keine gesonderte Funktion, die Variable wird geändert sobald eine Anfrage vom Gerät mit der passenden MAC gestellt wird.
Auf die Variable kann dann ein Ereigniss gelegt werden, dass bei Variablenänderung eine beliebige Aktion in IP-Symcon ausführt.


## 5. Konfiguration

###  DHCP Sniffer:

| Eigenschaft | Typ     | Standardwert | Funktion                                                        |
| :---------: | :-----: | :----------: | :-------------------------------------------------------------: |
| Protocol    | integer | 		       | Auswahl des Protokolls                                          |
| Address     | string  |              | MAC Adresse des Geräts das ein Event in IP-Symcon auslösen soll |
| Action      | integer |              | Art der Aktion, die ausgeführt werden soll                       |



## 6. Anhang

###  a. GUIDs und Datenaustausch:

#### DHCP Sniffer:

GUID: `{E93BCE5E-BA95-424E-8C3A-BF6AEE6CB976}` 



