#  WebSocket-Client (IPSNetwork)

Implementierung eines Clients mit Websocket Protokoll in IPS.

## Dokumentation

**Inhaltsverzeichnis**

1. [Funktionsumfang](#1-funktionsumfang) 
2. [Voraussetzungen](#2-voraussetzungen)
3. [Installation](#3-installation)
4. [Hinweise zur Verwendung](#4-hinweise-zur-verwendung)
5. [Einrichten eines Websocket-Client in IPS](#5-einrichten-eines-websocket-client-in-ips)
6. [PHP-Befehlsreferenz](#6-php-befehlsreferenz) 
7. [Parameter / Modul-Infos](#7-parameter--modul-infos) 
8. [Datenaustausch](#8-datenaustausch)
9. [Anhang](#9-anhang)
10. [Lizenz](#10-lizenz)

## 1. Funktionsumfang

  Dieses Modul stellt einen WebSocket-Client in IPS bereit.  
  Es wird sowohl TLS als auch die Basis-Authentifizierung unterstützt.  
    

## 2. Voraussetzungen

 - IPS ab Version 4.3  
 
## 3. Installation

   Über das Modul-Control folgende URL hinzufügen.  
   `git://github.com/Nall-chan/IPSNetwork.git`  

   **Bei kommerzieller Nutzung (z.B. als Errichter oder Integrator) wenden Sie sich bitte an den Autor.**  

   Weitere in diesem Modul enthaltene Librarys:

  **PHP-TLS**  
  https://github.com/rnaga/PHP-TLS  
    Copyright (c) 2016 Ryohei Nagatsuka    

  **Pure PHP Elliptic Curve Cryptography Library**  
  https://github.com/phpecc/phpecc  

  **Assert**  
  https://github.com/beberlei/assert  
    Copyright (c) 2011-2013, Benjamin Eberlei, All rights reserved.  

  **AES GCM (Galois Counter Mode) PHP Implementation**  
  https://github.com/Spomky-Labs/php-aes-gcm  
    Copyright (c) 2016 Spomky-Labs  

## 4. Hinweise zur Verwendung

   Das bereitgestellte Module unterstützt direkt keine Hard-/Software welche WebSocket nutzen.  
   Es dient nur dazu das Protokoll in IPS einzubinden.  
   Es sind somit andere Module oder Scripte (mit Register-Variable) notwendig um diese Dienste in IPS abzubilden.  
   Der Client unterstützt die unverschlüsselte (ws://) als auch die verschlüsselte (wss://) Übertragung mit TLS 1.1 & 1.2.  
   Ebenfalls wird die Basic-Authentifizierung unterstützt. Die Anmeldendaten können ohne aktiver Verschlüsselung jedoch mitgelesen werden und sind somit nicht 'sicher'.  
   Bei aktiver Verschlüsselung werden die Zugangsdaten der Basis-Authentifizierung ebenfalls verschlüsselt übertragen.  

  ![](imgs/daWebSocketClient.png)  
   Wird der Client vom Server getrennt, so wird die Instanz als Fehlerhaft makiert. Des weiteren versucht IPS dann alle 60 Sekunden die Verbindung wieder aufzubauen.  
   Der Client stellt ein Interface für die RegisterVariable sowie andere IPS-Instanzen welche ein serielles Protokoll nutzen bereit.  
  ![](imgs/phyWSC2.png)  
   Ebenso wird ein eigenes Interface für den Datenaustausch bereitgestellt, welches alle Möglichkeiten des Protokolls der untergeordneten Instanz zur Verfügung stellt.
  ![](imgs/phyWSC.png)  
  
## 5. Einrichten eines Websocket-Client in IPS

  Unter Instanz hinzufügen '(Splitter)' wählen und ein 'Websocket Client' hinzufügen (Haken bei Alle Module anzeigen!).  
  Es wird automatisch ein 'Client Socket' als übergeordnete Instanz angelegt und fertig konfiguriert.  

   ![](imgs/Client.png)  
  In den Einstellungen ist mindestens die URL des entfernten WebSocket-Server einzutragen.  
  Dabei gilt das übliche Schema einer URL aus Protokoll, Host (u.U. Port) und Pfad.  
  z.B. `wss://localhost:9090/meinWebSocketServer/`  

  Die Erweiterten Einstellungen sind abhängig vom zu verbindenen Dienst, brauchen in der Regel aber nicht geändert werden.  

## 6. PHP-Befehlsreferenz

```php
bool WSC_SendText(integer $InstanzeID, string $Text);
```
 Sendet die in `$Text` übergeben Daten an den WebSocket-Server, dabei wird als Frame (binary / text) die Einstellung auf der Instanz genutzt.  
 Dieser WebSocket-Frame wird immer mit dem Fin-Flag gesendet.  
 Der Rückgabewert ist `True`, sofern der Client verbunden ist.  

```php
bool WSC_SendPacket(integer $InstanzeID, bool $Fin, int $OPCode, string $Text);
```
 Sendet die in `$Text` übergeben Daten an den WebSocket-Server, dabei wird als Frame der übergeben `$OPCode` genutzt.  
 Der WebSocket-Frame wird nur mit dem Fin-Flag gesendet, wenn `$Fin` = `true` ist.  
 Die möglichen OPCodes sind:  

    0x0 (int 0) für  'continuation' => Bedeutet das ein vorheriges Paket fortgesetzt wird und nicht abgeschlossen ist.  
    0x1 (int 1) für  'text' => Ein neuer Frame dessen Inhalt text ist.  
    0x2 (int 2) für  'binary' => Ein neuer Frame dessen Inhalt binär ist.  

 Der Rückgabewert ist `True`, sofern der Client verbunden ist.  

```php
bool WSC_SendPing(integer $InstanzeID, string $Text);
```
 Senden die in `$Text` übergeben Daten als Payload des Ping den WebSocket-Server.  
 Der Rückgabewert ist `True`, wenn der Server den Ping beantwortet.  


## 7. Parameter / Modul-Infos

GUID des Moduls (z.B. wenn Instanz per PHP angelegt werden soll):  

| Instanz          | GUID                                   |
| :--------------: | :------------------------------------: |
| Websocket Client | {3AB77A94-3467-4E66-8A73-840B4AD89582} |

Eigenschaften des 'Websocket Client' für Get/SetProperty-Befehle:  

| Eigenschaft  | Typ     | Standardwert | Funktion                                                                              |
| :----------: | :-----: | :----------: | :-----------------------------------------------------------------------------------: |
| Open         | boolean | false        | false für inaktiv, true für aktiv                                                     |
| URL          | string  |              | Die URL auf die sich verbunden wird                                                   |
| Version      | integer | 13           | Die WebSocket-Version 13, 8 oder 6                                                    | 
| Origin       | string  |              | Das Origin Feld im Protokoll                                                          |
| PingInterval | integer | 0            | In Sekunden, wann ein Ping an den Server gesendet wird                                |
| PingPayload  | string  |              | Die im Ping zu versendenen Daten                                                      |
| Frame        | integer | 1            | Format in welchen Daten versendet werden, wenn der Typ nicht bekannt ist (2 = binär)  |
| BasisAuth    | boolean | false        | true = Basis-Authentifizierung verwenden                                              |
| Username     | string  |              | Benutzername für die Authentifizierung                                                |
| Password     | string  |              | Passwort für die Authentifizierung                                                    |

## 8. Datenaustausch

**Datenempfang:**  
  Vom WebSocket-Client zur untergeordneten Instanz (ReceiveData im fremden Modul).  
  Die Datensätze werden erst nach dem Empfang eines Fin als ein Block weitergeleitet.  
  Der WebSocket-Client buffert die Daten eigenständig bis zum nächten Paket mit gesetzten Fin-Flag.  
  Ping/Pong Funktionalität sowie das manuelle schließen der Verbindung sind aktuell nicht vorgesehen.  

| Parameter    | Typ     | Beschreibung                                              |
| :----------: | :-----: | :-------------------------------------------------------: |
| DataID       | string  | {C51A4B94-8195-4673-B78D-04D91D52D2DD}                    |
| FrameTyp     | integer | 1 = text, 2 = binär                                       |
| Buffer       | string  | Payload                                                   |

  ![](imgs/IfWSC.png)  

**Datenversand:**  
  Von der untergeordneten Instanz zum WebSocket-Client (SendDataToParent im fremden Modul).  
  Es ist empfohlen nur den FrameTyp 1 & 2 in Verbindung mit Fin = true zu nutzen!  
  Die Instanz meldet True zurück, solange sie Verbunden ist.  
  
| Parameter    | Typ     | Beschreibung                                              |
| :----------: | :-----: | :-------------------------------------------------------: |
| DataID       | string  | {BC49DE11-24CA-484D-85AE-9B6F24D89321}                    |
| FrameTyp     | integer | 0 = continuation, 1 = text, 2 = binär                     |
| Fin          | bool    | true wenn Paket komplett, false wenn weitere Daten folgen | 
| Buffer       | string  | Payload                                                   |

  ![](imgs/IfWSC2.png)  

## 9. Anhang

**Changlog:**  

Version 1.1:  
 - In IPSNetwork-Library integriert

Version 1.0:  
 - Erstes offizielles Release

## 10. Lizenz

  IPS-Modul:  
  [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/)  

  Librarys:  
  **PHP-TLS**  
  https://github.com/rnaga/PHP-TLS  
    Copyright (c) 2016 Ryohei Nagatsuka    

  **Pure PHP Elliptic Curve Cryptography Library**  
  https://github.com/phpecc/phpecc  

  **Assert**  
  https://github.com/beberlei/assert  
    Copyright (c) 2011-2013, Benjamin Eberlei, All rights reserved.  

  **AES GCM (Galois Counter Mode) PHP Implementation**  
  https://github.com/Spomky-Labs/php-aes-gcm  
    Copyright (c) 2016 Spomky-Labs  
