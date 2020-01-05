<?php

// TODO KeepAlive defekt
require_once __DIR__ . '/../libs/NetworkTraits.php';
require_once __DIR__ . '/../libs/WebsocketClass.php';  // diverse Klassen


/*
 * @addtogroup network
 * @{
 *
 * @package       Network
 * @file          module.php
 * @author        Michael Tröger <micha@nall-chan.net>get
 * @copyright     2018 Michael Tröger
 * @license       https://creativecommons.org/licenses/by-nc-sa/4.0/ CC BY-NC-SA 4.0
 * @version       1.4
 */

/**
 * WebsocketServer Klasse implementiert das Websocket-Protokoll für einen ServerSocket.
 * Erweitert IPSModule.
 *
 * @author        Michael Tröger <micha@nall-chan.net>
 * @copyright     2018 Michael Tröger
 * @license       https://creativecommons.org/licenses/by-nc-sa/4.0/ CC BY-NC-SA 4.0
 *
 * @version       1.4
 *
 * @example <b>Ohne</b>
 *
 * @property WebSocket_ClientList $Multi_Clients
 * @property bool $UseTLS
 * @property bool $UsePlain
 * @property string {$ClientIP.$ClientPort}
 * @property string {"Buffer".$ClientIP.$ClientPort} Buffer für Nutzdaten
 * @property string {"BufferTLS".$ClientIP.$ClientPort} Buffer für TLS-Nutzdaten
 * @property TLS {"Multi_TLS_".$ClientIP.$ClientPort} TLS-Object
 * @property array {"BufferListe_Multi_TLS_".$ClientIP.$ClientPort}
 * @property string $CertData
 * @property string $KeyData
 * @property string $KeyPassword
 * @property int $ParentID
 * @property int $PingInterval
 * @property bool $NoNewClients
 */
class WebsocketServer extends IPSModule
{

    use DebugHelper,
        InstanceStatus,
        BufferHelper,
        Semaphore;
    /**
     * Interne Funktion des SDK.
     */
    public function Create()
    {
        parent::Create();
        $this->RequireParent('{8062CF2B-600E-41D6-AD4B-1BA66C32D6ED}');
        $this->Multi_Clients = new WebSocket_ClientList();
        $this->NoNewClients = true;
        $this->RegisterPropertyBoolean('Open', false);
        $this->RegisterPropertyInteger('Port', 8080);
        $this->RegisterPropertyInteger('Interval', 0);
        $this->RegisterPropertyString('URI', '/');
        $this->RegisterPropertyBoolean('BasisAuth', false);
        $this->RegisterPropertyString('Username', '');
        $this->RegisterPropertyString('Password', '');
        $this->RegisterPropertyBoolean('TLS', false);
        $this->RegisterPropertyBoolean('Plain', true);
        $this->RegisterPropertyString('CertFile', '');
        $this->RegisterPropertyString('KeyFile', '');
        $this->RegisterPropertyString('KeyPassword', '');
        $this->RegisterTimer('KeepAlivePing', 0, 'WSS_KeepAlive($_IPS[\'TARGET\']);');
    }

    /**
     * Interne Funktion des SDK.
     */
    public function MessageSink($TimeStamp, $SenderID, $Message, $Data)
    {
        switch ($Message) {
            case IPS_KERNELMESSAGE:
                if ($Data[0] != KR_READY) {
                    break;
                }
            case IPS_KERNELSTARTED:
                $this->ApplyChanges();
                break;
            case IPS_KERNELSHUTDOWN:
                $this->DisconnectAllClients();
                break;
            case FM_DISCONNECT:
                $this->NoNewClients = true;
                $this->RemoveAllClients();
                $this->RegisterParent();
                break;
            case FM_CONNECT:
                $this->ApplyChanges();
                break;
            case IM_CHANGESTATUS:
                if ($SenderID == $this->ParentID) {
                    if ($Data[0] == IS_ACTIVE) {
                        $this->NoNewClients = false;
                    } else {
                        $this->NoNewClients = true;
                        $this->RemoveAllClients();
                    }
                }
                break;
        }
    }

    /**
     * Interne Funktion des SDK.
     */
    public function GetConfigurationForm()
    {
        $data = json_decode(file_get_contents(__DIR__ . '/form.json'));
        if ((float) IPS_GetKernelVersion() < 4.2) {
            $data->elements[8]->type = 'ValidationTextBox';
            $data->elements[8]->caption = 'Path to certificate';
            unset($data->elements[8]->extensions);
            $data->elements[9]->type = 'ValidationTextBox';
            $data->elements[9]->caption = 'Path to private key';
            unset($data->elements[9]->extensions);
        }
        return json_encode($data);
    }

    /**
     * Interne Funktion des SDK.
     */
    public function GetConfigurationForParent()
    {
        $Config['Port'] = $this->ReadPropertyInteger('Port');
        $Config['Open'] = $this->ReadPropertyBoolean('Open');
        return json_encode($Config);
    }

    /**
     * Interne Funktion des SDK.
     */
    public function ApplyChanges()
    {
        $this->NoNewClients = true;

        if ((float) IPS_GetKernelVersion() < 4.2) {
            $this->RegisterMessage(0, IPS_KERNELMESSAGE);
        } else {
            $this->RegisterMessage(0, IPS_KERNELSTARTED);
            $this->RegisterMessage(0, IPS_KERNELSHUTDOWN);
        }

        $this->RegisterMessage($this->InstanceID, FM_CONNECT);
        $this->RegisterMessage($this->InstanceID, FM_DISCONNECT);

        if (IPS_GetKernelRunlevel() != KR_READY) {
            return;
        }

        $this->SetTimerInterval('KeepAlivePing', 0);

        $OldParentID = $this->ParentID;
        if ($this->HasActiveParent() and ( $OldParentID > 0)) {
            $this->DisconnectAllClients();
        }

        parent::ApplyChanges();

        $NewState = IS_ACTIVE;
        $this->UseTLS = $this->ReadPropertyBoolean('TLS');
        $this->UsePlain = $this->ReadPropertyBoolean('Plain');
        //$this->SendDebug('UsePlain', ($this->UsePlain ? "true" : "false"), 0);
        //$this->SendDebug('UseTLS', ($this->UseTLS ? "true" : "false"), 0);
        if ($this->UseTLS) {
            $basedir = IPS_GetKernelDir() . 'cert';
            if (!file_exists($basedir)) {
                mkdir($basedir);
            }
            if (($this->ReadPropertyString('CertFile') == '') and ( $this->ReadPropertyString('KeyFile') == '')) {
                return $this->CreateNewCert($basedir);
            }

            try {
                if ((float) IPS_GetKernelVersion() < 4.2) {
                    $CertFile = @file_get_contents($this->ReadPropertyString('CertFile'));
                    $KeyFile = @file_get_contents($this->ReadPropertyString('KeyFile'));
                } else {
                    //Convert old settings
                    $CertFile = $this->ReadPropertyString('CertFile');
                    $KeyFile = $this->ReadPropertyString('KeyFile');
                    if (is_file($CertFile)) {
                        IPS_SetProperty($this->InstanceID, 'CertFile', @file_get_contents($this->ReadPropertyString('CertFile')));
                    }
                    if (is_file($KeyFile)) {
                        IPS_SetProperty($this->InstanceID, 'KeyFile', @file_get_contents($this->ReadPropertyString('KeyFile')));
                    }
                    if (IPS_HasChanges($this->InstanceID)) {
                        IPS_ApplyChanges($this->InstanceID);
                        return;
                    }

                    // Read new settings
                    $CertFile = base64_decode($CertFile);
                    $KeyFile = base64_decode($KeyFile);
                }

                if ($CertFile) {
                    $this->CertData = 'data://text/plain;base64,' . base64_encode($CertFile);
                } else {
                    throw new Exception('Certificate missing or not found');
                }

                if ($KeyFile) {
                    $this->KeyData = 'data://text/plain;base64,' . base64_encode($KeyFile);
                } else {
                    throw new Exception('Private key missing or not found');
                }

//                if (strlen($this->ReadPropertyString("KeyPassword")) == 0)
//                    throw new Exception('Password for private key missing');

                $this->KeyPassword = $this->ReadPropertyString('KeyPassword');
            } catch (Exception $exc) {
                echo $this->Translate($exc->getMessage());
                $this->UseTLS = false;
                $NewState = IS_EBASE + 1;
            }
        }

        $Open = $this->ReadPropertyBoolean('Open');
        $Port = $this->ReadPropertyInteger('Port');
        $this->PingInterval = $this->ReadPropertyInteger('Interval');
        if (!$Open) {
            $NewState = IS_INACTIVE;
        } else {
            if (($Port < 1) or ( $Port > 65535)) {
                $NewState = IS_EBASE + 2;
                $Open = false;
                trigger_error($this->Translate('Port invalid'), E_USER_NOTICE);
            } else {
                if (($this->PingInterval != 0) and ( $this->PingInterval < 5)) {
                    $this->PingInterval = 0;
                    $NewState = IS_EBASE + 4;
                    $Open = false;
                    trigger_error($this->Translate('Ping interval to small'), E_USER_NOTICE);
                }
            }
        }
        $ParentID = $this->RegisterParent();

        // Zwangskonfiguration des ServerSocket
        if ($ParentID > 0) {
            if (IPS_GetProperty($ParentID, 'Port') != $Port) {
                IPS_SetProperty($ParentID, 'Port', $Port);
            }
            if (IPS_GetProperty($ParentID, 'Open') != $Open) {
                IPS_SetProperty($ParentID, 'Open', $Open);
            }
            if (IPS_HasChanges($ParentID)) {
                @IPS_ApplyChanges($ParentID);
            }
        } else {
            if ($Open) {
                $NewState = IS_INACTIVE;
                $Open = false;
            }
        }

        if ($Open && !$this->HasActiveParent($ParentID)) {
            $NewState = IS_EBASE + 2;
        }

        $this->SetStatus($NewState);
        $this->NoNewClients = false;
    }

    //################# PRIVATE
    /**
     * Erzeugt ein selbst-signiertes Zertifikat.
     *
     * @param string $basedir Der Speicherort der Zertifikate.
     *
     * @return bool True bei Erflog, sonst false
     */
    private function CreateNewCert(string $basedir)
    {
        $CN = 'IPSymcon';
        $EMAIL = IPS_GetLicensee();
        $basedir .= DIRECTORY_SEPARATOR . $this->InstanceID;
        $configfile = $basedir . '.cnf';
        $certfile = $basedir . '.cer';
        $keyfile = $basedir . '.key';
        $newLine = "\r\n";

        $strCONFIG = 'default_md = sha256' . $newLine;
        $strCONFIG .= 'default_days = 3650' . $newLine;
        $strCONFIG .= $newLine;
        $strCONFIG .= 'x509_extensions = x509v3' . $newLine;
        $strCONFIG .= '[ req ]' . $newLine;
        $strCONFIG .= 'default_bits = 2048' . $newLine;
        $strCONFIG .= 'distinguished_name = req_DN' . $newLine;
        $strCONFIG .= 'string_mask = nombstr' . $newLine;
        $strCONFIG .= 'prompt = no' . $newLine;
        $strCONFIG .= 'req_extensions = v3_req' . $newLine;
        $strCONFIG .= $newLine;
        $strCONFIG .= '[ req_DN ]' . $newLine;
        $strCONFIG .= 'countryName = DE' . $newLine;
        $strCONFIG .= 'stateOrProvinceName = none' . $newLine;
        $strCONFIG .= 'localityName = none' . $newLine;
        $strCONFIG .= '0.organizationName = "Home"' . $newLine;
        $strCONFIG .= 'organizationalUnitName  = "IPS"' . $newLine;
        $strCONFIG .= 'commonName = ' . $CN . $newLine;
        $strCONFIG .= 'emailAddress = ' . $EMAIL . $newLine;
        $strCONFIG .= $newLine;
        $strCONFIG .= '[ v3_req ]' . $newLine;
        $strCONFIG .= 'basicConstraints=CA:FALSE' . $newLine;
        $strCONFIG .= 'subjectKeyIdentifier=hash' . $newLine;
        $strCONFIG .= $newLine;
        $strCONFIG .= '[ x509v3 ]' . $newLine;
        $strCONFIG .= 'basicConstraints=CA:FALSE' . $newLine;
        $strCONFIG .= 'nsCertType       = server' . $newLine;
        $strCONFIG .= 'keyUsage         = digitalSignature,nonRepudiation,keyEncipherment' . $newLine;
        $strCONFIG .= 'extendedKeyUsage = msSGC,nsSGC,serverAuth' . $newLine;
        $strCONFIG .= 'subjectKeyIdentifier=hash' . $newLine;
        $strCONFIG .= 'authorityKeyIdentifier=keyid,issuer:allways' . $newLine;
        $strCONFIG .= 'issuerAltName = issuer:copy' . $newLine;
        $strCONFIG .= 'subjectAltName = IP:192.168.201.34' . $newLine;
        $strCONFIG .= $newLine;
//        $strCONFIG .= '[alt_names]' . $newLine;
//        $strCONFIG .= 'email = '.$EMAIL . $newLine;
//        $strCONFIG .= 'IP = 192.168.201.34' . $newLine;
//        $strCONFIG .= $newLine;

        $fp = fopen($configfile, 'w');
        fwrite($fp, $strCONFIG);
        fclose($fp);

        $dn = [
            'countryName'            => 'DE',
            'stateOrProvinceName'    => 'none',
            'localityName'           => 'none',
            'organizationName'       => 'Home',
            'organizationalUnitName' => 'IPS',
            'commonName'             => "$CN",
            'emailAddress'           => "$EMAIL"
        ];

        $config = [
            'config'      => "$configfile",
            'encrypt_key' => true];

        $configKey = [
            'config'           => "$configfile",
            'encrypt_key'      => true,
            'digest_alg'       => 'sha512',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
        $pk = openssl_pkey_new($configKey);
        openssl_pkey_export($pk, $pkexport, 'Symcon', $config);
        if ((float) IPS_GetKernelVersion() < 4.2) {
            $fp = fopen($keyfile, 'w');
            fwrite($fp, $pkexport);
            fclose($fp);
            IPS_SetProperty($this->InstanceID, 'KeyFile', $basedir . '.key');
        } else {
            IPS_SetProperty($this->InstanceID, 'KeyFile', base64_encode($pkexport));
        }

        $csr = openssl_csr_new($dn, $pk, $config);
        if ($csr) {
            $cert = openssl_csr_sign($csr, null, $pk, 730, $config);
            if ($cert) {
                openssl_x509_export($cert, $certout);
                if ((float) IPS_GetKernelVersion() < 4.2) {
                    $fp = fopen($certfile, 'w');
                    fwrite($fp, $certout);
                    fclose($fp);
                    IPS_SetProperty($this->InstanceID, 'CertFile', $basedir . '.cer');
                } else {
                    IPS_SetProperty($this->InstanceID, 'CertFile', base64_encode($certout));
                }
            } else {
                unlink($configfile);
                return false;
            }
        } else {
            unlink($configfile);
            return false;
        }
        unlink($configfile);
        IPS_SetProperty($this->InstanceID, 'KeyPassword', 'Symcon');
        IPS_ApplyChanges($this->InstanceID);
        return true;
    }

    /**
     * Wertet den Handshake des Clients aus.
     *
     * @param string $Data Die Daten des Clients.
     *
     * @return bool|HTTP_ERROR_CODES True bei Erfolg, HTTP_ERROR_CODES bei Fehler, false wenn nicht genug Daten.
     */
    private function ReceiveHandshake(string $Data)
    {
        $this->SendDebug('Receive Handshake', $Data, 0);
        if (preg_match("/^GET ?([^?#]*) HTTP\/1.1\r\n/", $Data, $match)) {
            if (substr($Data, -4) != "\r\n\r\n") {
                $this->SendDebug('WAIT', $Data, 0);
                return false;
            }

            if (trim($match[1]) != trim($this->ReadPropertyString('URI'))) {
                $this->SendDebug('Wrong URI requested', $Data, 0);
                return HTTP_ERROR_CODES::Not_Found;
            }

            if ($this->ReadPropertyBoolean('BasisAuth')) {
                $realm = base64_encode($this->ReadPropertyString('Username') . ':' . $this->ReadPropertyString('Password'));
                if (preg_match("/Authorization: Basic (.*)\r\n/", $Data, $match)) {
                    if ($match[1] != $realm) {
                        $this->SendDebug('Unauthorized Connection:', base64_decode($match[1]), 0);
                        return HTTP_ERROR_CODES::Forbidden;
                    }
                } else {
                    $this->SendDebug('Authorization missing', '', 0);
                    return HTTP_ERROR_CODES::Unauthorized;
                }
            }
            if (preg_match("/Connection: (.*)\r\n/", $Data, $match)) {
                if (strtolower($match[1]) != 'upgrade') {
                    $this->SendDebug('WRONG Connection:', $match[1], 0);
                    return HTTP_ERROR_CODES::Method_Not_Allowed;
                }
            } else {
                $this->SendDebug('MISSING', 'Connection: Upgrade', 0);
                return HTTP_ERROR_CODES::Bad_Request;
            }

            if (preg_match("/Upgrade: (.*)\r\n/", $Data, $match)) {
                if (strtolower($match[1]) != 'websocket') {
                    $this->SendDebug('WRONG Upgrade:', $match[1], 0);
                    return HTTP_ERROR_CODES::Method_Not_Allowed;
                }
            } else {
                $this->SendDebug('MISSING', 'Upgrade: websocket', 0);
                return HTTP_ERROR_CODES::Bad_Request;
            }

            if (preg_match("/Sec-WebSocket-Version: (.*)\r\n/", $Data, $match)) {
                if (strpos($match[1], '13') === false) {
                    $this->SendDebug('WRONG Version:', $match[1], 0);
                    return HTTP_ERROR_CODES::Not_Acceptable;
                }
            } else {
                $this->SendDebug('MISSING', 'Sec-WebSocket-Version', 0);
                return HTTP_ERROR_CODES::Bad_Request;
            }

            if (!preg_match("/Sec-WebSocket-Key: (.*)\r\n/", $Data, $match)) {
                $this->SendDebug('MISSING', 'Sec-WebSocket-Key', 0);
                return HTTP_ERROR_CODES::Bad_Request;
            }

            return true;
        }
        $this->SendDebug('Invalid HTTP-Request', $Data, 0);

        return HTTP_ERROR_CODES::Bad_Request;
    }

    /**
     * Sendet den HTTP-Response an den Client.
     *
     * @param HTTP_ERROR_CODES $Code   Der HTTP Code welcher versendet werden soll.
     * @param string           $Data   Die empfangenen Daten des Clients.
     * @param Websocket_Client $Client Der Client vom welchen die Daten empfangen wurden.
     */
    private function SendHandshake(int $Code, string $Data, Websocket_Client $Client)
    {
        preg_match("/Sec-WebSocket-Key: (.*)\r\n/", $Data, $match);
        $SendKey = base64_encode(sha1($match[1] . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));

        $Header[] = 'HTTP/1.1 ' . HTTP_ERROR_CODES::ToString($Code);
        if ($Code == HTTP_ERROR_CODES::Unauthorized) {
            $Header[] = 'WWW-Authenticate: Basic';
        }
        //$Header[] = 'Date: '; // Datum fehlt !
        $Header[] = 'Server: IP-Symcon Websocket Gateway';
        if ($Code == HTTP_ERROR_CODES::Web_Socket_Protocol_Handshake) {
            $Header[] = 'Connection: Upgrade';
            $Header[] = 'Sec-WebSocket-Accept: ' . $SendKey;
            $Header[] = 'Upgrade: websocket';
            $Header[] = "\r\n";
            $SendHeader = implode("\r\n", $Header);
        } else {
            $Header[] = 'Content-Length:' . strlen(HTTP_ERROR_CODES::ToString($Code));
            $Header[] = "\r\n";
            $SendHeader = implode("\r\n", $Header) . HTTP_ERROR_CODES::ToString($Code);
        }

        $this->SendDebug('SendHandshake ' . $Client->ClientIP . ':' . $Client->ClientPort, $SendHeader, 0);
        $SendData = $this->MakeJSON($Client, $SendHeader);
        if ($SendData) {
            $this->SendDataToParent($SendData);
        }
    }

    /**
     * Erzeugt aus einen Datenframe ein JSON für den Datenaustausch mit dem IO.
     *
     * @param Websocket_Client $Client Der Client an welchen die Daten gesendet werden.
     * @param string           $Data   Die Nutzdaten
     * @param type             $UseTLS Bei false wird TLS nicht benutzt, auch wenn der Client dies erwartet.
     *
     * @return bool|string Der JSON-String zum versand an den IO, im Fehlerfall false.
     */
    private function MakeJSON(Websocket_Client $Client, string $Data, $UseTLS = true, int $Type = SocketType::Data)
    {
        if ($Type == SocketType::Data) {
            if ($UseTLS and $Client->UseTLS) {
                $this->SendDebug('Send TLS', $Data, 0);

                try {
                    $this->lock($Client->ClientIP . $Client->ClientPort);
                    $TLS = $this->{'Multi_TLS_' . $Client->ClientIP . $Client->ClientPort};
                    $Send = $TLS->output($Data)->decode();
                    $this->{'Multi_TLS_' . $Client->ClientIP . $Client->ClientPort} = $TLS;
                    $this->unlock($Client->ClientIP . $Client->ClientPort);
                } catch (Exception $exc) {
                    return false;
                }
                $Data = $Send;
            }
            $this->SendDebug('Send', $Data, 0);
        } else {
            $this->SendDebug('Send', SocketType::ToString($Type), 0);
        }
        $SendData['DataID'] = '{C8792760-65CF-4C53-B5C7-A30FCC84FEFE}';
        $SendData['Buffer'] = utf8_encode($Data);
        $SendData['ClientIP'] = $Client->ClientIP;
        $SendData['ClientPort'] = $Client->ClientPort;
        $SendData['Type'] = $Type;
        return json_encode($SendData);
    }

    /**
     * Dekodiert die empfangenen Daten und sendet sie an die Childs.
     *
     * @param WebSocketFrame   $Frame  Ein Objekt welches einen kompletten Frame enthält.
     * @param Websocket_Client $Client Der Client von welchem die Daten empfangen wurden.
     */
    private function DecodeFrame(WebSocketFrame $Frame, Websocket_Client $Client)
    {
        $this->SendDebug('DECODE', $Frame, ($Frame->OpCode == WebSocketOPCode::continuation) ? $this->PayloadTyp - 1 : $Frame->OpCode - 1);
        switch ($Frame->OpCode) {
            case WebSocketOPCode::ping:
                $this->SendPong($Client, $Frame->Payload);
                return;
            case WebSocketOPCode::close:
                $this->SendDebug('Receive', 'Client send stream close !', 0);
                $Client->State = WebSocketState::CloseReceived;
                $this->SendDisconnect($Client);
                $this->SendDataToChilds('', $Client); // RAW Childs
                return;
            case WebSocketOPCode::text:
            case WebSocketOPCode::binary:
                $this->{'OpCode' . $Client->ClientIP . $Client->ClientPort} = $Frame->OpCode;
                $Data = $Frame->Payload;
                break;
            case WebSocketOPCode::continuation:
                $Data = $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} . $Frame->Payload;
                break;
            case WebSocketOPCode::pong:
                $this->{'Pong' . $Client->ClientIP . $Client->ClientPort} = $Frame->Payload;
                $this->{'WaitForPong' . $Client->ClientIP . $Client->ClientPort} = true;
                $JSON['DataID'] = '{8F1F6C32-B1AD-4B7F-8DFB-1244A96FCACF}';
                $JSON['Buffer'] = utf8_encode($Frame->Payload);
                $JSON['ClientIP'] = $Client->ClientIP;
                $JSON['ClientPort'] = $Client->ClientPort;
                $JSON['FrameTyp'] = WebSocketOPCode::pong;
                $Data = json_encode($JSON);
                $this->SendDataToChildren($Data);
                return;
        }

        if ($Frame->Fin) {
            $this->SendDataToChilds($Data, $Client); // RAW Childs
        } else {
            $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} = $Data;
        }
    }

    /**
     * Setzt den Intervall des Timer auf den nächsten Timeout eines Client.
     */
    private function SetNextTimer()
    {
        $this->SetTimerInterval('KeepAlivePing', 0);
        $Clients = $this->Multi_Clients;
        $Client = $Clients->GetNextTimeout($this->PingInterval + 1);
        $this->SendDebug('NextTimeout', $Client, 0);
        if ($Client === false) {
            $next = 0;
        } else {
            $next = $Client->Timestamp - time();
            if ($next == 0) {
                $next = 0.001;
            }
            if ($next < 0) {
                $next = 0;
            }
        }
        $this->SendDebug('TIMER NEXT', $next, 0);
        $this->SetTimerInterval('KeepAlivePing', $next * 1000);
    }

    /**
     * Sendet einen Pong an einen Client.
     *
     * @param Websocket_Client $Client  Der Client an welchen das Pong versendet wird.
     * @param string           $Payload Der Payloaf des Pong.
     */
    private function SendPong(Websocket_Client $Client, string $Payload = null)
    {
        $this->Send($Payload, WebSocketOPCode::pong, $Client);
    }

    /**
     * Sendet ein Connection Close an alle Clients.
     */
    private function DisconnectAllClients()
    {
        $this->SetTimerInterval('KeepAlivePing', 0);
        $Clients = $this->Multi_Clients;
        foreach ($Clients->GetClients() as $Client) {
            $this->SendDisconnect($Client);
        }
        $this->Multi_Clients = new WebSocket_ClientList();
    }

    /**
     * Sendet einen Close an einen Client und löscht alle Buffer dieses Clients.
     *
     * @param Websocket_Client $Client Der Client an welchen das Close gesendet wird.
     *
     * @return bool True bei Erfolg, sonst false.
     */
    private function SendDisconnect(Websocket_Client $Client)
    {
        $ret = false;
        if ($Client->State == WebSocketState::CloseReceived) {
            $ret = true;
            $this->SendDebug('Send', 'Answer Client stream close !', 0);
            $this->Send('', WebSocketOPCode::close, $Client);
        }
        if ($Client->State == WebSocketState::Connected) {
            $this->SendDebug('Send', 'Server send stream close !', 0);
            $Clients = $this->Multi_Clients;
            $Client->State = WebSocketState::CloseSend;
            $Clients->Update($Client);
            $this->Multi_Clients = $Clients;
            $this->Send('', WebSocketOPCode::close, $Client);
            $ret = $this->WaitForClose($Client);
            $this->CloseConnection($Client);
        }
        $this->RemoveOneClient($Client);

        return $ret;
    }

    private function RemoveOneClient(Websocket_Client $Client)
    {
        $this->ClearClientBuffer($Client);
        $Clients = $this->Multi_Clients;
        $Clients->Remove($Client);
        $this->Multi_Clients = $Clients;
        $this->SetNextTimer();
    }

    /**
     * Leert die ClientListe und alle entsprechenden Buffer der Clients.
     */
    private function RemoveAllClients()
    {
        $Clients = $this->Multi_Clients;
        foreach ($Clients->GetClients() as $Client) {
            $this->ClearClientBuffer($Client);
        }
        $this->Multi_Clients = new WebSocket_ClientList();
    }

    /**
     * Leert die entsprechenden Buffer eines Clients.
     *
     * @param Websocket_Client $Client Der zu löschende Client.
     */
    private function ClearClientBuffer(Websocket_Client $Client)
    {
        $this->SetBuffer('OpCode' . $Client->ClientIP . $Client->ClientPort, '');
        $this->SetBuffer('Buffer' . $Client->ClientIP . $Client->ClientPort, '');
        $this->SetBuffer('Pong' . $Client->ClientIP . $Client->ClientPort, '');
        $this->SetBuffer('WaitForPong' . $Client->ClientIP . $Client->ClientPort, '');
        $this->SetBuffer('WaitForClose' . $Client->ClientIP . $Client->ClientPort, '');
        $this->{'Multi_TLS_' . $Client->ClientIP . $Client->ClientPort} = '';
        $this->SetBuffer('BufferListe_Multi_TLS_' . $Client->ClientIP . $Client->ClientPort, '');
    }

    /**
     * Wartet auf eine Handshake-Antwort.
     *
     * @param Websocket_Client $Client
     *
     * @return string|bool Der Payload des Pong, oder im Fehlerfall false.
     */
    private function WaitForPong(Websocket_Client $Client)
    {
        for ($i = 0; $i < 500; $i++) {
            if ($this->{'WaitForPong' . $Client->ClientIP . $Client->ClientPort} === true) {
                $Payload = $this->{'Pong' . $Client->ClientIP . $Client->ClientPort};
                $this->{'Pong' . $Client->ClientIP . $Client->ClientPort} = '';
                $this->{'WaitForPong' . $Client->ClientIP . $Client->ClientPort} = false;
                return $Payload;
            }
            IPS_Sleep(5);
        }
        return false;
    }

    /**
     * Wartet auf eine Close-Antwort eines Clients.
     *
     * @param Websocket_Client $Client
     *
     * @return bool True bei Erfolg, sonst false.
     */
    private function WaitForClose(Websocket_Client $Client)
    {
        for ($i = 0; $i < 500; $i++) {
            if ($this->{'WaitForClose' . $Client->ClientIP . $Client->ClientPort} === true) {
                $this->{'WaitForClose' . $Client->ClientIP . $Client->ClientPort} = false;
                return true;
            }
            IPS_Sleep(5);
        }
        return false;
    }

    /**
     * Versendet RawData mit OpCode an den IO.
     *
     * @param string           $RawData Das zu sende Payload
     * @param WebSocketOPCode  $OPCode  Der zu benutzende OPCode
     * @param Websocket_Client $Client  Der Client an welchen die Daten gesendet werden sollen.
     * @param bool             $Fin     True wenn Ende von Payload erreicht.
     */
    private function Send(string $RawData, int $OPCode, Websocket_Client $Client, $Fin = true)
    {
        $WSFrame = new WebSocketFrame($OPCode, $RawData);
        $WSFrame->Fin = $Fin;
        $Frame = $WSFrame->ToFrame();
        $this->SendDebug('Send', $WSFrame, 0);
        $SendData = $this->MakeJSON($Client, $Frame);
        if ($SendData) {
            $this->SendDataToParent($SendData);
        }
    }

    //################# DATAPOINTS CHILDS
    /**
     * Interne Funktion des SDK. Nimmt Daten von Childs entgegen und sendet Diese weiter.
     *
     * @param string $JSONString
     * @result bool true wenn Daten gesendet werden konnten, sonst false.
     */
    public function ForwardData($JSONString)
    {
        $Data = json_decode($JSONString);
        if ($Data->DataID == '{79827379-F36E-4ADA-8A95-5F8D1DC92FA9}') {
            $this->SendDebug('Forward Broadcast', utf8_decode($Data->Buffer), 0);
            $Clients = $this->Multi_Clients;
            foreach ($Clients as $Client) {
                $Data->FrameTyp = $this->{'OpCode' . $Client->ClientIP . $Client->ClientPort};
                $Data->Fin = true;
                $this->Send(utf8_decode($Data->Buffer), $Data->FrameTyp, $Client, $Data->Fin);
            }
            return true;
        }

        $Client = $this->Multi_Clients->GetByIpPort(new Websocket_Client($Data->ClientIP, $Data->ClientPort));
        if ($Client === false) {
            trigger_error($this->Translate('Unknow client') . ': ' . $Data->ClientIP . ':' . $Data->ClientPort, E_USER_NOTICE);
            return false;
        }
        if ($Client->State != WebSocketState::Connected) {
            trigger_error($this->Translate('Client not connected') . ': ' . $Data->ClientIP . ':' . $Data->ClientPort, E_USER_NOTICE);
            return false;
        }
        $this->SendDebug('Forward', utf8_decode($Data->Buffer), 0);

        if ($Data->DataID == '{714B71FB-3D11-41D1-AFAC-E06F1E983E09}') {
            if ($Data->FrameTyp == WebSocketOPCode::close) {
                return $this->SendDisconnect($Client);
            }
            if ($Data->FrameTyp == WebSocketOPCode::ping) {
                return $this->SendPing($Client->ClientIP, $Client->ClientPort, utf8_decode($Data->Buffer));
            }
            if (($Data->FrameTyp < 0) || ($Data->FrameTyp > 2)) {
                trigger_error($this->Translate('FrameTyp invalid') . ': ' . $Data->ClientIP . ':' . $Data->ClientPort, E_USER_NOTICE);
                return false;
            }
        } else { //{C8792760-65CF-4C53-B5C7-A30FCC84FEFE}
            if (property_exists($Data, 'Type')) {
                if ($Data->Type == 2) {
                    return $this->SendDisconnect($Client);
                }
            }
            //Type fehlt
            $Data->FrameTyp = $this->{'OpCode' . $Client->ClientIP . $Client->ClientPort};
            $Data->Fin = true;
        }

        $this->Send(utf8_decode($Data->Buffer), $Data->FrameTyp, $Client, $Data->Fin);
        return true;
    }

    /**
     * Sendet die Rohdaten an die Childs.
     *
     * @param string           $RawData Die Nutzdaten.
     * @param Websocket_Client $Client  Der Client von welchem die Daten empfangen wurden.
     */
    private function SendDataToChilds(string $RawData, Websocket_Client $Client)
    {
        $JSON['DataID'] = '{7A1272A4-CBDB-46EF-BFC6-DCF4A53D2FC7}'; //ServerSocket Receive
        $JSON['Buffer'] = utf8_encode($RawData);
        $JSON['ClientIP'] = $Client->ClientIP;
        $JSON['ClientPort'] = $Client->ClientPort;
        $JSON['Type'] = 0; // Data
        if ($Client->State == WebSocketState::Connected) {
            $JSON['Type'] = 1; // Connected
        }
        if ($Client->State == WebSocketState::CloseReceived) {
            $JSON['Type'] = 2; // Disconnected
        }
        $Data = json_encode($JSON);
        $this->SendDataToChildren($Data);
        $JSON['DataID'] = '{8F1F6C32-B1AD-4B7F-8DFB-1244A96FCACF}';
        $JSON['FrameTyp'] = $this->{'OpCode' . $Client->ClientIP . $Client->ClientPort};
        if ($Client->State == WebSocketState::HandshakeReceived) {
            $JSON['FrameTyp'] = WebSocketOPCode::continuation; // Connected
        }
        if ($Client->State == WebSocketState::CloseReceived) {
            $JSON['FrameTyp'] = WebSocketOPCode::close; // Disconnected
        }
        $Data = json_encode($JSON);
        $this->SendDataToChildren($Data);
    }

    private function SplitTLSFrames(string &$Payload)
    {
        $Frames = [];
        while (strlen($Payload) > 0) {
            $len = unpack('n', substr($Payload, 3, 2))[1] + 5;
            if (strlen($Payload) >= $len) {
                $this->SendDebug('Receive TLS Frame', substr($Payload, 0, $len), 0);
                $Frames[] = substr($Payload, 0, $len);
                $Payload = substr($Payload, $len);
            } else {
                break;
            }
        }
        return $Frames;
    }

    private function ProcessIncomingData(Websocket_Client &$Client, string $Payload)
    {
        $this->SendDebug('Receive ' . $Client->ClientIP . ':' . $Client->ClientPort, $Payload, 0);
        if ($Client->State == WebSocketState::init) { //new
            if ($this->UseTLS and ( (ord($Payload[0]) >= 0x14) && (ord($Payload[0]) <= 0x18) && (ord($Payload[1]) == 0x03))) { //valid header wenn TLS is active
                $Client->State = WebSocketState::TLSisReceived;
                $Client->UseTLS = true;
                $this->{'BufferTLS' . $Client->ClientIP . $Client->ClientPort} = '';
                $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} = '';
                // TLS Config
                $TLSconfig = \PTLS\TLSContext::getServerConfig([
                            'key_pair_files' => [
                                'cert' => [$this->CertData],
                                'key'  => [$this->KeyData, $this->KeyPassword]
                            ]
                ]);
                $this->SendDebug('NEW TLSContex', '', 0);
                //$this->lock($Client->ClientIP . $Client->ClientPort);
                $this->lock($Client->ClientIP . $Client->ClientPort);
                $TLS = \PTLS\TLSContext::createTLS($TLSconfig);
            }
            if ($this->UsePlain and ( preg_match("/^GET ?([^?#]*) HTTP\/1.1\r\n/", $Payload, $match))) { //valid header wenn Plain is active
                $Client->State = WebSocketState::HandshakeReceived;
                $Client->UseTLS = false;
                $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} = '';
            }
        } else {
            if ($Client->UseTLS) {
                $this->SendDebug('OLD TLSContex', '', 0);
                $this->lock($Client->ClientIP . $Client->ClientPort);
                $TLS = $this->{'Multi_TLS_' . $Client->ClientIP . $Client->ClientPort};
            }
        }
        if ($Client->UseTLS) {
            $Payload = $this->{'BufferTLS' . $Client->ClientIP . $Client->ClientPort} .= $Payload;
            if ((ord($Payload[0]) >= 0x14) && (ord($Payload[0]) <= 0x18) && (ord($Payload[1]) == 0x03)) {
                $TLSFrames = $this->SplitTLSFrames($Payload);
                $this->{'BufferTLS' . $Client->ClientIP . $Client->ClientPort} = $Payload;
                $Payload = '';

                foreach ($TLSFrames as $TLSFrame) {
                    $this->SendDebug('TLS Frame', $TLSFrame, 0);
                    if ($Client->State != WebSocketState::TLSisReceived) {
                        $TLS->encode($TLSFrame);
                        $Payload .= $TLS->input();
                        continue;
                    }
                    if ($Client->State == WebSocketState::TLSisReceived) {
                        try {
                            $TLS->encode($TLSFrame);
                        } catch (\PTLS\Exceptions\TLSAlertException $e) {
                            if (strlen($out = $e->decode())) {
                                $this->SendDebug('Send TLS Handshake error', $out, 0);
                                $SendData = $this->MakeJSON($Client, $out, false);
                                if ($SendData) {
                                    $this->SendDataToParent($SendData);
                                }
                            }
                            $this->SendDebug('Send TLS Handshake error', $e->getMessage(), 0);
                            trigger_error($e->getMessage(), E_USER_NOTICE);
                            $this->{'Multi_TLS_' . $Client->ClientIP . $Client->ClientPort} = '';
                            $this->unlock($Client->ClientIP . $Client->ClientPort);
                            $this->CloseConnection($Client);
                            return;
                        } catch (\PTLS\Exceptions\TLSException $e) {
                            $this->SendDebug('Send TLS Handshake error', $e->getMessage(), 0);
                            trigger_error($e->getMessage(), E_USER_NOTICE);
                            $this->{'Multi_TLS_' . $Client->ClientIP . $Client->ClientPort} = '';
                            $this->unlock($Client->ClientIP . $Client->ClientPort);
                            $this->CloseConnection($Client);
                            return;
                        }

                        try {
                            $out = $TLS->decode();
                        } catch (\PTLS\Exceptions\TLSException $e) {
                            trigger_error($e->getMessage(), E_USER_NOTICE);
                            $this->{'Multi_TLS_' . $Client->ClientIP . $Client->ClientPort} = '';
                            $this->unlock($Client->ClientIP . $Client->ClientPort);
                            $this->CloseConnection($Client);
                            return;
                        }
                        if (strlen($out)) {
                            $this->SendDebug('Send TLS Handshake', $out, 0);
                            $SendData = $this->MakeJSON($Client, $out, false);
                            if ($SendData) {
                                $this->SendDataToParent($SendData);
                            }
                        }
                        if ($TLS->isHandshaked()) {
                            $Client->State = WebSocketState::HandshakeReceived;
                            $this->SendDebug('TLS ProtocolVersion', $TLS->getDebug()->getProtocolVersion(), 0);
                            $UsingCipherSuite = explode("\n", $TLS->getDebug()->getUsingCipherSuite());
                            unset($UsingCipherSuite[0]);
                            foreach ($UsingCipherSuite as $Line) {
                                $this->SendDebug(trim(substr($Line, 0, 14)), trim(substr($Line, 15)), 0);
                            }
                        }
                    }
                }
                $this->{'Multi_TLS_' . $Client->ClientIP . $Client->ClientPort} = $TLS;
                $this->unlock($Client->ClientIP . $Client->ClientPort);
            } else { // Anfang (inkl. Buffer) paßt nicht
                $this->{'BufferTLS' . $Client->ClientIP . $Client->ClientPort} = '';
                $this->{'Multi_TLS_' . $Client->ClientIP . $Client->ClientPort} = '';
                $this->unlock($Client->ClientIP . $Client->ClientPort);
                $this->CloseConnection($Client);
                return; // nix sichern
            }
        }

        if (strlen($Payload) == 0) {
            return;
        }

        if ($Client->State == WebSocketState::HandshakeReceived) {
            $NewData = $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} . $Payload;
            $CheckData = $this->ReceiveHandshake($NewData);
            if ($CheckData === true) { // Daten komplett und heil.
                $this->SendHandshake(HTTP_ERROR_CODES::Web_Socket_Protocol_Handshake, $NewData, $Client); //Handshake senden
                $this->SendDebug('SUCCESSFULLY CONNECT', $Client, 0);
                $this->SendDataToChilds('', $Client);
                $Client->State = WebSocketState::Connected; // jetzt verbunden
                $Client->Timestamp = time() + $this->ReadPropertyInteger('Interval');
            } elseif ($CheckData === false) { // Daten nicht komplett, buffern.
                $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} = $CheckData;
            } else { // Daten komplett, aber defekt.
                $this->SendHandshake($CheckData, $NewData, $Client);
                $this->CloseConnection($Client);
            }
        } elseif ($Client->State == WebSocketState::Connected) { // bekannt und verbunden
            $NewData = $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} . $Payload;
            $this->SendDebug('ReceivePacket ' . $Client->ClientIP . $Client->ClientPort, $NewData, 1);
            while (true) {
                if (strlen($NewData) < 2) {
                    break;
                }
                $Frame = new WebSocketFrame($NewData);
                if ($NewData == $Frame->Tail) {
                    break;
                }
                $NewData = $Frame->Tail;
                $Frame->Tail = null;
                $this->DecodeFrame($Frame, $Client);
                $Client->Timestamp = time() + $this->ReadPropertyInteger('Interval');
            }
            $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} = $NewData;
        } elseif ($Client->State == WebSocketState::CloseSend) {
            $this->SendDebug('Receive', 'client answer server stream close !', 0);
            $this->{'WaitForClose' . $Client->ClientIP . $Client->ClientPort} = true;
        }
    }

    private function CloseConnection(Websocket_Client $Client)
    {
        $SendSocketClose = $this->MakeJSON($Client, '', false, SocketType::Disconnected);
        $this->SendDataToParent($SendSocketClose);
    }

    //################# DATAPOINTS PARENT
    /**
     * Empfängt Daten vom Parent.
     *
     * @param string $JSONString Das empfangene JSON-kodierte Objekt vom Parent.
     */
    public function ReceiveData($JSONString)
    {
        $data = json_decode($JSONString);
        unset($data->DataID);
        //$this->SendDebug('incoming', $data, 0);
        $Payload = utf8_decode($data->Buffer);
        $Clients = $this->Multi_Clients;
        $IncomingClient = new Websocket_Client($data->ClientIP, $data->ClientPort, WebSocketState::init);
        $Client = $Clients->GetByIpPort($IncomingClient);
        $this->SendDebug(($Client ? 'OLD' : 'NEW') . ' CLIENT', SocketType::ToString($data->Type), 0);
        switch ($data->Type) {
            case 0: /* Data */
                if ($Client === false) {
                    $this->SendDebug('no Connection for Data found', $IncomingClient->ClientIP . ':' . $IncomingClient->ClientPort, 0);
                    $this->CloseConnection($IncomingClient);
                } else {
                    $this->ProcessIncomingData($Client, $Payload);
                    $Clients->Update($Client);
                }
                break;
            case 1: /* Connected */
                if (!$this->NoNewClients) {
                    $this->SendDebug('new Connection', $IncomingClient->ClientIP . ':' . $IncomingClient->ClientPort, 0);
                    $this->ClearClientBuffer($IncomingClient);
                    $Clients->Update($IncomingClient);
                }
                break;
            case 2: /* Disconnected */
                if ($Client === false) {
                    $this->SendDebug('no Connection to disconnect found', $IncomingClient->ClientIP . ':' . $IncomingClient->ClientPort, 0);
                } else {
                    $Clients->Remove($Client);
                    $this->ClearClientBuffer($Client);
                }
                break;
        }
        $this->Multi_Clients = $Clients;
        $this->SetNextTimer();
    }

    //################# PUBLIC
    /**
     * Wird vom Timer aufgerufen.
     * Sendet einen Ping an den Client welcher als nächstes das Timeout erreicht.
     */
    public function KeepAlive()
    {
        $this->SendDebug('KeepAlive', 'start', 0);
        $this->SetTimerInterval('KeepAlivePing', 0);
        $Client = true;

        while ($Client) {
            $Clients = $this->Multi_Clients;
            $Client = $Clients->GetNextTimeout(1);
            if ($Client === false) {
                break;
            }
            if (@$this->SendPing($Client->ClientIP, $Client->ClientPort, '') === false) {
                $this->SendDebug('TIMEOUT ' . $Client->ClientIP . ':' . $Client->ClientPort, 'Ping timeout', 0);
            }
        }
        $this->SendDebug('KeepAlive', 'end', 0);
    }

    /**
     * Versendet einen Ping an einen Client.
     *
     * @param string $ClientIP   Die IP-Adresse des Client.
     * @param string $ClientPort Der Port des Client.
     * @param string $Text       Der Payload des Ping.
     *
     * @return bool True bei Erfolg, im Fehlerfall wird eine Warnung und false ausgegeben.
     */
    public function SendPing(string $ClientIP, string $ClientPort, string $Text)
    {
        $Client = $this->Multi_Clients->GetByIpPort(new Websocket_Client($ClientIP, $ClientPort));
        if ($Client === false) {
            $this->SendDebug('Unknow client', $ClientIP . ':' . $ClientPort, 0);
            trigger_error($this->Translate('Unknow client') . ': ' . $ClientIP . ':' . $ClientPort, E_USER_NOTICE);
            return false;
        }
        if ($Client->State != WebSocketState::Connected) {
            $this->SendDebug('Client not connected', $ClientIP . ':' . $ClientPort, 0);
            trigger_error($this->Translate('Client not connected') . ': ' . $ClientIP . ':' . $ClientPort, E_USER_NOTICE);
            return false;
        }
        $this->SendDebug('Send Ping' . $Client->ClientIP . ':' . $Client->ClientPort, $Text, 0);
        $this->Send($Text, WebSocketOPCode::ping, $Client);
        $Result = $this->WaitForPong($Client);
        $this->{'Pong' . $Client->ClientIP . $Client->ClientPort} = '';
        if ($Result === false) {
            $this->SendDebug('Timeout ' . $Client->ClientIP . ':' . $Client->ClientPort, '', 0);
            trigger_error($this->Translate('Timeout'), E_USER_NOTICE);
            $this->RemoveOneClient($Client);
            $this->CloseConnection($Client);
            return false;
        }
        if ($Result !== $Text) {
            $this->SendDebug('Error in Pong ' . $Client->ClientIP . ':' . $Client->ClientPort, $Result, 0);
            trigger_error($this->Translate('Wrong pong received'), E_USER_NOTICE);
            $this->RemoveOneClient($Client);
            $this->SendDisconnect($Client);
            return false;
        }
        return true;
    }

}

/* @} */
