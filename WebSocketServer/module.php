<?

require_once(__DIR__ . "/../libs/NetworkTraits.php");
require_once(__DIR__ . "/../libs/WebsocketClass.php");  // diverse Klassen

use PTLS\TLSContext;
use PTLS\Exceptions\TLSAlertException;

/*
 * @addtogroup network
 * @{
 *
 * @package       Network
 * @file          module.php
 * @author        Michael Tröger <micha@nall-chan.net>get
 * @copyright     2017 Michael Tröger
 * @license       https://creativecommons.org/licenses/by-nc-sa/4.0/ CC BY-NC-SA 4.0
 * @version       1.2
 */

/**
 * WebsocketServer Klasse implementiert das Websocket-Protokoll für einen ServerSocket.
 * Erweitert IPSModule.
 * 
 * @package       Network
 * @author        Michael Tröger <micha@nall-chan.net>
 * @copyright     2017 Michael Tröger
 * @license       https://creativecommons.org/licenses/by-nc-sa/4.0/ CC BY-NC-SA 4.0
 * @version       1.2
 * @example <b>Ohne</b>
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
 * 
 */
class WebsocketServer extends IPSModule
{

    use DebugHelper,
        InstanceStatus,
        BufferHelper;

    /**
     * Interne Funktion des SDK.
     *
     * @access public
     */
    public function Create()
    {
        parent::Create();
        $this->RequireParent("{8062CF2B-600E-41D6-AD4B-1BA66C32D6ED}");
        $this->Multi_Clients = new WebSocket_ClientList();
        $this->NoNewClients = true;
        $this->RegisterPropertyBoolean("Open", false);
        $this->RegisterPropertyInteger("Port", 8080);
        $this->RegisterPropertyInteger("Interval", 0);
        $this->RegisterPropertyString("URI", "/");
        $this->RegisterPropertyBoolean("BasisAuth", false);
        $this->RegisterPropertyString("Username", "");
        $this->RegisterPropertyString("Password", "");
        $this->RegisterPropertyBoolean("TLS", false);
        $this->RegisterPropertyBoolean("Plain", true);
        $this->RegisterPropertyString("CertFile", "");
        $this->RegisterPropertyString("KeyFile", "");
        $this->RegisterPropertyString("KeyPassword", "");
        $this->RegisterTimer('KeepAlivePing', 0, 'WSS_KeepAlive($_IPS[\'TARGET\']);');
    }

    /**
     * Interne Funktion des SDK.
     *
     * @access public
     */
    public function MessageSink($TimeStamp, $SenderID, $Message, $Data)
    {
        switch ($Message)
        {
            case IPS_KERNELMESSAGE:
                if ($Data[0] != KR_READY)
                    break;
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
                if ($SenderID == $this->ParentID)
                {
                    if ($Data[0] == IS_ACTIVE)
                        $this->NoNewClients = false;
                    else
                    {
                        $this->NoNewClients = true;
                        $this->RemoveAllClients();
                    }
                }
                break;
        }
    }

    /**
     * Interne Funktion des SDK.
     *
     * @access public
     */
    public function GetConfigurationForm()
    {
        $data = json_decode(file_get_contents(__DIR__ . "/form.json"));
        if ((float) IPS_GetKernelVersion() < 4.2)
        {

            $data->elements[8]->type = "ValidationTextBox";
            $data->elements[8]->caption = "Path to certificate";
            unset($data->elements[8]->extensions);
            $data->elements[9]->type = "ValidationTextBox";
            $data->elements[9]->caption = "Path to private key";
            unset($data->elements[9]->extensions);
        }
        return json_encode($data);
    }

    /**
     * Interne Funktion des SDK.
     * 
     * @access public
     */
    public function GetConfigurationForParent()
    {
        $Config['Port'] = $this->ReadPropertyInteger('Port');
        $Config['Open'] = $this->ReadPropertyBoolean('Open');
        return json_encode($Config);
    }

    /**
     * Interne Funktion des SDK.
     * 
     * @access public
     */
    public function ApplyChanges()
    {
        $this->NoNewClients = true;

        if ((float) IPS_GetKernelVersion() < 4.2)
            $this->RegisterMessage(0, IPS_KERNELMESSAGE);
        else
        {
            $this->RegisterMessage(0, IPS_KERNELSTARTED);
            $this->RegisterMessage(0, IPS_KERNELSHUTDOWN);
        }

        $this->RegisterMessage($this->InstanceID, FM_CONNECT);
        $this->RegisterMessage($this->InstanceID, FM_DISCONNECT);

        if (IPS_GetKernelRunlevel() <> KR_READY)
            return;

        $this->SetTimerInterval('KeepAlivePing', 0);

        $OldParentID = $this->ParentID;
        if ($this->HasActiveParent() and ( $OldParentID > 0))
        {
            $this->DisconnectAllClients();
            IPS_SetProperty($OldParentID, 'Open', false);
            @IPS_ApplyChanges($OldParentID);
        }

        parent::ApplyChanges();

        $NewState = IS_ACTIVE;
        $this->UseTLS = $this->ReadPropertyBoolean('TLS');
        $this->UsePlain = $this->ReadPropertyBoolean('Plain');
        //$this->SendDebug('UsePlain', ($this->UsePlain ? "true" : "false"), 0);
        //$this->SendDebug('UseTLS', ($this->UseTLS ? "true" : "false"), 0);
        if ($this->UseTLS)
        {
            $basedir = IPS_GetKernelDir() . "cert";
            if (!file_exists($basedir))
                mkdir($basedir);
            if (($this->ReadPropertyString("CertFile") == "" ) and ( $this->ReadPropertyString("KeyFile") == "" ))
                return $this->CreateNewCert($basedir);

            try
            {
                if ((float) IPS_GetKernelVersion() < 4.2)
                {

                    $CertFile = @file_get_contents($this->ReadPropertyString("CertFile"));
                    $KeyFile = @file_get_contents($this->ReadPropertyString("KeyFile"));
                }
                else
                {
                    //Convert old settings
                    $CertFile = $this->ReadPropertyString("CertFile");
                    $KeyFile = $this->ReadPropertyString("KeyFile");
                    if (is_file($CertFile))
                        IPS_SetProperty($this->InstanceID, "CertFile", @file_get_contents($this->ReadPropertyString("CertFile")));
                    if (is_file($KeyFile))
                        IPS_SetProperty($this->InstanceID, "KeyFile", @file_get_contents($this->ReadPropertyString("KeyFile")));
                    if (IPS_HasChanges($this->InstanceID))
                    {
                        IPS_ApplyChanges($this->InstanceID);
                        return;
                    }

                    // Read new settings
                    $CertFile = base64_decode($CertFile);
                    $KeyFile = base64_decode($KeyFile);
                }

                if ($CertFile)
                    $this->CertData = 'data://text/plain;base64,' . base64_encode($CertFile);
                else
                    throw new Exception('Certificate missing or not found');

                if ($KeyFile)
                    $this->KeyData = 'data://text/plain;base64,' . base64_encode($KeyFile);
                else
                    throw new Exception('Private key missing or not found');

//                if (strlen($this->ReadPropertyString("KeyPassword")) == 0)
//                    throw new Exception('Password for private key missing');

                $this->KeyPassword = $this->ReadPropertyString("KeyPassword");
            }
            catch (Exception $exc)
            {
                echo $this->Translate($exc->getMessage());
                $this->UseTLS = false;
                $NewState = IS_EBASE + 1;
            }
        }

        $Open = $this->ReadPropertyBoolean('Open');
        $Port = $this->ReadPropertyInteger('Port');
        $this->PingInterval = $this->ReadPropertyInteger('Interval');
        if (!$Open)
            $NewState = IS_INACTIVE;
        else
        {
            if (($Port < 1) or ( $Port > 65535))
            {
                $NewState = IS_EBASE + 2;
                $Open = false;
                trigger_error($this->Translate('Port invalid'), E_USER_NOTICE);
            }
            else
            {
                if (($this->PingInterval != 0) and ( $this->PingInterval < 5))
                {
                    $this->PingInterval = 0;
                    $NewState = IS_EBASE + 4;
                    $Open = false;
                    trigger_error($this->Translate('Ping interval to small'), E_USER_NOTICE);
                }
            }
        }
        $ParentID = $this->RegisterParent();

        // Zwangskonfiguration des ServerSocket
        if ($ParentID > 0)
        {
            if (IPS_GetProperty($ParentID, 'Port') <> $Port)
                IPS_SetProperty($ParentID, 'Port', $Port);
            if (IPS_GetProperty($ParentID, 'Open') <> $Open)
                IPS_SetProperty($ParentID, 'Open', $Open);
            if (IPS_HasChanges($ParentID))
                @IPS_ApplyChanges($ParentID);
        }
        else
        {
            if ($Open)
            {
                $NewState = IS_INACTIVE;
                $Open = false;
            }
        }

        if ($Open && !$this->HasActiveParent($ParentID))
            $NewState = IS_EBASE + 2;

        $this->SetStatus($NewState);
        $this->NoNewClients = FALSE;
    }

################## PRIVATE

    /**
     * Erzeugt ein selbst-signiertes Zertifikat.
     * 
     * @access private
     * @param string $basedir Der Speicherort der Zertifikate.
     * @return boolean True bei Erflog, sonst false
     */
    private function CreateNewCert(string $basedir)
    {

        $CN = 'IPSymcon';
        $EMAIL = IPS_GetLicensee();
        $basedir .= DIRECTORY_SEPARATOR . $this->InstanceID;
        $configfile = $basedir . ".cnf";
        $certfile = $basedir . ".cer";
        $keyfile = $basedir . ".key";
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

        $dn = array(
            "countryName" => "DE",
            "stateOrProvinceName" => "none",
            "localityName" => "none",
            "organizationName" => "Home",
            "organizationalUnitName" => "IPS",
            "commonName" => "$CN",
            "emailAddress" => "$EMAIL"
        );

        $config = array(
            "config" => "$configfile",
            "encrypt_key" => true);

        $configKey = array(
            "config" => "$configfile",
            "encrypt_key" => true,
            "digest_alg" => "sha512",
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );
        $pk = openssl_pkey_new($configKey);
        openssl_pkey_export($pk, $pkexport, 'Symcon', $config);
        if ((float) IPS_GetKernelVersion() < 4.2)
        {
            $fp = fopen($keyfile, 'w');
            fwrite($fp, $pkexport);
            fclose($fp);
            IPS_SetProperty($this->InstanceID, "KeyFile", $basedir . ".key");
        }
        else
        {
            IPS_SetProperty($this->InstanceID, "KeyFile", base64_encode($pkexport));
        }


        $csr = openssl_csr_new($dn, $pk, $config);
        if ($csr)
        {
            $cert = openssl_csr_sign($csr, NULL, $pk, 730, $config);
            if ($cert)
            {
                openssl_x509_export($cert, $certout);
                if ((float) IPS_GetKernelVersion() < 4.2)
                {

                    $fp = fopen($certfile, 'w');
                    fwrite($fp, $certout);
                    fclose($fp);
                    IPS_SetProperty($this->InstanceID, "CertFile", $basedir . ".cer");
                }
                else
                {
                    IPS_SetProperty($this->InstanceID, "CertFile", base64_encode($certout));
                }
            }
            else
            {
                unlink($configfile);
                return false;
            }
        }
        else
        {
            unlink($configfile);
            return false;
        }
        unlink($configfile);
        IPS_SetProperty($this->InstanceID, "KeyPassword", "Symcon");
        IPS_ApplyChanges($this->InstanceID);
        return true;
    }

    /**
     * Wertet den Handshake des Clients aus.
     * 
     * @access private
     * @param string $Data Die Daten des Clients.
     * @return boolean|HTTP_ERROR_CODES True bei Erfolg, HTTP_ERROR_CODES bei Fehler, false wenn nicht genug Daten.
     */
    private function ReceiveHandshake(string $Data)
    {
        $this->SendDebug('Receive Handshake', $Data, 0);
        if (preg_match("/^GET ?([^?#]*) HTTP\/1.1\r\n/", $Data, $match))
        {
            if (substr($Data, -4) != "\r\n\r\n")
            {
                $this->SendDebug('WAIT', $Data, 0);
                return false;
            }

            if (trim($match[1]) != trim($this->ReadPropertyString('URI')))
            {
                $this->SendDebug('Wrong URI requested', $Data, 0);
                return HTTP_ERROR_CODES::Not_Found;
            }

            if ($this->ReadPropertyBoolean("BasisAuth"))
            {
                $realm = base64_encode($this->ReadPropertyString("Username") . ':' . $this->ReadPropertyString("Password"));
                if (preg_match("/Authorization: Basic (.*)\r\n/", $Data, $match))
                {
                    if ($match[1] != $realm)
                    {
                        $this->SendDebug('Unauthorized Connection:', base64_decode($match[1]), 0);
                        return HTTP_ERROR_CODES::Forbidden;
                    }
                }
                else
                {
                    $this->SendDebug('Authorization missing', '', 0);
                    return HTTP_ERROR_CODES::Unauthorized;
                }
            }
            if (preg_match("/Connection: (.*)\r\n/", $Data, $match))
            {
                if (strtolower($match[1]) != 'upgrade')
                {
                    $this->SendDebug('WRONG Connection:', $match[1], 0);
                    return HTTP_ERROR_CODES::Method_Not_Allowed;
                }
            }
            else
            {
                $this->SendDebug('MISSING', 'Connection: Upgrade', 0);
                return HTTP_ERROR_CODES::Bad_Request;
            }

            if (preg_match("/Upgrade: (.*)\r\n/", $Data, $match))
            {
                if (strtolower($match[1]) != 'websocket')
                {
                    $this->SendDebug('WRONG Upgrade:', $match[1], 0);
                    return HTTP_ERROR_CODES::Method_Not_Allowed;
                }
            }
            else
            {
                $this->SendDebug('MISSING', 'Upgrade: websocket', 0);
                return HTTP_ERROR_CODES::Bad_Request;
            }


            if (preg_match("/Sec-WebSocket-Version: (.*)\r\n/", $Data, $match))
            {
                if (strpos($match[1], '13') === false)
                {
                    $this->SendDebug('WRONG Version:', $match[1], 0);
                    return HTTP_ERROR_CODES::Not_Acceptable;
                }
            }
            else
            {
                $this->SendDebug('MISSING', 'Sec-WebSocket-Version', 0);
                return HTTP_ERROR_CODES::Bad_Request;
            }

            if (!preg_match("/Sec-WebSocket-Key: (.*)\r\n/", $Data, $match))
            {
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
     * @access private
     * @param HTTP_ERROR_CODES $Code Der HTTP Code welcher versendet werden soll.
     * @param string $Data Die empfangenen Daten des Clients.
     * @param Websocket_Client $Client Der Client vom welchen die Daten empfangen wurden.
     */
    private function SendHandshake(int $Code, string $Data, Websocket_Client $Client)
    {
        preg_match("/Sec-WebSocket-Key: (.*)\r\n/", $Data, $match);
        $SendKey = base64_encode(sha1($match[1] . "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", true));

        $Header[] = 'HTTP/1.1 ' . HTTP_ERROR_CODES::ToString($Code);
        if ($Code == HTTP_ERROR_CODES::Unauthorized)
            $Header[] = 'WWW-Authenticate: Basic';
        //$Header[] = 'Date: '; // Datum fehlt !
        $Header[] = 'Server: IP-Symcon Websocket Gateway';
        if ($Code == HTTP_ERROR_CODES::Web_Socket_Protocol_Handshake)
        {
            $Header[] = 'Connection: Upgrade';
            $Header[] = 'Sec-WebSocket-Accept: ' . $SendKey;
            $Header[] = 'Upgrade: websocket';
            $Header[] = "\r\n";
            $SendHeader = implode("\r\n", $Header);
        }
        else
        {
            $Header[] = "Content-Length:" . strlen(HTTP_ERROR_CODES::ToString($Code));
            $Header[] = "\r\n";
            $SendHeader = implode("\r\n", $Header) . HTTP_ERROR_CODES::ToString($Code);
        }

        $this->SendDebug("SendHandshake " . $Client->ClientIP . ':' . $Client->ClientPort, $SendHeader, 0);
        $SendData = $this->MakeJSON($Client, $SendHeader);
        if ($SendData)
            $this->SendDataToParent($SendData);
    }

    /**
     * Erzeugt aus einen Datenframe ein JSON für den Datenaustausch mit dem IO.
     * 
     * @param Websocket_Client $Client Der Client an welchen die Daten gesendet werden.
     * @param string $Data Die Nutzdaten
     * @param type $UseTLS Bei false wird TLS nicht benutzt, auch wenn der Client dies erwartet.
     * @return boolean|string Der JSON-String zum versand an den IO, im Fehlerfall false.
     */
    private function MakeJSON(Websocket_Client $Client, string $Data, $UseTLS = true)
    {
        if ($UseTLS and $Client->UseTLS)
        {
            $TLS = $this->{"Multi_TLS_" . $Client->ClientIP . $Client->ClientPort};
            $this->SendDebug('Send TLS', $Data, 0);
            try
            {
                $Send = $TLS->output($Data)->decode();
            }
            catch (Exception $exc)
            {
                return false;
            }
            $this->{"Multi_TLS_" . $Client->ClientIP . $Client->ClientPort} = $TLS;
            $Data = $Send;
        }
        $this->SendDebug('Send', $Data, 0);
        $SendData['DataID'] = "{C8792760-65CF-4C53-B5C7-A30FCC84FEFE}";
        $SendData['Buffer'] = utf8_encode($Data);
        $SendData['ClientIP'] = $Client->ClientIP;
        $SendData['ClientPort'] = $Client->ClientPort;
        return json_encode($SendData);
    }

    /**
     * Dekodiert die empfangenen Daten und sendet sie an die Childs.
     * 
     * @access private
     * @param WebSocketFrame $Frame Ein Objekt welches einen kompletten Frame enthält.
     * @param Websocket_Client $Client Der Client von welchem die Daten empfangen wurden.
     */
    private function DecodeFrame(WebSocketFrame $Frame, Websocket_Client $Client)
    {
        $this->SendDebug('DECODE', $Frame, ($Frame->OpCode == WebSocketOPCode::continuation) ? $this->PayloadTyp - 1 : $Frame->OpCode - 1);
        switch ($Frame->OpCode)
        {
            case WebSocketOPCode::ping:
                $this->SendPong($Client, $Frame->Payload);
                return;
            case WebSocketOPCode::close:
                $this->SendDebug('Receive', 'Client send stream close !', 0);
                $Client->State = WebSocketState::CloseReceived;
                $this->SendDisconnect($Client);
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
                return;
        }

        if ($Frame->Fin)
        {
            $this->SendDataToChilds($Data, $Client); // RAW Childs
        }
        else
        {
            $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} = $Data;
        }
    }

    /**
     * Setzt den Intervall des Timer auf den nächsten Timeout eines Client.
     * 
     * @access private
     */
    private function SetNextTimer()
    {
        $Clients = $this->Multi_Clients;
        $Client = $Clients->GetNextTimeout($this->PingInterval + 1);
        $this->SendDebug('NextTimeout', $Client, 0);
        if ($Client === false)
            $next = 0;
        else
        {
            $next = $Client->Timestamp - time();
            if ($next < 0)
                $next = 0;
        }
        $this->SendDebug('TIMER NEXT', $next, 0);
        $this->SetTimerInterval('KeepAlivePing', $next * 1000);
    }

    /**
     * Sendet einen Pong an einen Client.
     * 
     * @access private
     * @param Websocket_Client $Client Der Client an welchen das Pong versendet wird.
     * @param string $Payload Der Payloaf des Pong.
     */
    private function SendPong(Websocket_Client $Client, string $Payload = null)
    {
        $this->Send($Payload, WebSocketOPCode::pong, $Client);
    }

    /**
     * Sendet ein Connection Close an alle Clients.
     * 
     * @access private
     */
    private function DisconnectAllClients()
    {
        $Clients = $this->Multi_Clients;
        foreach ($Clients->GetClients() as $Client)
        {
            $this->SendDisconnect($Client);
        }
        $this->Multi_Clients = new WebSocket_ClientList();
    }

    /**
     * Sendet einen Close an einen Client und löscht alle Buffer dieses Clients.
     * 
     * @access private
     * @param Websocket_Client $Client Der Client an welchen das Close gesendet wird.
     * @return bool True bei Erfolg, sonst false.
     */
    private function SendDisconnect(Websocket_Client $Client)
    {
        $ret = false;
        if ($Client->State == WebSocketState::CloseReceived)
        {
            $ret = true;
            $this->SendDebug('Send', 'Answer Client stream close !', 0);
            $this->Send("", WebSocketOPCode::close, $Client);
        }
        if ($Client->State == WebSocketState::Connected)
        {
            $this->SendDebug('Send', 'Server send stream close !', 0);
            $Clients = $this->Multi_Clients;
            $Client->State = WebSocketState::CloseSend;
            $Clients->Update($Client);
            $this->Multi_Clients = $Clients;
            $this->Send("", WebSocketOPCode::close, $Client);
            $ret = $this->WaitForClose($Client);
        }

        $this->RemoveClient($Client);
        $Clients = $this->Multi_Clients;
        $Clients->Remove($Client);
        $this->Multi_Clients = $Clients;

        return $ret;
    }

    /**
     * Leert die ClientListe und alle entsprechenden Buffer der Clients.
     * 
     * @access private
     */
    private function RemoveAllClients()
    {
        $Clients = $this->Multi_Clients;
        foreach ($Clients->GetClients() as $Client)
        {
            $this->RemoveClient($Client);
        }
        $this->Multi_Clients = new WebSocket_ClientList();
    }

    /**
     * Leert die entsprechenden Buffer eines Clients.
     * 
     * @access private
     * @param Websocket_Client $Client Der zu löschende Client.
     */
    private function RemoveClient(Websocket_Client $Client)
    {
        $this->SetBuffer('OpCode' . $Client->ClientIP . $Client->ClientPort, "");
        $this->SetBuffer('Buffer' . $Client->ClientIP . $Client->ClientPort, "");
        $this->SetBuffer('Pong' . $Client->ClientIP . $Client->ClientPort, "");
        $this->SetBuffer('WaitForPong' . $Client->ClientIP . $Client->ClientPort, "");
        $this->SetBuffer('WaitForClose' . $Client->ClientIP . $Client->ClientPort, "");
        $this->{"Multi_TLS_" . $Client->ClientIP . $Client->ClientPort} = "";
        $this->SetBuffer("BufferListe_Multi_TLS_" . $Client->ClientIP . $Client->ClientPort, "");
    }

    /**
     * Wartet auf eine Handshake-Antwort.
     * 
     * @access private
     * @param Websocket_Client $Client
     * @return string|bool Der Payload des Pong, oder im Fehlerfall false.
     */
    private function WaitForPong(Websocket_Client $Client)
    {
        for ($i = 0; $i < 500; $i++)
        {
            if ($this->{'WaitForPong' . $Client->ClientIP . $Client->ClientPort} === true)
            {
                $Payload = $this->{'Pong' . $Client->ClientIP . $Client->ClientPort};
                $this->{'Pong' . $Client->ClientIP . $Client->ClientPort} = "";
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
     * @access private
     * @param Websocket_Client $Client
     * @return bool True bei Erfolg, sonst false.
     */
    private function WaitForClose(Websocket_Client $Client)
    {
        for ($i = 0; $i < 500; $i++)
        {
            if ($this->{'WaitForClose' . $Client->ClientIP . $Client->ClientPort} === true)
            {
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
     * @access private
     * @param string $RawData Das zu sende Payload
     * @param WebSocketOPCode $OPCode Der zu benutzende OPCode
     * @param Websocket_Client $Client Der Client an welchen die Daten gesendet werden sollen.
     * @param bool $Fin True wenn Ende von Payload erreicht.
     */
    private function Send(string $RawData, int $OPCode, Websocket_Client $Client, $Fin = true)
    {

        $WSFrame = new WebSocketFrame($OPCode, $RawData);
        $WSFrame->Fin = $Fin;
        $Frame = $WSFrame->ToFrame();
        $this->SendDebug('Send', $WSFrame, 0);
        $SendData = $this->MakeJSON($Client, $Frame);
        if ($SendData)
            $this->SendDataToParent($SendData);
    }

################## DATAPOINTS CHILDS

    /**
     * Interne Funktion des SDK. Nimmt Daten von Childs entgegen und sendet Diese weiter.
     * 
     * @access public
     * @param string $JSONString
     * @result bool true wenn Daten gesendet werden konnten, sonst false.
     */
    public function ForwardData($JSONString)
    {
        $Data = json_decode($JSONString);
        $Client = $this->Multi_Clients->GetByIpPort(new Websocket_Client($Data->ClientIP, $Data->ClientPort));
        if ($Client === false)
        {
            trigger_error($this->Translate('Unknow client') . ': ' . $Data->ClientIP . ':' . $Data->ClientPort, E_USER_NOTICE);
            return false;
        }
        if ($Client->State != WebSocketState::Connected)
        {
            trigger_error($this->Translate('Client not connected') . ': ' . $Data->ClientIP . ':' . $Data->ClientPort, E_USER_NOTICE);
            return false;
        }
        $this->SendDebug("Forward", utf8_decode($Data->Buffer), 0);

        if ($Data->DataID == "{714B71FB-3D11-41D1-AFAC-E06F1E983E09}")
        {
            if ($Data->FrameTyp == WebSocketOPCode::close)
                return $this->SendDisconnect($Client);
            if ($Data->FrameTyp == WebSocketOPCode::ping)
                return $this->SendPing($Client->ClientIP, $Client->ClientPort, utf8_decode($Data->Buffer));
            if (($Data->FrameTyp < 0) || ($Data->FrameTyp > 2))
            {
                trigger_error($this->Translate('FrameTyp invalid') . ': ' . $Data->ClientIP . ':' . $Data->ClientPort, E_USER_NOTICE);
                return false;
            }
        }
        else
        {
            $Data->FrameTyp = $this->{'OpCode' . $Client->ClientIP . $Client->ClientPort};
            $Data->Fin = true;
        }

        $this->Send(utf8_decode($Data->Buffer), $Data->FrameTyp, $Client, $Data->Fin);
        return true;
    }

    /**
     * Sendet die Rohdaten an die Childs.
     * 
     * @access private
     * @param string $RawData Die Nutzdaten.
     * @param Websocket_Client $Client Der Client von welchem die Daten empfangen wurden.
     */
    private function SendDataToChilds(string $RawData, Websocket_Client $Client)
    {
        $JSON['DataID'] = '{7A1272A4-CBDB-46EF-BFC6-DCF4A53D2FC7}'; //ServerSocket Receive
        $JSON['Buffer'] = utf8_encode($RawData);
        $JSON['ClientIP'] = $Client->ClientIP;
        $JSON['ClientPort'] = $Client->ClientPort;
        $Data = json_encode($JSON);
        $this->SendDataToChildren($Data);

        $JSON['DataID'] = '{8F1F6C32-B1AD-4B7F-8DFB-1244A96FCACF}';
        $JSON['FrameTyp'] = $this->{'OpCode' . $Client->ClientIP . $Client->ClientPort};
        $Data = json_encode($JSON);
        $this->SendDataToChildren($Data);
    }

################## DATAPOINTS PARENT    

    /**
     * Empfängt Daten vom Parent.
     * 
     * @access public
     * @param string $JSONString Das empfangene JSON-kodierte Objekt vom Parent.
     */
    public function ReceiveData($JSONString)
    {

        $data = json_decode($JSONString);
        unset($data->DataID);
        $this->SendDebug('incoming', $data, 0);
        $Data = utf8_decode($data->Buffer);
        $Clients = $this->Multi_Clients;
        $Client = $Clients->GetByIpPort(new Websocket_Client($data->ClientIP, $data->ClientPort));
//        if (($Client === false) or ( preg_match("/^GET ?([^?#]*) HTTP\/1.1\r\n/", $Data, $match)) or ( (ord($Data[0]) >= 0x14) && (ord($Data[0]) <= 0x18) && (ord($Data[1]) == 0x03) && (ord($Data[5]) == 0x01)))
        if (($Client === false) or ( preg_match("/^GET ?([^?#]*) HTTP\/1.1\r\n/", $Data, $match)) or ( (ord($Data[0]) == 0x16) && (ord($Data[1]) == 0x03) && (ord($Data[5]) == 0x01)))
        { // neu oder neu verbunden!
            if ($this->NoNewClients) //Server start neu... keine neuen Verbindungen annehmen.
                return;

            $this->SendDebug(($Client ? "RECONNECT" : "NEW") . ' CLIENT', $Data, 0);

            if ($this->UseTLS and ( (ord($Data[0]) >= 0x14) && (ord($Data[0]) <= 0x18) && (ord($Data[1]) == 0x03)))
            { //valid header wenn TLS is active
                $Client = new Websocket_Client($data->ClientIP, $data->ClientPort, WebSocketState::TLSisReceived, true);
                $Clients->Update($Client);
                $this->Multi_Clients = $Clients;
                $this->{'BufferTLS' . $Client->ClientIP . $Client->ClientPort} = "";
                $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} = "";
                // TLS Config
                $TLSconfig = TLSContext::getServerConfig([
                            'key_pair_files' => [
                                'cert' => [$this->CertData],
                                'key' => [$this->KeyData, $this->KeyPassword]
                            ]
                ]);
                $TLS = TLSContext::createTLS($TLSconfig);
            }

            if ($this->UsePlain and ( preg_match("/^GET ?([^?#]*) HTTP\/1.1\r\n/", $Data, $match)))
            { //valid header wenn Plain is active
                $Client = new Websocket_Client($data->ClientIP, $data->ClientPort);
                $Clients->Update($Client);
                $this->Multi_Clients = $Clients;
                $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} = "";
            }
            if ($Client === false) // Paket verwerfen, da Daten nicht zum Protocol passen.
                return;
        }
        // Client jetzt bekannt.
        if ($Client->UseTLS) // TLS Daten
        {
            $Data = $this->{'BufferTLS' . $Client->ClientIP . $Client->ClientPort} .= $Data;
            if (!isset($TLS))
                $TLS = $this->{"Multi_TLS_" . $Client->ClientIP . $Client->ClientPort};

            if ((ord($Data[0]) >= 0x14) && (ord($Data[0]) <= 0x18) && (ord($Data[1]) == 0x03))
            {
                if (($Client->State == WebSocketState::TLSisSend) or ( $Client->State == WebSocketState::TLSisReceived))
                {
                    $this->SendDebug('Get TLS Handshake', $Data, 0);
                    try
                    {
                        $TLS->encode($Data);
                    }
                    catch (TLSAlertException $e)
                    {
                        if (strlen($out = $e->decode()))
                        {
                            $this->SendDebug('Send TLS Handshake error', $out, 0);
                            $SendData = $this->MakeJSON($Client, $out, false);
                            if ($SendData)
                                $this->SendDataToParent($SendData);
                        }
                        $this->SendDebug('Send TLS Handshake error', $e->getMessage(), 0);
                        trigger_error($e->getMessage(), E_USER_NOTICE);
                        return false; //durch return wird weder BufferTLS noch Client Objekt behalten !
                    }
                    catch (\PTLS\Exceptions\TLSException $e)
                    {
                        $this->SendDebug('Send TLS Handshake error', $e->getMessage(), 0);
                        trigger_error($e->getMessage(), E_USER_NOTICE);
                        return false; //durch return wird weder BufferTLS noch Client Objekt behalten !
                    }

                    try
                    {
                        $out = $TLS->decode();
                    }
                    catch (\PTLS\Exceptions\TLSException $e)
                    {
                        trigger_error($e->getMessage(), E_USER_NOTICE);
                        return false; //durch return wird weder BufferTLS noch Client Objekt behalten !
                    }

                    if (strlen($out))
                    {
                        $this->SendDebug('Send TLS Handshake', $out, 0);
                        $SendData = $this->MakeJSON($Client, $out, false);
                        if ($SendData)
                            $this->SendDataToParent($SendData);
                    } else
                    {
                        $this->SendDebug('Send TLS EMPTY', $out, 0);
                    }
                    if ($TLS->isHandshaked())
                    {
                        $Client->State = WebSocketState::HandshakeReceived;
                        $this->SendDebug('TLS ProtocolVersion', $TLS->getDebug()->getProtocolVersion(), 0);
                        $UsingCipherSuite = explode("\n", $TLS->getDebug()->getUsingCipherSuite());
                        unset($UsingCipherSuite[0]);
                        foreach ($UsingCipherSuite as $Line)
                        {
                            $this->SendDebug(trim(substr($Line, 0, 14)), trim(substr($Line, 15)), 0);
                        }
                    }
                    $Clients = $this->Multi_Clients;
                    $Clients->Update($Client);
                    $this->Multi_Clients = $Clients;
                    $this->{'BufferTLS' . $Client->ClientIP . $Client->ClientPort} = "";
                    $this->{"Multi_TLS_" . $Client->ClientIP . $Client->ClientPort} = $TLS;
                    return;
                }

                $TLSData = $Data;
                $Data = "";
                while (strlen($TLSData) > 0)
                {
                    $len = unpack("n", substr($TLSData, 3, 2))[1] + 5;
                    if (strlen($TLSData) >= $len)
                    {
                        $Part = substr($TLSData, 0, $len);
                        $TLSData = substr($TLSData, $len);


                        $this->SendDebug('Receive TLS Frame', $Part, 0);
                        $TLS->encode($Part);
                        $Data .= $TLS->input();
                    }
                    else
                        break;
                }
                $this->{'BufferTLS' . $Client->ClientIP . $Client->ClientPort} = $TLSData;
                $this->{"Multi_TLS_" . $Client->ClientIP . $Client->ClientPort} = $TLS;

                if (strlen($TLSData) > 0)
                    $this->SendDebug('Receive TLS Part', $TLSData, 0);
            }
            else // Anfang (inkl. Buffer) paßt nicht
            {

                $this->{'BufferTLS' . $Client->ClientIP . $Client->ClientPort} = "";
                return; // nix sichern
            }
        }

        if ($Client->State == WebSocketState::HandshakeReceived)
        {
            $NewData = $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} . $Data;
            $CheckData = $this->ReceiveHandshake($NewData);
            if ($CheckData === true) // Daten komplett und heil.
            {
                $Client->State = WebSocketState::Connected; // jetzt verbunden
                $Client->Timestamp = time() + $this->ReadPropertyInteger("Interval");
                $Clients->Update($Client);
                $this->Multi_Clients = $Clients;
                $this->SendHandshake(101, $NewData, $Client); //Handshake senden
                $this->SendDebug('SUCCESSFULLY CONNECT', $Client, 0);
                $this->SetNextTimer();
            }
            elseif ($CheckData === false) // Daten nicht komplett, buffern.
            {
                $this->Multi_Clients = $Clients;
                $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} = $CheckData;
            }
            else // Daten komplett, aber defekt.
            {
                $this->SendHandshake($CheckData, $NewData, $Client);
                //$Clients->Remove($Client);
                $this->Multi_Clients = $Clients;
                //$this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} = "";
            }
        }
        elseif ($Client->State == WebSocketState::Connected)
        { // bekannt und verbunden
            $Client->Timestamp = time() + $this->ReadPropertyInteger("Interval");
            $Clients->Update($Client);
            $this->Multi_Clients = $Clients;
            $NewData = $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} . $Data;
            $this->SendDebug('ReceivePacket ' . $Client->ClientIP . $Client->ClientPort, $NewData, 1);
            while (true)
            {
                if (strlen($NewData) < 2)
                    break;
                $Frame = new WebSocketFrame($NewData);
                if ($NewData == $Frame->Tail)
                    break;
                $NewData = $Frame->Tail;
                $Frame->Tail = null;
                $this->DecodeFrame($Frame, $Client);
                $this->SetNextTimer();
            }
            $this->{'Buffer' . $Client->ClientIP . $Client->ClientPort} = $NewData;
        } elseif ($Client->State == WebSocketState::CloseSend)
        {
            $this->SendDebug('Receive', 'client answer server stream close !', 0);
            $this->{'WaitForClose' . $Client->ClientIP . $Client->ClientPort} = true;
        }
    }

################## PUBLIC

    /**
     * Wird vom Timer aufgerufen.
     * Sendet einen Ping an den Client welcher als nächstes das Timeout erreicht.
     * 
     * @access public
     */
    public function KeepAlive()
    {
        $this->SendDebug('KeepAlive', 'start', 0);
        $this->SetTimerInterval('KeepAlivePing', 0);
        $Client = true;

        while ($Client)
        {
            $Clients = $this->Multi_Clients;
            $Client = $Clients->GetNextTimeout(1);
            if ($Client === false)
                break;
            if (@$this->SendPing($Client->ClientIP, $Client->ClientPort, "") === false)
            {
                $this->SendDebug('TIMEOUT ' . $Client->ClientIP . ':' . $Client->ClientPort, "Ping timeout", 0);
                $Clients->Remove($Client);
                $this->Multi_Clients = $Clients;
            }
        }
        $this->SendDebug('KeepAlive', 'end', 0);
    }

    /**
     * Versendet einen Ping an einen Client.
     * 
     * @access public
     * @param string $ClientIP Die IP-Adresse des Client.
     * @param string $ClientPort Der Port des Client.
     * @param string $Text Der Payload des Ping.
     * @return bool True bei Erfolg, im Fehlerfall wird eine Warnung und false ausgegeben.
     */
    public function SendPing(string $ClientIP, string $ClientPort, string $Text)
    {
        $Client = $this->Multi_Clients->GetByIpPort(new Websocket_Client($ClientIP, $ClientPort));
        if ($Client === false)
        {
            $this->SendDebug('Unknow client', $ClientIP . ':' . $ClientPort, 0);
            trigger_error($this->Translate('Unknow client') . ': ' . $ClientIP . ':' . $ClientPort, E_USER_NOTICE);
            return false;
        }
        if ($Client->State != WebSocketState::Connected)
        {
            $this->SendDebug('Client not connected', $ClientIP . ':' . $ClientPort, 0);
            trigger_error($this->Translate('Client not connected') . ': ' . $ClientIP . ':' . $ClientPort, E_USER_NOTICE);
            return false;
        }
        $this->SendDebug('Send Ping' . $Client->ClientIP . ':' . $Client->ClientPort, $Text, 0);
        $this->Send($Text, WebSocketOPCode::ping, $Client);
        $Result = $this->WaitForPong($Client);
        $this->{'Pong' . $Client->ClientIP . $Client->ClientPort} = "";
        if ($Result === false)
        {
            $this->SendDebug('Timeout ' . $Client->ClientIP . ':' . $Client->ClientPort, "", 0);
            trigger_error($this->Translate('Timeout'), E_USER_NOTICE);
            $this->Multi_Clients->Remove($Client);
            return false;
        }
        if ($Result !== $Text)
        {
            $this->SendDebug('Error in Pong ' . $Client->ClientIP . ':' . $Client->ClientPort, $Result, 0);
            trigger_error($this->Translate('Wrong pong received'), E_USER_NOTICE);
            $this->Multi_Clients->Remove($Client);
            return false;
        }
        return true;
    }

}

/** @} */