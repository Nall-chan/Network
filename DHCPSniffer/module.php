<?

include_once(__DIR__ . "/../libs/NetworkTraits.php");

/**
 * bla bla bla Erklärung Doku bla
 * 
 */
class DHCPSniffer extends ipsmodule
{

    use DebugHelper; // Erweitert die SendDebug Methode von IPS um Arrays, Objekte und bool.

    /**
     * Interne Funktion des SDK.
     * Wird immer ausgeführt wenn IPS startet und wenn eine Instanz neu erstellt wird.
     * @access public
     */
    public function Create()
    {
        // Diese Zeile nicht löschen.
        parent::Create();
        $this->RegisterPropertyString('Address', '');
        $this->RegisterPropertyInteger('Protocol', 2);
        $this->RegisterPropertyInteger('Action', 0);
        $instance = IPS_GetInstance($this->InstanceID);
        if ($instance['ConnectionID'] == 0)
        {
            $ids = IPS_GetInstanceListByModuleID("{BAB408E0-0A0F-48C3-B14E-9FB2FA81F66A}");
            foreach ($ids as $id)
            {
                if (IPS_GetObject($id)['ObjectIdent'] == 'DHCPSniffer')
                {
                    IPS_ConnectInstance($this->InstanceID, $id);
                    return;
                }
            }
            //Always create our own MultiCast I/O, when no parent is already available
            $this->RequireParent("{BAB408E0-0A0F-48C3-B14E-9FB2FA81F66A}");
            IPS_SetIdent(IPS_GetInstance($this->InstanceID)['ConnectionID'], 'DHCPSniffer');
        }
    }

    // Überschreibt die intere IPS_ApplyChanges($id) Funktion
    public function ApplyChanges()
    {
        // Wir wollen wissen wann IPS fertig ist mit dem starten, weil vorher funktioniert der Datenaustausch nicht.
        $this->RegisterMessage(0, IPS_KERNELSTARTED);

        parent::ApplyChanges();

        // Wenn Kernel nicht bereit, dann warten... IPS_KERNELSTARTED/KR_READY kommt ja gleich
        if (IPS_GetKernelRunlevel() <> KR_READY)
            return;
        $Mac = $this->ReadPropertyString('Address');
        if ($Mac == '')
            $Mac = "FFFFFFFFFFFF";
        $Mac = str_replace(array(' ', ':', '-'), array('', '', ''), $Mac);
        $Mac = preg_quote(utf8_encode(hex2bin($Mac)), '\\');
        $Filter = '.*\\\\u0001\\\\u0001\\\\u0006' . '.*' . $Mac . '.*'; // Alles

        $this->SendDebug('FILTER', $Filter, 0);
        $this->SetReceiveDataFilter($Filter);

        switch ($this->ReadPropertyInteger('Action'))
        {
            case 0: //EVENT
                $vid = @$this->GetIDForIdent('EVENT');
                if (!$vid)
                    $this->RegisterVariableBoolean('EVENT', 'EVENT');
                $vid = @$this->GetIDForIdent('IMPULSE');
                if ($vid > 0)
                    $this->UnregisterVariable('IMPULSE');
                $vid = @$this->GetIDForIdent('TOGGLE');
                if ($vid > 0)
                    $this->UnregisterVariable('TOGGLE');
                break;
            case 1: // IMPULSE
                $vid = @$this->GetIDForIdent('EVENT');
                if ($vid > 0)
                    $this->UnregisterVariable('EVENT');
                $vid = @$this->GetIDForIdent('IMPULSE');
                if (!$vid)
                    $this->RegisterVariableBoolean('IMPULSE', 'IMPULSE');
                $vid = @$this->GetIDForIdent('TOGGLE');
                if ($vid > 0)
                    $this->UnregisterVariable('TOGGLE');
                break;
            case 2: // Toggle
                $vid = @$this->GetIDForIdent('EVENT');
                if ($vid > 0)
                    $this->UnregisterVariable('EVENT');
                $vid = @$this->GetIDForIdent('IMPULSE');
                if ($vid > 0)
                    $this->UnregisterVariable('IMPULSE');
                $vid = @$this->GetIDForIdent('TOGGLE');
                if (!$vid)
                    $this->RegisterVariableBoolean('TOGGLE', 'TOGGLE');
                break;
        }
    }

    /**
     * Interne Funktion des SDK.
     * Verarbeitet alle Nachrichten auf die wir uns registriert haben.
     * @access public
     */
    public function MessageSink($TimeStamp, $SenderID, $Message, $Data)
    {
        switch ($Message)
        {
            case IPS_KERNELSTARTED: // Nach dem IPS-Start
                $this->KernelReady(); // Sagt alles.
                break;
        }
    }

    /**
     * Wird ausgeführt wenn der Kernel hochgefahren wurde.
     * @access protected
     */
    protected function KernelReady()
    {
        $this->ApplyChanges();
    }

    /**
     * Interne Funktion des SDK.
     * Wird von der Console aufgerufen, wenn 'unser' IO-Parent geöffnet wird.
     * Außerdem nutzen wir sie in Applychanges, da wir dort die Daten zum konfigurieren nutzen.
     * @access public
     */
    public function GetConfigurationForParent()
    {
        $Config['Port'] = 68;
        $Config['MulticastIP'] = "224.0.0.50";
        $Config['BindPort'] = 67;
        $Config['EnableBroadcast'] = true;
        $Config['EnableReuseAddress'] = true;
        $Config['EnableLoopback'] = false;
        return json_encode($Config);
    }

    public function ReceiveData($JSONString)
    {
        $Data = utf8_decode(json_decode($JSONString)->Buffer);
        $this->SendDebug('Data', $Data, 1);
        $isDHCP = (substr($Data, 236, 4) === chr(0x63) . chr(0x82) . chr(0x53) . chr(0x63));
        $isDHCPRequest = (substr($Data, 236, 7) === chr(0x63) . chr(0x82) . chr(0x53) . chr(0x63) . chr(0x35) . chr(0x01) . chr(0x03));
        $this->SendDebug('isDHCP', $isDHCP, 0);
        $this->SendDebug('isDHCPRequest', $isDHCPRequest, 0);
        switch ($this->ReadPropertyInteger('Protocol'))
        {
            case 0: // DHCP
                if ($isDHCPRequest)
                    $this->SendEvent();
                break;
            case 1: // Bootp
                if (!$isDHCP)
                    $this->SendEvent();
                break;
            case 2: // both
                if ($isDHCPRequest)
                    $this->SendEvent();
                if (!$isDHCP)
                    $this->SendEvent();
                break;
        }
    }

    protected function SendEvent()
    {
        $this->SendDebug('FIRE', 'EVENT', 0);
        switch ($this->ReadPropertyInteger('Action'))
        {
            case 0: //EVENT
                $vid = @$this->GetIDForIdent('EVENT');
                if ($vid > 0)
                    SetValueBoolean($vid, true);
                break;
            case 1: // IMPULSE
                $vid = @$this->GetIDForIdent('IMPULSE');
                if ($vid > 0)
                {
                    SetValueBoolean($vid, true);
                    IPS_Sleep(1);
                    SetValueBoolean($vid, false);
                }

                break;
            case 2: // Toggle
                $vid = @$this->GetIDForIdent('TOGGLE');
                if ($vid > 0)
                    SetValueBoolean($vid, !GetValueBoolean($vid));
                break;
        }
    }

}

?>
