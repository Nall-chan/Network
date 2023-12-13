<?php

declare(strict_types=1);

include_once __DIR__ . '/../libs/NetworkTraits.php';

/*
 * @addtogroup network
 * @{
 *
 * @package       Network
 * @file          module.php
 * @author        Michael Tröger <micha@nall-chan.net>
 * @copyright     2020 Michael Tröger
 * @license       https://creativecommons.org/licenses/by-nc-sa/4.0/ CC BY-NC-SA 4.0
 * @version       1.2
 */

/**
 * DHCPSniffer Klasse implementiert einen Sniffer für DHCP Requests.
 * Erweitert IPSModule.
 *
 * @author        Michael Tröger <micha@nall-chan.net>
 * @copyright     2020 Michael Tröger
 * @license       https://creativecommons.org/licenses/by-nc-sa/4.0/ CC BY-NC-SA 4.0
 *
 * @version       1.2
 *
 * @example <b>Ohne</b>
 */
class DHCPSniffer extends ipsmodule
{
    use DebugHelper; // Erweitert die SendDebug Methode von IPS um Arrays, Objekte und bool.

    /**
     * Interne Funktion des SDK.
     */
    public function Create()
    {
        parent::Create();
        $this->RegisterPropertyString('Address', '');
        $this->RegisterPropertyInteger('Protocol', 2);
        $this->RegisterPropertyInteger('Action', 0);
        $instance = IPS_GetInstance($this->InstanceID);
        if ($instance['ConnectionID'] == 0) {
            $ids = IPS_GetInstanceListByModuleID('{BAB408E0-0A0F-48C3-B14E-9FB2FA81F66A}');
            foreach ($ids as $id) {
                if (IPS_GetObject($id)['ObjectIdent'] == 'DHCPSniffer') {
                    IPS_ConnectInstance($this->InstanceID, $id);
                    return;
                }
            }
            $this->RequireParent('{BAB408E0-0A0F-48C3-B14E-9FB2FA81F66A}');
            IPS_SetIdent(IPS_GetInstance($this->InstanceID)['ConnectionID'], 'DHCPSniffer');
        }
    }

    /**
     * Interne Funktion des SDK.
     */
    public function ApplyChanges()
    {
        $this->RegisterMessage(0, IPS_KERNELSTARTED);

        parent::ApplyChanges();

        $Mac = $this->ReadPropertyString('Address');
        if ($Mac == '') {
            $Mac = 'FFFFFFFFFFFF';
        }
        $Mac = str_replace([' ', ':', '-'], ['', '', ''], $Mac);
        $Mac = hex2bin($Mac);

        if (strlen($Mac) != 6) {
            $Mac = 'FFFFFFFFFFFF';
            $this->SetStatus(IS_EBASE + 1);
        } else {
            $this->SetStatus(IS_ACTIVE);
        }

        $MacJSONencoded = [];
        for ($index = 0; $index < 6; $index++) {
            $MacJSONencoded[$index] = substr(json_encode(utf8_encode($Mac[$index]), JSON_UNESCAPED_UNICODE), 1, -1);
            if (strlen($MacJSONencoded[$index]) == 6) {
                $MacJSONencoded[$index] = '\\u' . substr(strtoupper($MacJSONencoded[$index]), 2);
            }
        }
        $MacMatch = preg_quote(implode('', $MacJSONencoded), '\\');
        $Filter = '.*\\\\u0001\\\\u0001\\\\u0006' . '.*' . $MacMatch . '.*'; // Alles

        $this->SendDebug('FILTER', $Filter, 0);
        $this->SetReceiveDataFilter($Filter);

        switch ($this->ReadPropertyInteger('Action')) {
            case 0: //EVENT
                $vid = @$this->GetIDForIdent('EVENT');
                if (!$vid) {
                    $this->RegisterVariableBoolean('EVENT', 'EVENT');
                }
                $vid = @$this->GetIDForIdent('IMPULSE');
                if ($vid > 0) {
                    $this->UnregisterVariable('IMPULSE');
                }
                $vid = @$this->GetIDForIdent('TOGGLE');
                if ($vid > 0) {
                    $this->UnregisterVariable('TOGGLE');
                }
                break;
            case 1: // IMPULSE
                $vid = @$this->GetIDForIdent('EVENT');
                if ($vid > 0) {
                    $this->UnregisterVariable('EVENT');
                }
                $vid = @$this->GetIDForIdent('IMPULSE');
                if (!$vid) {
                    $this->RegisterVariableBoolean('IMPULSE', 'IMPULSE');
                }
                $vid = @$this->GetIDForIdent('TOGGLE');
                if ($vid > 0) {
                    $this->UnregisterVariable('TOGGLE');
                }
                break;
            case 2: // Toggle
                $vid = @$this->GetIDForIdent('EVENT');
                if ($vid > 0) {
                    $this->UnregisterVariable('EVENT');
                }
                $vid = @$this->GetIDForIdent('IMPULSE');
                if ($vid > 0) {
                    $this->UnregisterVariable('IMPULSE');
                }
                $vid = @$this->GetIDForIdent('TOGGLE');
                if (!$vid) {
                    $this->RegisterVariableBoolean('TOGGLE', 'TOGGLE');
                }
                break;
        }
    }

    /**
     * Interne Funktion des SDK.
     */
    public function MessageSink($TimeStamp, $SenderID, $Message, $Data)
    {
        switch ($Message) {
            case IPS_KERNELSTARTED: // Nach dem IPS-Start
                $this->KernelReady(); // Sagt alles.
                break;
        }
    }

    /**
     * Interne Funktion des SDK.
     * Wird von der Console aufgerufen, wenn 'unser' IO-Parent geöffnet wird.
     * Außerdem nutzen wir sie in Applychanges, da wir dort die Daten zum konfigurieren nutzen.
     */
    public function GetConfigurationForParent()
    {
        $Config['Port'] = 68;
        $Config['MulticastIP'] = '224.0.0.50';
        $Config['BindPort'] = 67;
        $Config['EnableBroadcast'] = true;
        $Config['EnableReuseAddress'] = true;
        $Config['EnableLoopback'] = false;
        return json_encode($Config);
    }

    /**
     * Empfängt Daten vom Parent.
     *
     * @param string $JSONString Das empfangene JSON-kodierte Objekt vom Parent.
     */
    public function ReceiveData($JSONString)
    {
        $Data = utf8_decode(json_decode($JSONString)->Buffer);
        $this->SendDebug('Data', $Data, 1);
        $this->LogMessage(bin2hex($Data), KL_MESSAGE);
        $isDHCP = (substr($Data, 236, 4) === chr(0x63) . chr(0x82) . chr(0x53) . chr(0x63));
        $isDHCPRequest = (substr($Data, 236, 7) === chr(0x63) . chr(0x82) . chr(0x53) . chr(0x63) . chr(0x35) . chr(0x01) . chr(0x03));
        $this->SendDebug('isDHCP', $isDHCP, 0);
        $this->SendDebug('isDHCPRequest', $isDHCPRequest, 0);
        switch ($this->ReadPropertyInteger('Protocol')) {
            case 0: // DHCP
                if ($isDHCPRequest) {
                    $this->SendEvent();
                }
                break;
            case 1: // Bootp
                if (!$isDHCP) {
                    $this->SendEvent();
                }
                break;
            case 2: // both
                if ($isDHCPRequest) {
                    $this->SendEvent();
                } elseif (!$isDHCP) {
                    $this->SendEvent();
                }
                break;
        }
    }

    /**
     * Wird ausgeführt wenn der Kernel hochgefahren wurde.
     */
    protected function KernelReady()
    {
        $this->ApplyChanges();
    }

    /**
     * Beschreibt die Statusvariable.
     */
    protected function SendEvent()
    {
        $this->SendDebug('FIRE', 'EVENT', 0);
        switch ($this->ReadPropertyInteger('Action')) {
            case 0: //EVENT
                $this->SetValue('EVENT', true);
                break;
            case 1: // IMPULSE
                $this->SetValue('IMPULSE', true);
                IPS_Sleep(1);
                $this->SetValue('IMPULSE', false);
                break;
            case 2: // Toggle
                $this->SetValue('TOGGLE', !$this->GetValue('TOGGLE'));
                break;
        }
    }
}
