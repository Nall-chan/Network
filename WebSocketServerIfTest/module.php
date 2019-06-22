<?php

/*
 * @addtogroup network
 * @{
 *
 * @package       Network
 * @file          module.php
 * @author        Michael Tröger <micha@nall-chan.net>
 * @copyright     2017 Michael Tröger
 * @license       https://creativecommons.org/licenses/by-nc-sa/4.0/ CC BY-NC-SA 4.0
 * @version       1.0
 *
 */

/**
 * WebSocketInterfaceTest Klasse zeigt die Verwendung des Datenaustausches mit einem WebSocket-Server oder -Client.
 * Erweitert IPSModule.
 *
 * @author        Michael Tröger <micha@nall-chan.net>
 * @copyright     2017 Michael Tröger
 * @license       https://creativecommons.org/licenses/by-nc-sa/4.0/ CC BY-NC-SA 4.0
 *
 * @version       1.0
 *
 * @example <b>Ohne</b>
 */
class WebSocketInterfaceTest extends IPSModule
{
    /**
     * Interne Funktion des SDK.
     */
    public function Create()
    {
        parent::Create();
    }

    /**
     * Interne Funktion des SDK.
     */
    public function ApplyChanges()
    {
        parent::ApplyChanges();
    }

    public function SendTestServer(string $ClientIP, int $FrameTyp, string $Data, bool $Fin)
    {
        // Daten zum WebSocket-Server
        $SendData['DataID'] = '{714B71FB-3D11-41D1-AFAC-E06F1E983E09}';
        $SendData['ClientIP'] = $ClientIP;
        $SendData['FrameTyp'] = $FrameTyp;
        $SendData['Fin'] = $Fin;
        $SendData['Buffer'] = utf8_encode($Data); // immer utf8_encode falls binäre Daten enthalten sind
        $this->SendDebug('ClientIP', $SendData['ClientIP'], 0);
        $this->SendDebug('FrameTyp', $SendData['FrameTyp'], 0);
        $this->SendDebug('Fin', ($SendData['Fin'] ? 'true' : 'false'), 0);
        $this->SendDebug('Buffer', $SendData['Buffer'], 0);

        return $this->SendDataToParent(json_encode($SendData));
    }

    public function SendTestClient(int $FrameTyp, string $Data, bool $Fin)
    {
        // Daten zum WebSocket-Client
        $SendData['DataID'] = '{BC49DE11-24CA-484D-85AE-9B6F24D89321}';
        $SendData['FrameTyp'] = $FrameTyp;
        $SendData['Fin'] = $Fin;
        $SendData['Buffer'] = utf8_encode($Data); // immer utf8_encode falls binäre Daten enthalten sind
        $this->SendDebug('FrameTyp', $SendData['FrameTyp'], 0);
        $this->SendDebug('Fin', ($SendData['Fin'] ? 'true' : 'false'), 0);
        $this->SendDebug('Buffer', $SendData['Buffer'], 0);
        return $this->SendDataToParent(json_encode($SendData));
    }

    //################# DATAPOINTS PARENT

    /**
     * Empfängt Daten vom Parent.
     *
     * @param string $JSONString Das empfangene JSON-kodierte Objekt vom Parent.
     */
    public function ReceiveData($JSONString)
    {
        $Data = json_decode($JSONString);

        // Daten vom WebSocket-Server
        if ($Data->DataID == '{8F1F6C32-B1AD-4B7F-8DFB-1244A96FCACF}') {
            $this->SendDebug('FrameTyp', $Data->FrameTyp, 0);
            $this->SendDebug('ClientIP', $Data->ClientIP, 0);
            $this->SendDebug('ClientPort', $Data->ClientPort, 0);
            $this->SendDebug('Receive', utf8_decode($Data->Buffer), 0);
        }

        // Daten vom WebSocket-Client
        if ($Data->DataID == '{C51A4B94-8195-4673-B78D-04D91D52D2DD}') {
            $this->SendDebug('FrameTyp', $Data->FrameTyp, 0);
            $this->SendDebug('Receive', utf8_decode($Data->Buffer), 0);
        }
    }
}

/* @} */
