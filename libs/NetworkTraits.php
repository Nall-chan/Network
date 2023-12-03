<?php

declare(strict_types=1);

/* @addtogroup network
 * @{
 *
 * @package       Network
 * @author        Michael Tröger <micha@nall-chan.net>
 * @copyright     2018 Michael Tröger
 * @license       https://creativecommons.org/licenses/by-nc-sa/4.0/ CC BY-NC-SA 4.0
 * @version       1.1
 * @example <b>Ohne</b>
 */
/**
 * DebugHelper ergänzt SendDebug um die Möglichkeit Array und Objekte auszugeben.
 */
trait DebugHelper
{
    /**
     * Ergänzt SendDebug um die Möglichkeit Objekte und Array auszugeben.
     *
     * @param string               $Message Nachricht für Data.
     * @param WebSocketFrame|mixed $Data    Daten für die Ausgabe.
     *
     * @return int $Format Ausgabeformat für Strings.
     */
    protected function SendDebug($Message, $Data, $Format)
    {
        if (is_a($Data, 'WebSocketFrame')) {
            $this->SendDebug($Message . ' FIN', ($Data->Fin ? 'true' : 'false'), 0);
            $this->SendDebug($Message . ' OpCode', WebSocketOPCode::ToString($Data->OpCode), 0);
            $this->SendDebug($Message . ' Mask', ($Data->Mask ? 'true' : 'false'), 0);
            if ($Data->MaskKey != '') {
                $this->SendDebug($Message . ' MaskKey', $Data->MaskKey, 1);
            }
            if ($Data->Payload != '') {
                $this->SendDebug($Message . ' Payload', $Data->Payload, ($Data->OpCode == WebSocketOPCode::text ? (int) $Data->Mask : ($Format)));
            }

            if ($Data->PayloadRAW != '') {
                $this->SendDebug($Message . ' PayloadRAW', $Data->PayloadRAW, ($Data->OpCode == WebSocketOPCode::text ? 0 : 1));
            }
        } elseif (is_object($Data)) {
            foreach ($Data as $Key => $DebugData) {
                $this->SendDebug($Message . ':' . $Key, $DebugData, 0);
            }
        } elseif (is_array($Data)) {
            foreach ($Data as $Key => $DebugData) {
                $this->SendDebug($Message . ':' . $Key, $DebugData, 0);
            }
        } else {
            if (is_bool($Data)) {
                parent::SendDebug($Message, ($Data ? 'true' : 'false'), 0);
            } else {
                parent::SendDebug($Message, (string) $Data, $Format);
            }
        }
    }
}

/**
 * Trait mit Hilfsfunktionen für den Datenaustausch.
 */
trait InstanceStatus
{
    /**
     * Interne Funktion des SDK.
     */
    protected function MessageSink($TimeStamp, $SenderID, $Message, $Data)
    {
        switch ($Message) {
            case FM_CONNECT:
                $this->RegisterParent();
                if ($this->HasActiveParent()) {
                    $this->IOChangeState(IS_ACTIVE);
                } else {
                    $this->IOChangeState(IS_INACTIVE);
                }
                break;
            case FM_DISCONNECT:
                $this->RegisterParent();
                $this->IOChangeState(IS_INACTIVE);
                break;
            case IM_CHANGESTATUS:
                if ($SenderID == $this->ParentID) {
                    $this->IOChangeState($Data[0]);
                }
                break;
        }
    }

    /**
     * Ermittelt den Parent und verwaltet die Einträge des Parent im MessageSink
     * Ermöglicht es das Statusänderungen des Parent empfangen werden können.
     *
     * @return int ID des Parent.
     */
    protected function RegisterParent()
    {
        $OldParentId = $this->ParentID;
        $ParentId = @IPS_GetInstance($this->InstanceID)['ConnectionID'];
        if ($ParentId != $OldParentId) {
            if ($OldParentId > 0) {
                $this->UnregisterMessage($OldParentId, IM_CHANGESTATUS);
            }
            if ($ParentId > 0) {
                $this->RegisterMessage($ParentId, IM_CHANGESTATUS);
            } else {
                $ParentId = 0;
            }
            $this->ParentID = $ParentId;
        }
        return $ParentId;
    }

    /**
     * Prüft den Parent auf vorhandensein und Status.
     *
     * @return bool True wenn Parent vorhanden und in Status 102, sonst false.
     */
    protected function HasActiveParent()
    {
        $instance = @IPS_GetInstance($this->InstanceID);
        if ($instance['ConnectionID'] > 0) {
            $parent = IPS_GetInstance($instance['ConnectionID']);
            if ($parent['InstanceStatus'] == 102) {
                return true;
            }
        }
        return false;
    }
}

/**
 * Biete Funktionen um auf Objekte Thread-Safe zuzugreifen.
 */
trait Semaphore
{
    /**
     * Versucht eine Semaphore zu setzen und wiederholt dies bei Misserfolg bis zu 100 mal.
     *
     * @param string $ident Ein String der den Lock bezeichnet.
     *
     * @return bool TRUE bei Erfolg, FALSE bei Misserfolg.
     */
    private function lock($ident)
    {
        for ($i = 0; $i < 1000; $i++) {
            if (IPS_SemaphoreEnter(__CLASS__ . '.' . (string) $this->InstanceID . (string) $ident, 1)) {
                return true;
            } else {
                IPS_Sleep(5);
            }
        }
        return false;
    }

    /**
     * Löscht eine Semaphore.
     *
     * @param string $ident Ein String der den Lock bezeichnet.
     */
    private function unlock($ident)
    {
        IPS_SemaphoreLeave(__CLASS__ . '.' . (string) $this->InstanceID . (string) $ident);
    }
}
/**
 * Trait welcher Objekt-Eigenschaften in den Instance-Buffer schreiben und lesen kann.
 */
trait BufferHelper
{
    /**
     * Wert einer Eigenschaft aus den InstanceBuffer lesen.
     *
     * @param string $name Propertyname
     *
     * @return mixed Value of Name
     */
    public function __get($name)
    {
        if (strpos($name, 'Multi_') === 0) {
            $Lines = '';
            foreach ($this->{'BufferListe_' . $name} as $BufferIndex) {
                $Lines .= $this->{'Part_' . $name . $BufferIndex};
            }
            return unserialize($Lines);
        }
        return unserialize($this->GetBuffer($name));
    }

    /**
     * Wert einer Eigenschaft in den InstanceBuffer schreiben.
     *
     * @param string $name Propertyname
     * @param mixed Value of Name
     */
    public function __set($name, $value)
    {
        $Data = serialize($value);
        if (strpos($name, 'Multi_') === 0) {
            $OldBuffers = $this->{'BufferListe_' . $name};
            if ($OldBuffers == false) {
                $OldBuffers = [];
            }
            $Lines = str_split($Data, 8000);
            foreach ($Lines as $BufferIndex => $BufferLine) {
                $this->{'Part_' . $name . $BufferIndex} = $BufferLine;
            }
            $NewBuffers = array_keys($Lines);
            $this->{'BufferListe_' . $name} = $NewBuffers;
            $DelBuffers = array_diff_key($OldBuffers, $NewBuffers);
            foreach ($DelBuffers as $DelBuffer) {
                $this->{'Part_' . $name . $DelBuffer} = '';
            }
            return;
        }
        $this->SetBuffer($name, $Data);
    }
}

trait UTF8Coder
{
    /**
     * Führt eine UTF8-Dekodierung für einen String oder ein Objekt durch (rekursiv).
     *
     * @param string|object $item Zu dekodierene Daten.
     *
     * @return string|object Dekodierte Daten.
     */
    private function DecodeUTF8($item)
    {
        if (is_string($item)) {
            $item = utf8_decode($item);
        } elseif (is_object($item)) {
            foreach ($item as $property => $value) {
                $item->{$property} = $this->DecodeUTF8($value);
            }
        }
        return $item;
    }

    /**
     * Führt eine UTF8-Enkodierung für einen String oder ein Objekt durch (rekursiv).
     *
     * @param string|object $item Zu Enkodierene Daten.
     *
     * @return string|object Enkodierte Daten.
     */
    private function EncodeUTF8($item)
    {
        if (is_string($item)) {
            $item = utf8_encode($item);
        } elseif (is_object($item)) {
            foreach ($item as $property => $value) {
                $item->{$property} = $this->EncodeUTF8($value);
            }
        }
        return $item;
    }
}

/* @} */
