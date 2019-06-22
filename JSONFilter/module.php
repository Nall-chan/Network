<?php

require_once __DIR__ . '/../libs/NetworkTraits.php';

class JSONFilter extends IPSModule
{
    use DebugHelper,
        UTF8Coder;

    public function Create()
    {
        parent::Create();

        $this->RegisterPropertyString('FilterItems', json_encode([]));
        $this->RegisterPropertyInteger('Condition', 0);
        $this->RegisterPropertyInteger('Type', 0);
    }

    public function ApplyChanges()
    {
        parent::ApplyChanges();
        $Items = json_decode($this->ReadPropertyString('FilterItems'), true);

        if (count($Items) > 0) {
            foreach ($Items as $Item) {
                $Value = '';
                switch ($Item['Type']) {
                    case 0:
                        if (is_numeric($Item['Value'])) {
                            $Value = (bool) $Item['Value'] ? 'true' : 'false';
                        } elseif (is_string($Item['Value'])) {
                            $Value = strtolower($Item['Value']) == 'true' ? 'true' : 'false';
                        } else {
                            $Value = 'false';
                        }
                        break;
                    case 1:
                        if (is_numeric($Item['Value'])) {
                            $Value = (int) $Item['Value'] . '\D';
                        } else {
                            $Value = '0\D';
                        }
                        break;
                    case 2:
                        if (is_numeric($Item['Value'])) {
                            $Value = (float) $Item['Value'] . '\D';
                        } else {
                            $Value = '0\D';
                        }
                        break;
                    case 3:
                        switch ($Item['Condition']) {
                            case 0:
                                $Value = '';
                                break;
                            case 1:
                                $Value = '\\\"' . (string) $Item['Value'] . '\\\"';

                                break;
                            case 2:
                                $Value = '\\\".*' . (string) $Item['Value'] . '.*\\\"';
                                break;
                        }
                        break;
                }
                $Types[$Item['Item']][] = $Value;
            }
            foreach ($Types as $Key => $Typ) {
                if (count($Typ) > 1) {
                    $ValueLine = '(' . implode('|', $Typ) . ')';
                } else {
                    $ValueLine = $Typ[0];
                }

                if ($ValueLine != '') {
                    $Lines[] = '.*\\\"' . $Key . '\\\":' . $ValueLine . '.*';
                } else {
                    $Lines[] = '.*\\\"' . $Key . '\\\":.*';
                }
            }
            switch ($this->ReadPropertyInteger('Condition')) {
                case 0: // and
                    $Line = implode(')(?=', $Lines);
                    $Line = '.*(?=' . $Line . ').*';
                    break;
                case 1: // or
                    $Line = implode('|', $Lines);
                    break;
            }

            $this->SetReceiveDataFilter($Line);
            $this->SendDebug('FILTER', $Line, 0);
        } else {
            $this->SetReceiveDataFilter('');
            $this->SendDebug('FILTER', 'NOTHING', 0);
        }
        // Alles Items lesen und als Filter setzen
        /*
          $this->SetReceiveDataFilter('.*"UUID":"' . $UUID . '".*');
          else
          $this->SetReceiveDataFilter(".*9999999999.*");
         */
    }

    public function ReceiveData($JSONString)
    {
        $this->SendDebug('Receive', $JSONString, 0);
        $AllData = utf8_decode(json_decode($JSONString)->Buffer);
        $this->SendDebug('Receive', $AllData, 0);
        $FilterType = $this->ReadPropertyInteger('Type');

        if ($FilterType == 2) {
            $this->SendDebug('ForwardToChild', $JSONString, 0);
            $this->SendDataToChildren($JSONString);
            return;
        }

        if ($FilterType == 0) {
            $ReceiveItems = json_decode($AllData, true);
            if ($ReceiveItems === null) {
                trigger_error('Error receive Data', E_USER_NOTICE);
                $this->SendDebug('Error', 'Error receive Data', 0);
                return;
            }
            $ReceiveItems = $this->DecodeUTF8($ReceiveItems);
            $ConfigItems = array_column(json_decode($this->ReadPropertyString('FilterItems'), true), 'Value', 'Item');
            $this->SendDebug('ConfigItems', $ConfigItems, 0);
            $Items = array_intersect_key($ReceiveItems, $ConfigItems);
            $this->SendDebug('Items', $Items, 0);
            foreach (array_keys($Items) as $Item) {
                $ReceiveItems[$Item] = $this->EncodeUTF8($ReceiveItems[$Item]);

                $SendData['DataID'] = '{018EF6B5-AB94-40C6-AA53-46943E824ACF}';
                $SendData['Buffer'] = json_encode($ReceiveItems[$Item]);
                $this->SendDebug('Forward', $SendData['Buffer'], 0);
                $this->SendDataToChildren(json_encode($SendData));
            }
            return;
        }
    }

    public function ForwardData($JSONString)
    {
        $this->SendDataToChildren($JSONString);
    }
}
