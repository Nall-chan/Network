<?

require_once(__DIR__ . "/../libs/NetworkTraits.php");

class JSONValues extends IPSModule
{

    use DebugHelper,
        UTF8Coder;

    public function Create()
    {
        parent::Create();
        $this->RegisterPropertyString("Items", json_encode(array()));
    }

    public function ApplyChanges()
    {
        parent::ApplyChanges();

        // Alles Items lesen und als Filter setzen
        /*
          $this->SetReceiveDataFilter('.*"UUID":"' . $UUID . '".*');
          else
          $this->SetReceiveDataFilter(".*9999999999.*");
         */

        // Prüfen Einstellungen und anlegen Variablen
        $this->MakeStatusVariables();
    }

    private function MakeStatusVariables()
    {
        $Items = json_decode($this->ReadPropertyString('Items'), true);
        $this->SendDebug('Config', $Items, 0);
//        print_r($Items);
        $ConfigItems = array_column($Items, 'Type', 'Item');

        foreach ($ConfigItems as $Item => $Typ)
        {
            if ($Item == "")
                continue;
            $Ident = $this->generateIdent($Item);
            $vid = @$this->GetIDForIdent($Ident);
            if ($vid === false)
            {
                $this->MaintainVariable($Ident, $Item, $Typ, '', 0, true);
                $vid = $this->GetIDForIdent($Ident);
            }
        }
    }

    public function ReceiveData($JSONString)
    {
        $Data = utf8_decode(json_decode($JSONString)->Buffer);
        $this->SendDebug('Receive', $Data, 0);
        $ReceiveItems = json_decode($Data, true);

        if ($ReceiveItems === NULL)
        {
            trigger_error('Error receive Data', E_USER_NOTICE);
            return;
        }
        $ReceiveItems = $this->DecodeUTF8($ReceiveItems);
        $this->SendDebug('ReceiveItems', $ReceiveItems, 0);
        $ConfigItems = array_column(json_decode($this->ReadPropertyString('Items'), true), 'Type', 'Item');

        $Items = array_intersect_key($ReceiveItems, $ConfigItems);
        $this->SendDebug('ProcessItems', $Items, 0);

        foreach ($Items as $Item => $Value)
        {
            $Ident = $this->generateIdent($Item);
            $vid = @$this->GetIDForIdent($Ident);
            if ($vid === false)
            {
                $this->MaintainVariable($Ident, $Item, $ConfigItems[$Item], '', 0, true);
                $vid = $this->GetIDForIdent($Ident);
            }
            SetValue($vid, $Value);
        }
    }

    protected function generateIdent($Name)
    {
        if (preg_match('/^[a-zA-Z0-9]+$/', $Name))
            return $Name;
        return preg_replace("/[^a-z0-9]+/i", "", $Name);
    }

}
