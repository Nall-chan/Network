<?php

//declare(strict_types = 1);

/**
 * Ein Trait um Webhooks zu erzeugen und zu löschen.
 */
trait WebhookHelper
{
    /**
     * Erstellt einen WebHook, wenn nicht schon vorhanden.
     *
     * @param string $WebHook URI des WebHook.
     */
    protected function RegisterHook($WebHook)
    {
        $ids = IPS_GetInstanceListByModuleID('{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}');
        if (count($ids) > 0) {
            $hooks = json_decode(IPS_GetProperty($ids[0], 'Hooks'), true);
            $found = false;
            foreach ($hooks as $index => $hook) {
                if ($hook['Hook'] == $WebHook) {
                    if ($hook['TargetID'] == $this->InstanceID) {
                        return;
                    }
                    $hooks[$index]['TargetID'] = $this->InstanceID;
                    $found = true;
                }
            }
            if (!$found) {
                $hooks[] = ['Hook' => $WebHook, 'TargetID' => $this->InstanceID];
            }
            //$this->SendDebug('hook', $hooks, 0);
            IPS_SetProperty($ids[0], 'Hooks', json_encode($hooks));
            IPS_ApplyChanges($ids[0]);
        }
    }

    /**
     * Löscht einen WebHook, wenn vorhanden.
     *
     * @param string $WebHook URI des WebHook.
     */
    protected function UnregisterHook($WebHook)
    {
        $ids = IPS_GetInstanceListByModuleID('{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}');
        if (count($ids) > 0) {
            $hooks = json_decode(IPS_GetProperty($ids[0], 'Hooks'), true);
            $found = false;
            foreach ($hooks as $index => $hook) {
                if ($hook['Hook'] == $WebHook) {
                    $found = $index;
                    break;
                }
            }

            if ($found !== false) {
                array_splice($hooks, $index, 1);
                IPS_SetProperty($ids[0], 'Hooks', json_encode($hooks));
                IPS_ApplyChanges($ids[0]);
            }
        }
    }
}
