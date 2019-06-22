<?php

declare(strict_types=1);

//declare(strict_types = 1);

require_once __DIR__ . '/../libs/NetworkTraits.php';
require_once __DIR__ . '/../libs/WebhookHelper.php';

/*
 * @addtogroup Network
 * @{
 *
 * @package       Network
 * @file          module.php
 * @author        Michael Tröger <micha@nall-chan.net>
 * @copyright     2018 Michael Tröger
 * @license       https://creativecommons.org/licenses/by-nc-sa/4.0/ CC BY-NC-SA 4.0
 * @version       2.20
 *
 */

/**
 * HookReverseProxy Klasse
 * Erweitert IPSModule.
 *
 * @author        Michael Tröger <micha@nall-chan.net>
 * @copyright     2018 Michael Tröger
 * @license       https://creativecommons.org/licenses/by-nc-sa/4.0/ CC BY-NC-SA 4.0
 *
 * @version       2.20
 *
 * @example <b>Ohne</b>
 *
 * @property array $Hooks
 */
class HookReverseProxy extends IPSModule
{
    use BufferHelper,
        DebugHelper,
        WebhookHelper;

    /**
     * Interne Funktion des SDK.
     */
    public function Create()
    {
        parent::Create();
        $this->RegisterPropertyString('Hooks', '[]');
        $this->Hooks = [];
    }

    /**
     * Interne Funktion des SDK.
     */
    public function Destroy()
    {
        if (!IPS_InstanceExists($this->InstanceID)) {
            foreach ($this->Hooks as $Hook) {
                $this->UnregisterHook($Hook['Hook']);
            }
        }
        parent::Destroy();
    }

    /**
     * Interne Funktion des SDK.
     */
    public function ApplyChanges()
    {
        $OldHooks = $this->Hooks;
        $OldHooksColumns = array_column($OldHooks, 'Hook');
        parent::ApplyChanges();
        $NewHooks = $this->Hooks = json_decode($this->ReadPropertyString('Hooks'), true);
        $NewHooksColumns = array_column($NewHooks, 'Hook');
        $DeleteHooks = array_diff($OldHooksColumns, $NewHooksColumns);
        $AddHooks = array_diff($NewHooksColumns, $OldHooksColumns);

        if (IPS_GetKernelRunlevel() == KR_READY) {
            foreach ($DeleteHooks as $DeleteHook) {
                $this->UnregisterHook($DeleteHook);
            }
            foreach ($AddHooks as $AddHook) {
                $this->RegisterHook($AddHook);
            }
        }
    }

    private function GetURL($RequestURI)
    {
        $Hooks = $this->Hooks;
        $HookColumns = array_column($Hooks, null, 'Hook');
        if (array_key_exists($RequestURI, $HookColumns)) {
            return $HookColumns[$RequestURI];
        }
        return false;
    }

    private function DeliveryLocalFile(string $File, bool $forceDL)
    {
        $DirName = pathinfo($File, PATHINFO_DIRNAME);
        $Extension = pathinfo($File, PATHINFO_EXTENSION);
        $this->SendDebug('pathinfo', pathinfo($File), 0);
        if ($DirName == '.') {
            $File = IPS_GetKernelDir() . $File;
        }
        $fp = @fopen($File, 'rb');
        if ($fp === false) {
            http_response_code(404);
            header('Content-Type: text/plain');
            header('Connection: close');
            header('Server: Symcon ' . IPS_GetKernelVersion());
            header('X-Powered-By: Hook Reverse Proxy');
            header('Expires: 0');
            header('Cache-Control: no-cache');
            die('File not found!');
        }
        http_response_code(200);
        header('Connection: close');
        header('Server: Symcon ' . IPS_GetKernelVersion());
        header('X-Powered-By: Hook Reverse Proxy');
        header('Expires: 0');
        header('Cache-Control: no-cache');
        if ($forceDL) {
            header('Content-Description: File Transfer');
            $ContentType = 'Content-Type: application/octet-stream';
            header('Content-Disposition: attachment; filename="' . basename($File) . '"');
            header('Pragma: public');
        } else {
            $ContentType = 'Content-Type: ' . $this->GetMimeType($Extension);
        }
        header($ContentType);
        $Result = @fpassthru($fp);
        $this->SendDebug('Send Content-Type', $ContentType, 0);
        $this->SendDebug('Send Bytes', $Result, 0);
        fclose($fp);
    }

    private function BuildNewUrl(array &$HookData, array $Get)
    {
        $ConfigQuery = parse_url($HookData['Url'], PHP_URL_QUERY);
        $ConfigGet = [];
        if ($ConfigQuery !== null) {
            parse_str($ConfigQuery, $ConfigGet);
        }
        $this->SendDebug('config Get', $ConfigGet, 0);
        $this->SendDebug('add Get', $Get, 0);
        $NewGet = array_merge($ConfigGet, $Get);
        if (count($NewGet) > 0) {
            $NewURL = parse_url($HookData['Url']);
            $NewURL['query'] = http_build_query($NewGet);
            $HookData['Url'] = $this->unparse_url($NewURL);
        }
    }

    private function DeliveryRemoteFile(array $HookData, array $Get)
    {
        if ($HookData['allowGet']) {
            $this->BuildNewUrl($HookData, $Get);
        }
        $opts = [
            'http' => [
                'ignore_errors'    => true,
                'protocol_version' => 1.1,
                'timeout'          => 5.0,
                'header'           => [
                    'Connection: close'
                ]
            ],
            'ftp'  => [
                'ignore_errors' => true
            ]
        ];
        if ($HookData['weakSSL']) {
            $opts['ssl']['verify_peer'] = false;
            $opts['ssl']['verify_peer_name'] = false;
            $opts['ssl']['allow_self_signed'] = true;
        }
        $context = stream_context_create($opts);
        $fp = @fopen($HookData['Url'], 'rb', false, $context);
        if ($fp === false) {
            http_response_code(404);
            header('Content-Type: text/plain');
            header('Connection: close');
            header('Server: Symcon ' . IPS_GetKernelVersion());
            header('X-Powered-By: Hook Reverse Proxy');
            header('Expires: 0');
            header('Cache-Control: no-cache');
            header('Content-Type: text/plain');
            die('File not found!');
        }
        header($http_response_header[0]);
        header('Connection: close');
        header('Server: Symcon ' . IPS_GetKernelVersion());
        header('X-Powered-By: Hook Reverse Proxy');
        header('Expires: 0');
        header('Cache-Control: no-cache');
        if ($HookData['forceDL']) {
            header('Content-Description: File Transfer');
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . basename($HookData['Url']) . '"');
            header('Pragma: public');
        } else {
            foreach ($http_response_header as $Header) {
                if (stripos($Header, 'Content-Type:') !== false) {
                    header($Header);
                    break;
                }
            }
        }
        $Result = @fpassthru($fp);
        fclose($fp);
        $this->SendDebug('Send Bytes', $Result, 0);
        if ($Result === false) {
            header_remove();
            http_response_code(500);
            header('Content-Type: text/plain');
            header('Connection: close');
            header('Server: Symcon ' . IPS_GetKernelVersion());
            header('X-Powered-By: Hook Reverse Proxy');
            header('Expires: 0');
            header('Cache-Control: no-cache');
            header('Content-Type: text/plain');
            die('Server error!');
        }
    }

    /**
     * Interne Funktion des SDK.
     */
    protected function ProcessHookdata()
    {
        // SSL fehlt
        // Authentifizierung lokal einbauen
        $HookData = $this->GetURL($_SERVER['HOOK']);
        if ($HookData) {
            $URLScheme = parse_url($HookData['Url'], PHP_URL_SCHEME);
            if (in_array($URLScheme, ['http', 'https', 'ftp'])) {
                return $this->DeliveryRemoteFile($HookData, $_GET);
            }
            return $this->DeliveryLocalFile($HookData['Url'], $HookData['forceDL']);
        } else {
            http_response_code(404);
            header('Content-Type: text/plain');
            header('Connection: close');
            header('Server: Symcon ' . IPS_GetKernelVersion());
            header('X-Powered-By: Hook Reverse Proxy');
            header('Expires: 0');
            header('Cache-Control: no-cache');
            header('Content-Type: text/plain');
            die('File not found!');
        }
    }

    private function unparse_url($parsed_url)
    {
        $scheme = isset($parsed_url['scheme']) ? $parsed_url['scheme'] . '://' : '';
        $host = isset($parsed_url['host']) ? $parsed_url['host'] : '';
        $port = isset($parsed_url['port']) ? ':' . $parsed_url['port'] : '';
        $user = isset($parsed_url['user']) ? $parsed_url['user'] : '';
        $pass = isset($parsed_url['pass']) ? ':' . $parsed_url['pass'] : '';
        $pass = ($user || $pass) ? "$pass@" : '';
        $path = isset($parsed_url['path']) ? $parsed_url['path'] : '';
        $query = isset($parsed_url['query']) ? '?' . $parsed_url['query'] : '';
        $fragment = isset($parsed_url['fragment']) ? '#' . $parsed_url['fragment'] : '';
        return $scheme . $user . $pass . $host . $port . $path . $query . $fragment;
    }

    private function GetMimeType($extension)
    {
        $lines = file(IPS_GetKernelDirEx() . 'mime.types');
        foreach ($lines as $line) {
            $type = explode("\t", $line, 2);
            if (count($type) == 2) {
                $types = explode(' ', trim($type[1]));
                foreach ($types as $ext) {
                    if ($ext == $extension) {
                        return $type[0];
                    }
                }
            }
        }
        return 'text/plain';
    }
}

/* @} */
