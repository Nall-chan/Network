<?php

declare(strict_types=1);

include_once __DIR__ . '/stubs/Validator.php';

class LibraryTest extends TestCaseSymconValidation
{
    public function testValidateLibrary(): void
    {
        $this->validateLibrary(__DIR__ . '/..');
    }
    public function testValidateClientSplitter(): void
    {
        $this->validateModule(__DIR__ . '/../ClientSplitter');
    }
    public function testValidateDHCPSniffer(): void
    {
        $this->validateModule(__DIR__ . '/../DHCPSniffer');
    }
    public function testValidateHookReverseProxy(): void
    {
        $this->validateModule(__DIR__ . '/../HookReverseProxy');
    }
    public function testValidateWebSocketClient(): void
    {
        $this->validateModule(__DIR__ . '/../WebSocketClient');
    }
    public function testValidateWebSocketServer(): void
    {
        $this->validateModule(__DIR__ . '/../WebSocketServer');
    }
    public function testValidateWebSocketServerIfTest(): void
    {
        $this->validateModule(__DIR__ . '/../WebSocketServerIfTest');
    }
}
