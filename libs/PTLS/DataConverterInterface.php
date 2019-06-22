<?php

declare(strict_types=1);

namespace PTLS;

interface DataConverterInterface
{
    /**
     * Unserialize.
     */
    public function encode($data);

    /**
     *  Serialize to TLS format.
     */
    public function decode();
}
