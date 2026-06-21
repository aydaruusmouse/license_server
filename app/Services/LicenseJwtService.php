<?php

namespace App\Services;

use App\Models\AppAccount;
use App\Models\License;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Illuminate\Support\Str;
use UnexpectedValueException;

class LicenseJwtService
{
    public function readPublicKeyPem(): string
    {
        $keyPath = (string) config('licensing.public_key_path');
        if (! is_readable($keyPath)) {
            throw new \RuntimeException(
                'License public key not readable at '.$keyPath.'. Fix storage/keys permissions for PHP-FPM user.'
            );
        }
        $public = file_get_contents($keyPath);
        if ($public === false || trim($public) === '') {
            throw new \RuntimeException('License public key missing at '.$keyPath);
        }

        return trim($public);
    }

    public function issue(License $license, string $deviceId, ?AppAccount $account = null): string
    {
        $cfg = config('licensing.jwt');
        $now = time();
        $ttl = max(60, (int) $cfg['ttl_seconds']);
        $exp = $this->resolveTokenExpUnix($license, $now, $ttl);

        $keyPath = (string) config('licensing.private_key_path');
        if (! is_readable($keyPath)) {
            throw new \RuntimeException(
                'License private key not readable at '.$keyPath.'. Fix: chown nginx:nginx storage/keys/private.pem && chmod 640 storage/keys/private.pem'
            );
        }
        $private = file_get_contents($keyPath);
        if ($private === false || $private === '') {
            throw new \RuntimeException('License private key missing. Generate storage/keys/private.pem');
        }

        $payload = [
            'iss' => $cfg['issuer'],
            'aud' => $cfg['audience'],
            'iat' => $now,
            'nbf' => $now,
            'exp' => $exp,
            'jti' => (string) Str::uuid(),
            'sub' => (string) $license->id,
            'lid' => (string) $license->id,
            'did' => $deviceId,
        ];

        if ($account !== null) {
            $payload['aid'] = (string) $account->id;
            $payload['phone'] = $account->phone;
        }

        return JWT::encode($payload, $private, 'RS256');
    }

    /**
     * @return object{sub:string,lid:string,did:string,exp:int,iat:int,jti:string}
     */
    public function decode(string $jwt): object
    {
        $public = file_get_contents(config('licensing.public_key_path'));
        if ($public === false || $public === '') {
            throw new \RuntimeException('License public key missing.');
        }

        $cfg = config('licensing.jwt');

        try {
            $decoded = JWT::decode($jwt, new Key($public, 'RS256'));
        } catch (ExpiredException|SignatureInvalidException|UnexpectedValueException $e) {
            throw new \InvalidArgumentException('Invalid token', 0, $e);
        }

        if (($decoded->iss ?? null) !== $cfg['issuer']) {
            throw new \InvalidArgumentException('Invalid issuer');
        }
        if (($decoded->aud ?? null) !== $cfg['audience']) {
            throw new \InvalidArgumentException('Invalid audience');
        }

        return $decoded;
    }

    /**
     * JWT lifetime is the shorter of configured TTL and portal [License::expires_at] (when set).
     */
    private function resolveTokenExpUnix(License $license, int $now, int $ttl): int
    {
        $exp = $now + $ttl;
        if ($license->expires_at !== null) {
            $licenseEnd = $license->expires_at->getTimestamp();
            if ($licenseEnd <= $now) {
                throw new \RuntimeException('License already expired');
            }
            $exp = min($exp, $licenseEnd);
        }

        return max($now + 60, $exp);
    }
}
