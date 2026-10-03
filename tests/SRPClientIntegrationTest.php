<?php
/*
 * (c) Dmitri Petmanson <dpetmanson@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests;

use Exception;
use Laizerox\Wowemu\SRP\HostClient;
use Laizerox\Wowemu\SRP\UserClient;
use phpseclib3\Math\BigInteger;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class SRPClientIntegrationTest extends TestCase
{
    public function testHandshakeMatchesPhpseclib2Vectors(): void
    {
        // Captured before migrating from phpseclib 2, with fixed private ephemerals.
        $salt = '12ee32e201835ebc6a00c7056f08e18651633ab9cec6cfd5a1bdda413747c74c';
        $verifier = '2b25415d6fd90435b9506f64c15e0670bef49a9905d62f21eb573dc4ff2bbaf0';
        $user = $this->getMockBuilder(UserClient::class)
            ->setConstructorArgs(['admin', $salt])
            ->onlyMethods(['generateSecretEphemeralValue'])
            ->getMock();
        $user->expects($this->once())->method('generateSecretEphemeralValue')
            ->willReturn(new BigInteger('123456789abcdef123456789abcdef', 16));

        $A = $user->getPublicEphemeralValue();
        $this->assertSame('1af38658d0a401b48f54168ae30f27567c93668904d7eebc97e3507ad542fba1', $A);

        $host = $this->getMockBuilder(HostClient::class)
            ->setConstructorArgs(['admin', $salt, $verifier, $A])
            ->onlyMethods(['generateSecretEphemeralValue'])
            ->getMock();
        $host->expects($this->once())->method('generateSecretEphemeralValue')
            ->willReturn(new BigInteger('fedcba987654321fedcba987654321', 16));

        $B = $host->getPublicEphemeralValue();
        $this->assertSame('3f81fc3b4a3a564dc8ecaae35b7fcc6f98344ed5d3591a6468d39d7ebb5f58ca', $B);
        // This vector also exercises modular exponentiation with a negative B - 3v.
        $this->assertTrue((new BigInteger($B, 16))->subtract(
            (new BigInteger($verifier, 16))->multiply(new BigInteger(3))
        )->isNegative());

        $user->setHostPublicEphemeralValue($B);
        $user->calculateSessionKey($user->computePrivateKey('admin'));
        $host->calculateSessionKey();

        $sessionKey = '5c96b7ab4a7aad15847ae8164c0336599e90121280a8e3b81edf1f3f97ed8196';
        $strongSessionKey = '7c44a07eccc4fadad8d67b4ca384c424f845e0d2';
        $this->assertSame($sessionKey, $user->getSessionKey());
        $this->assertSame($sessionKey, $host->getSessionKey());
        $this->assertSame($strongSessionKey, $user->getStrongSessionKey());
        $this->assertSame($strongSessionKey, $host->getStrongSessionKey());

        $clientProof = $user->computeClientSessionKeyProof();
        $this->assertSame('11cc49973d0dc7bf598e982c92f77084668015e9', $clientProof);
        $this->assertTrue($host->validateClientSessionKeyProof($clientProof));
        $hostProof = $host->computeHostSessionKeyProof($clientProof);
        $this->assertSame('b398c88866538d07fc666a2ad6b39c0a7f5963a4', $hostProof);
        $this->assertTrue($user->validateHostSessionKeyProof($clientProof, $hostProof));
    }

    public static function dataProvider(): array
    {
        return [
            [
                // Client known values
                [
                    'username' => 'admin',
                    'password' => 'admin',
                ],
                // Host known values
                [
                    'salt'     => '12ee32e201835ebc6a00c7056f08e18651633ab9cec6cfd5a1bdda413747c74c',
                    'verifier' => '2b25415d6fd90435b9506f64c15e0670bef49a9905d62f21eb573dc4ff2bbaf0',
                ],
            ],
            [
                // Client known values
                [
                    'username' => 'player',
                    'password' => 'player',
                ],
                // Host known values
                [
                    'salt'     => '50b39832882cc3174f4b566d377775ecc33af5f21fa71bcac58290595101d4e9',
                    'verifier' => '59f9d68f247ff723c46677847e042923184307f652c297726da2868670c607bf',
                ],
            ],
        ];
    }

    /**
     * @param  array  $client
     * @param  array  $host
     *
     * @throws Exception
     */
    #[DataProvider('dataProvider')]
    public function testClientHostIntegration(array $client, array $host): void
    {
        $srpUserClient = new UserClient($client['username']);

        // 1. Client should generate public ephemeral value A and send username I to host
        $A = $srpUserClient->getPublicEphemeralValue();

        // 2. Host receives username I and public ephemeral value A.
        $srpHostClient = new HostClient($client['username'], $host['salt'], $host['verifier'], $A);
        $B = $srpHostClient->getPublicEphemeralValue();

        // 3. Client calculates its own session key
        $srpUserClient->setSalt($host['salt']);
        $srpUserClient->setHostPublicEphemeralValue($B);
        $srpUserClient->calculateSessionKey($srpUserClient->computePrivateKey($client['password']));

        // 4. Client sends proof of its session key to host
        $userSessionProof = $srpUserClient->computeClientSessionKeyProof();

        // 5. Host calculates its own session key
        $srpHostClient->calculateSessionKey();

        // 6. Host compares clients proof against its own equivalent client calculated proof
        $this->assertTrue($srpHostClient->validateClientSessionKeyProof($userSessionProof));

        // 7. Host computes & sends proof of its session key to client
        $hostSessionProof = $srpHostClient->computeHostSessionKeyProof(
            $srpHostClient->computeClientSessionKeyProof()
        );

        // 8. Client compares hosts proof against its own equivalent host calculated proof
        $this->assertTrue($srpUserClient->validateHostSessionKeyProof($userSessionProof, $hostSessionProof));

        // 9. In theory if both proofs match session keys should be same
        $this->assertEquals($srpHostClient->getSessionKey(), $srpUserClient->getSessionKey());
        $this->assertEquals($srpHostClient->getStrongSessionKey(), $srpUserClient->getStrongSessionKey());
    }
}
