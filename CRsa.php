<?php
/**
 * author: cty@20130321
 *   desc: 利用phpseclib进行RSA加密;
 *         公/私钥用linux命令ssh-keygen生成即可;
 *         前端JS的公钥用privatekey2publickey方法获取;
 *
 *   demo: 1,php加解密:
 *           $text = "abcdef=====";
 *           $cipher = $rsa->encrypt($text);
 *           echo $rsa->decrypt($cipher); 
 *
 *         2,js加密php解密:
 *           js:
 *           var publicKey = "fc1a1..."(由privatekey2publickey得到);
 *           function encrypt() {
 *               var rsa = new RSAKey();
 *               rsa.setPublic(publicKey, "10001");
 *               var cipher = rsa.encrypt(明文);
 *               return cipher;
 *           }
 *           php:
 *           $rsa = new CRsa();
 *           $rsa->decrypt(js返回的密文)
 *
 *
*/
include_once(__DIR__ . '/rsa/phpseclib/Crypt/RSA.php');

class CRsa{

    private $privateKey = "-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCYlSUk/nzEYBQjGlh7F4vU2NXjNd3Vv7eI98HXaaXNdfNUV5Af
8OoSI6F7lsQOj2xNV7RmALtAVXwckqUpzCushJZbv3uCxemIrqtt0eyI1LzhIekn
tTD/7qe73nxv4Gwyvs5AVpvx2LbL7LKA9cidaopgBUGd2c76VMyzvmoWsQIDAQAB
AoGBAIVGYPd7QkfVFEHFFVwPKRh1ff3EY0v89bcxkaMyqJxaVnxpL3521D2b2cU1
33JIXHUCEpS2Ntju0kWy4YksyUfCEFEIBDNtuIQVhCtCFKJFcQy+W6AGV3xPHG37
M5ibVtZ1Wh3UFXLy2n3PGHNhv0XHxL+rSV8+ELq3Al8Ajp6xAkEAx37at5D5t4Sy
2gqVaDMCSPYE8qqL45BUFKIIUXJ499pRS8dIVMom97S01iLsiAQ5JJzq9piZAPju
tNwBovHDGwJBAMPMsvSuQRChU1gNg3gW60QVWCdDxIqz2odSOQkNPSkmM+VUxNGY
hLOed5IbAiDMtj3m+/P764mb2eV3ougx3iMCQBNq8okJkHTfcrUscIx64o8Nez/P
f9w/kR+NAfhDhyjA1Ebm99Bg+NgFe9CYB6PZnWJF78ze342rrThnbbVZiN8CQDeP
jbSbAgGbFdBlvUnFjys5t1MlCs+lK7y8m0yzQgi8O3u3K0aitf1WWW3PVjJChPBZ
7GMWuIbK//D6mvKyu+sCQDQIvPlZRsfA3wsgvVWnLndaKjyCqkMxeMbdyTNJlNm7
DvJfU2u2l/g+4Qnx0jXeH7VlV4drjjnR7BJHbd0jswA=
-----END RSA PRIVATE KEY-----";
    //private key 可以用linux的ssh-keygen来生成
    
    
    private $publicKey = "-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAJiVJST+fMRgFCMaWHsXi9TY1eM13dW/t4j3wddppc1181RXkB/w6hIj
oXuWxA6PbE1XtGYAu0BVfBySpSnMK6yEllu/e4LF6Yiuq23R7IjUvOEh6Se1MP/u
p7vefG/gbDK+zkBWm/HYtsvssoD1yJ1qimAFQZ3ZzvpUzLO+ahaxAgMBAAE=
-----END RSA PUBLIC KEY-----";
    //这是专用于php
    //js的public key请用privatekey2publickey获取
    
    private $rsa = null;
    
    private function getRsa()
    {
        if(null === $this->rsa){
            $this->rsa = new Crypt_RSA();
        }
        return $this->rsa;
    }

    //根据private key得到public key(十六进制)(js模式)
    public function privatekey2publickey()
    {
        $rsa = $this->getRsa();
        $privateKey = $this->privateKey;
        $rsa->loadKey($privateKey);
        $raw = $rsa->getPublicKey(CRYPT_RSA_PUBLIC_FORMAT_RAW);
        // print_r(get_class_methods($raw['n']));
        // print_r($raw['n']->toString());
        // echo "\n";
        // print_r($raw['n']->toHex());
        return $raw['n']->toHex();
    }
    
    //解密
    public function decrypt($cipher)
    {
        $rsa = $this->getRsa();
        $privateKey = $this->privateKey;
        $cipher     = pack('H*', $cipher);
        $rsa->loadKey($privateKey);
        $rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);
        return $rsa->decrypt($cipher);
    }

    //加密(调试中...)
    public function encrypt($plain)
    {
        $rsa = $this->getRsa();
        $publicKey = $this->publicKey;
        $rsa->loadKey($publicKey);
        $rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);
        return $this->string2hex($rsa->encrypt($plain));
    }
    
    //16进制编码转换为汉字
    function hex2string($s)
    {
        $r = "";
        for($i=0; $i<strlen($s); $i += 2) {
            $x1 = ord($s{$i});
            $x1 = ($x1>=48 && $x1<58) ? $x1-48 : $x1-97+10;
            $x2 = ord($s{$i+1});
            $x2 = ($x2>=48 && $x2<58) ? $x2-48 : $x2-97+10;
            $r .= chr((($x1 << 4) & 0xf0) | ($x2 & 0x0f));
        }
        return $r;
    }

    //汉字转换为16进制编码
    function string2hex($s) {
        $r = "";
        $hexes = array ("0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f");
        for($i=0; $i<strlen($s); $i++) {
            $r .= ($hexes [(ord($s{$i}) >> 4)] . $hexes [(ord($s{$i}) & 0xf)]);
        }
        return $r;
    }


};