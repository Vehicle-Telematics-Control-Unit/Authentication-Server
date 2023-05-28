using AuthenticationServer.Data;
using AuthenticationServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthenticationServer.Controllers
{
    [Route("authentication/tcu")]
    [ApiController]
    public class TCUAuthenticationController : BaseController
    {
        private readonly RsaKeyParameters _publicKeyParameters;
        private readonly ISignatureFactory _signatureFactory;
        private readonly X509Certificate _serverCertificate;

        public TCUAuthenticationController(TcuContext tcuContext, UserManager<IdentityUser> userManager, IConfiguration config): base(tcuContext, userManager, config)
        {
            var certificatePath = config.GetSection("LicencesPaths:serverLicense").Value ?? throw new FileNotFoundException();
            var publicKeyPath = config.GetSection("LicencesPaths:publicKey").Value ?? throw new FileNotFoundException();
            var privateKeyPath = config.GetSection("LicencesPaths:privateKey").Value?? throw new FileNotFoundException();
            using (FileStream pemFileStream = new(publicKeyPath, FileMode.Open))
            {
                var pemReader = new PemReader(new StreamReader(pemFileStream));
                _publicKeyParameters = (RsaKeyParameters)pemReader.ReadObject();
            }
            using (FileStream pemFileStream = new(privateKeyPath, FileMode.Open))
            {
                var pemReader = new PemReader(new StreamReader(pemFileStream));
                var privateKeyParamters = (RsaPrivateCrtKeyParameters)pemReader.ReadObject();
                _signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", privateKeyParamters, new SecureRandom());
            }
            byte[] certificateData = System.IO.File.ReadAllBytes(certificatePath);            
            _serverCertificate = new(certificateData);
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login(IFormFile challenge, IFormFile certificate)
        {
            byte[] challengeBytes;

            using (var stream = new MemoryStream())
            {
                await challenge.CopyToAsync(stream);
                challengeBytes = stream.ToArray();
            }
            byte[] bytes = await ParseIformFile(certificate);
            X509Certificate tcuCertificate = new(bytes);
            try
            {
                tcuCertificate.Verify(_publicKeyParameters);
            }
            catch
            {
                return Unauthorized();
            }
            string? MAC = GetMAC_FromCertificate(tcuCertificate);

            if (MAC == null)
                return Forbid();

            Tcu? tcu = (from _tcu in tcuContext.Tcus
                       where _tcu.Mac == MAC
                       select _tcu).FirstOrDefault();
            
            if (tcu == null)
                return Unauthorized();
            if (tcu.Challenge == null)
                return BadRequest();
            if (DateTime.Now > tcu.ExpiresAt)
                return Ok(new
                {
                    statusCode = -1
                });
            string secret = Convert.ToBase64String(tcu.Challenge);
            IAsymmetricBlockCipher engine = new RsaEngine();
            engine.Init(true, tcuCertificate.GetPublicKey());
            var encryptedChallenge = engine.ProcessBlock(challengeBytes, 0, challengeBytes.Length);
            string tcuChallenge = Convert.ToBase64String(encryptedChallenge);
            if (secret != tcuChallenge)
                return Forbid();
            var user = await userManager.FindByIdAsync(tcu.UserId);
            var ipAAddress = resolveIPAddress(Request.HttpContext);
            if (ipAAddress != null)
                tcu.IpAddress = ipAAddress;
            await tcuContext.SaveChangesAsync();
            var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, tcu.Mac),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim("TCU", "True")
                };
            var token = GenerateJwtToken(authClaims);
            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                expiration = token.ValidTo
            });
        }


        [HttpPost]
        [Route("csr")]
        public async Task<IActionResult> SubmitCsr(IFormFile csrRequest,[FromForm] string MAC_Address)
        {
            Tcu? tcu = (from _tcu in tcuContext.Tcus
                        where _tcu.Mac == MAC_Address
                        select _tcu).FirstOrDefault();
            if (tcu == null)
                return NotFound();
            byte[] bytes = await ParseIformFile(csrRequest);
            Pkcs10CertificationRequest csr = new(bytes);
            if (csr.Verify() == false)
                return BadRequest();
            var certGen = new X509V3CertificateGenerator();
            certGen.SetIssuerDN(_serverCertificate.IssuerDN);
            certGen.SetSubjectDN(_serverCertificate.SubjectDN);
            certGen.SetNotBefore(_serverCertificate.NotBefore);
            certGen.SetNotAfter(_serverCertificate.NotAfter);
            certGen.SetPublicKey(csr.GetPublicKey());
            var serialNumber = GenerateSerialNumber();
            certGen.SetSerialNumber(serialNumber);
            GeneralName macAddressName = new (GeneralName.OtherName, new DerUtf8String(tcu.Mac));
            Asn1Encodable macAddressExtensionValue = new GeneralNames(macAddressName);
            X509Extension macAddressExtension = new(false, new DerOctetString(macAddressExtensionValue));
            certGen.AddExtension("2.5.29.48", true, macAddressExtensionValue);
            X509Certificate chainedCertificate = certGen.Generate(_signatureFactory);
            return File(chainedCertificate.GetEncoded(), 
                "application/x-x509-ca-cert", 
                "ChainedCertficate.cer");
        }


        [HttpPost]
        [Route("challenge")]
        public async Task<IActionResult> RequestChallenge(IFormFile chainedCertificateFile)
        {
            byte[] certificateBytes = await ParseIformFile(chainedCertificateFile);
            X509Certificate chainedCerticate = new(certificateBytes);
            try
            {
                chainedCerticate.Verify(_serverCertificate.GetPublicKey());
            }
            catch
            {
                return Unauthorized();
            }
            AsymmetricKeyParameter publicKey = chainedCerticate.GetPublicKey();
            string? MAC = GetMAC_FromCertificate(chainedCerticate);
            if (MAC == null)
                return Forbid();
            byte[] challenge = GenerateChallege();
            Tcu? tcu = (from _tcu in tcuContext.Tcus
                       where _tcu.Mac == MAC
                       select _tcu).FirstOrDefault();
            if (tcu == null)
                return NotFound();
            IAsymmetricBlockCipher engine = new RsaEngine();
            engine.Init(true, publicKey);
            var encryptedChallenge = engine.ProcessBlock(challenge, 0, challenge.Length);
            tcu.Challenge = encryptedChallenge;
            tcu.ExpiresAt = DateTime.Now.AddHours(12);
            tcuContext.SaveChanges();
            return File(
                encryptedChallenge,
                "application/octet-stream",
                "challenge.bin");
        }



        private static byte[] GenerateChallege()
        {
            var digestor = DigestUtilities.GetDigest("SHA256");
            byte[] challenge = new byte[digestor.GetDigestSize()];
            digestor.BlockUpdate(challenge, 0, challenge.Length);
            digestor.DoFinal(challenge, 0);
            return challenge;
        }

        private static string? GetMAC_FromCertificate(X509Certificate certificate)
        {
            string? MAC;
            DerObjectIdentifier macAddressOid = new("2.5.29.48"); // OID for subject alternative name
            try
            {
                Asn1OctetString macAddressExtension = certificate.GetExtensionValue(macAddressOid);
                MAC = Encoding.UTF8.GetString(macAddressExtension.GetOctets());
            }
            catch
            {
                return null;
            }
            return MAC[^17..];
        }

        private static BigInteger GenerateSerialNumber()
        {
            SecureRandom random = new();
            return BigInteger.ProbablePrime(128, random);
        }
    }
}
