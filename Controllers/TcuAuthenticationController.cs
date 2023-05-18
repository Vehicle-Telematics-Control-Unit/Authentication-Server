using AuthenticationServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Operators;
using System.Runtime.ConstrainedExecution;

namespace AuthenticationServer.Controllers
{
    [Route("api/TCU")]
    [ApiController]
    public class TCUAuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly TcuContext tcuContext;
        private readonly IConfiguration _config;

        public TCUAuthenticationController(TcuContext tcuContext, UserManager<IdentityUser> userManager, IConfiguration config) //RoleManager<IdentityRole> roleManager, IConfiguration config)
        {
            this.userManager = userManager;
            this.tcuContext = tcuContext;
            _config = config;
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

            byte[] bytes = new byte[certificate.Length];
            X509Certificate tcuCertificate;
            using (var reader = certificate.OpenReadStream())
            {
                await reader.ReadAsync(bytes.AsMemory(0, (int)certificate.Length));
                var parser = new X509CertificateParser();
                tcuCertificate = parser.ReadCertificate(bytes);
            }

            RsaKeyParameters keyPair;

            using (FileStream pemFileStream = new FileStream(@"D:\Valeo\Graduation project\AuthenticationServer\AuthenticationServer\Licences\public_key.pem", FileMode.Open))
            {
                var pemReader = new PemReader(new StreamReader(pemFileStream));
                keyPair = (RsaKeyParameters)pemReader.ReadObject();
            }


            try
            {
                tcuCertificate.Verify(keyPair);
            }
            catch
            {
                return Unauthorized();
            }


            DerObjectIdentifier macAddressOid = new DerObjectIdentifier("2.5.29.48"); // OID for subject alternative name
            Asn1OctetString macAddressExtension = tcuCertificate.GetExtensionValue(macAddressOid);
            string MAC = Encoding.UTF8.GetString(macAddressExtension.GetOctets());
            MAC = MAC.Substring(MAC.Length - 17);

#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.
            Tcu tcu = (from _tcu in tcuContext.Tcus
                       //where _tcu.Mac == MAC
                       //&& _tcu.Challenge == challengeBytes
                       select _tcu).FirstOrDefault();
#pragma warning restore CS8600 // Converting null literal or possible null value to non-nullable type.

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


            // Convert the hash bytes to a hexadecimal string representation
            var encryptedChallenge = engine.ProcessBlock(challengeBytes, 0, challengeBytes.Length);
            string tcuChallenge = Convert.ToBase64String(encryptedChallenge);
            
            if (secret != tcuChallenge)
                return Forbid();



            var user = await userManager.FindByIdAsync(tcu.UserId);
            #pragma warning disable CS8602 // Possible null reference argument.
            tcu.IpAddress = Request.HttpContext.Connection.RemoteIpAddress.ToString();
            #pragma warning restore CS8602 // Possible null reference argument.
            await tcuContext.SaveChangesAsync();

            var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, tcu.Vin),
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
        public async Task<IActionResult> SubmitCsr(IFormFile csrRequest,string VIN)
        {
            Tcu? tcu = (from _tcu in tcuContext.Tcus
                        where _tcu.Vin == VIN
                        //&& _tcu.IsValidated == false
                        select _tcu).FirstOrDefault();

            byte[] bytes = new byte[csrRequest.Length];
            X509Certificate chainedCertificate;

            using (var reader = csrRequest.OpenReadStream())
            {
                await reader.ReadAsync(bytes.AsMemory(0, (int)csrRequest.Length));
                var loadedCsr = new Pkcs10CertificationRequest(bytes);
                // Read the private key from the PEM file
                RsaPrivateCrtKeyParameters rsaParams;
                using (FileStream pemFileStream = new FileStream(@"D:\Valeo\Graduation project\AuthenticationServer\AuthenticationServer\Licences\private_key.pem", FileMode.Open))
                {
                    var pemReader = new PemReader(new StreamReader(pemFileStream));
                    rsaParams = (RsaPrivateCrtKeyParameters)pemReader.ReadObject();
                }

                // Create a new X509V3CertificateGenerator object
                var certGen = new X509V3CertificateGenerator();


                byte[] certificateData = System.IO.File.ReadAllBytes(@"D:\Valeo\Graduation project\AuthenticationServer\AuthenticationServer\Licences\certificate.crt");

                X509CertificateParser parser = new X509CertificateParser();
                X509Certificate certificate = parser.ReadCertificate(certificateData);

                certGen.SetIssuerDN(certificate.IssuerDN);
                certGen.SetSubjectDN(certificate.SubjectDN);

                // Set the validity period
                var notBefore = DateTime.UtcNow.Date;
                var notAfter = notBefore.AddDays(365);
                certGen.SetNotBefore(certificate.NotBefore);
                certGen.SetNotAfter(certificate.NotAfter);

                // Set the public key
                certGen.SetPublicKey(loadedCsr.GetPublicKey());

                var serialNumber = BigInteger.ProbablePrime(128, new Random());

                certGen.SetSerialNumber(serialNumber);

                // Create a new instance of SecureRandom
                SecureRandom random = new SecureRandom(new DigestRandomGenerator(new Sha256Digest()));
                GeneralName macAddressName = new GeneralName(GeneralName.OtherName, new DerUtf8String(tcu.Mac));
                Asn1Encodable macAddressExtensionValue = new GeneralNames(macAddressName);
                X509Extension macAddressExtension = new X509Extension(false, new DerOctetString(macAddressExtensionValue));
                certGen.AddExtension("2.5.29.48", true, macAddressExtensionValue);
                ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", rsaParams, random);
                // Create the signed certificate
                chainedCertificate = certGen.Generate(signatureFactory);
            }

            // Export the certificate to a byte array
            byte[] certBytes = chainedCertificate.GetEncoded();
            return File(certBytes, "application/x-x509-ca-cert", "ChainedCertficate.cer");
        }

        [HttpPost]
        [Route("challenge")]
        public async Task<IActionResult> requestChallenge(IFormFile chainedCerticate, string VIN)
        {
            X509Certificate cert;
            using (var reader = chainedCerticate.OpenReadStream())
            {
                byte[] bytes = new byte[chainedCerticate.Length];
                await reader.ReadAsync(bytes.AsMemory(0, (int)chainedCerticate.Length));
                cert = new X509Certificate(bytes);
            }


            X509Certificate serverCertificate;

            
           byte[] certBytes = System.IO.File.ReadAllBytes(@"D:\Valeo\Graduation project\AuthenticationServer\AuthenticationServer\Licences\certificate.crt");
           serverCertificate = new X509Certificate(certBytes);
            try
            {
                cert.Verify(serverCertificate.GetPublicKey());
            }
            catch
            {
                return Unauthorized();
            }

            var publicKey = cert.GetPublicKey();

            SecureRandom random = new SecureRandom(new DigestRandomGenerator(new Sha256Digest()));
            // Generate a random 32-byte array


            // Compute the SHA256 hash of the random bytes
            IDigest digest = DigestUtilities.GetDigest("SHA256");
            byte[] challenge = new byte[digest.GetDigestSize()];

            digest.BlockUpdate(challenge, 0, challenge.Length);

            digest.DoFinal(challenge, 0);
            
            Tcu tcu = (from _tcu in tcuContext.Tcus
                       where _tcu.Vin == VIN
                       select _tcu).First();

            
            string str = Convert.ToBase64String(challenge);
            

            IAsymmetricBlockCipher engine = new RsaEngine();
            engine.Init(true, publicKey);

            // Convert the hash bytes to a hexadecimal string representation
            var encryptedChallenge = engine.ProcessBlock(challenge, 0, challenge.Length);
            tcu.Challenge = encryptedChallenge;
            tcu.ExpiresAt = DateTime.Now.AddHours(12);
            tcuContext.SaveChanges();

            return File(
                encryptedChallenge,
                "application/octet-stream", 
                "challenge.bin");
        }


        private JwtSecurityToken GenerateJwtToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetValue<string>("JWT:Secret")));
            var token = new JwtSecurityToken(
                issuer: _config["JWT:ValidIssuer"],
                audience: _config["JWT:ValidAudience"],
                expires: DateTime.Now.AddMinutes(30),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );
            return token;
        }
    }
}
