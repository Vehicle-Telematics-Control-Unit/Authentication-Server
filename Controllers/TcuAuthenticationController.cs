using AuthenticationServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;

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
        public async Task<IActionResult> Login(string VIN, IFormFile certificate)
        {
            byte[] bytes = new byte[certificate.Length];
            X509Certificate2 x509Certificate;
            using (var reader = certificate.OpenReadStream())
            {
                await reader.ReadAsync(bytes.AsMemory(0, (int)certificate.Length));
                x509Certificate = new(bytes);
            }

            var vehicle = (from _vehicle in tcuContext.Tcus
                           where _vehicle.IsValidated
                           && _vehicle.Vin == VIN
                           && _vehicle.Thumbprint == x509Certificate.Thumbprint
                           select _vehicle).FirstOrDefault();

            if (vehicle == null)
                return Unauthorized();
            var user = await userManager.FindByIdAsync(vehicle.UserId);
            #pragma warning disable CS8602 // Possible null reference argument.
            vehicle.IpAddress = Request.HttpContext.Connection.RemoteIpAddress.ToString();
            #pragma warning restore CS8602 // Possible null reference argument.
            await tcuContext.SaveChangesAsync();

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, vehicle.Vin),
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
        public async Task<IActionResult> SubmitCsr(IFormFile tcuCertificate, string VIN)
        {
            byte[] certificateData = System.IO.File.ReadAllBytes(@"D:\AASTMT\Graduation project\AuthenticationServer\AuthenticationServer\Licences\VehiclePlus.crt");
            X509Certificate2 rootCertificate = new(certificateData);

            byte[] bytes = new byte[tcuCertificate.Length];
            Pkcs10CertificationRequest csr;

            using (var reader = tcuCertificate.OpenReadStream())
            {
                await reader.ReadAsync(bytes.AsMemory(0, (int)tcuCertificate.Length));
                csr = new Pkcs10CertificationRequest(bytes);
            }

            // Verify the CSR
            if (!csr.Verify())
            {
                // CSR signature is not valid
                return BadRequest();
            }

            Tcu? tcu = (from _tcu in tcuContext.Tcus
                       where _tcu.Vin == VIN
                       && _tcu.IsValidated == false
                       select _tcu).FirstOrDefault();

            if (tcu == null)
                return BadRequest();

            // Verify the CSR
            if (tcu == null || !csr.Verify())
            {
                // CSR signature is not valid
                return BadRequest();
            }


            // Generate the certificate serial number
            var serialNumber = DateTime.Now.Ticks;

            // Create the certificate generator
            var certGenerator = new X509V3CertificateGenerator();


            // Set the certificate properties
            certGenerator.SetSerialNumber(new BigInteger(serialNumber.ToString()));
            certGenerator.SetSubjectDN(csr.GetCertificationRequestInfo().Subject);
            byte[] x500Bytes = rootCertificate.SubjectName.RawData;

            // Parse the byte array to get an X509Name object
            X509Name x509Name = X509Name.GetInstance(x500Bytes);

            certGenerator.SetIssuerDN(x509Name);
            certGenerator.SetNotBefore(DateTime.UtcNow.Date);
            certGenerator.SetNotAfter(DateTime.UtcNow.Date.AddDays(365));
            certGenerator.SetPublicKey(csr.GetPublicKey());

            string privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDXj0plHTLop+Xa7wDVkWiiwohTxdGUPe1+LaWLhdbjSMmXapVlx3jTzeBpijRyxbOKZ6MkJ+fp0jOlmX02aSuhirUJL1VP6tg9diVAQiDjrQuOEyGtVhwsq4R2pKNe28jeB8BiCs37+i4lML8bWbHeK1yK9l2dgqXbhiOtGRwizh12CLwvpnSn2XEOXb7f4toatE63nKK9os3s77BwRBH2zJF9fQEwmDUZ2vc2bjRZhmDZmkoI5TPpWFjwEVcfyhVsv/Pm2gYYQAcjCB0QVyfs73mm9hAJ0pc5r3Mr8OG7KVJ3g0dM+tg2QxvCvVCd9id9QSV5Sc4PP+4e0Zh0p3epAgMBAAECggEAZ4dWf8HKVZtt9fycNfakfqdXuoRj6ALmMZfSznP1hSvMRoDWSA/JpFBY29eY4Ra66FpmLFNOOyrNy1cwoBVa8zcfQ84L91ofiUVZFser7C2MQyxFHG8jEQE/mYvxOvnsO1cVuwDddYvu5cXHw2cM2luREtzIkYHSDuEZ+WT58mySSm/3ypWbP2z3g0pGxGlmX9YGZhJbrSfC/uK8pOe/yYYk4BrxhZ4xNGtwflBnCVNqSIX9ES+Od2BNxjqukeAJkSg0DpaR2MzaH0CbwEVk3BHz0aqixClBV98/uCQktuziodeI6JUxhoORfWwWkK34rTv/UT8LW+ygykyufTJIQQKBgQDzAl6e7Jq9S+k8tFxIv2kcnLZFd8glQhv50+T+qK7H857ety9FV9V9zwX8M6H1nlLyvatPlZW6R/SmgpyXKK5Aw6nu4s74xSN2yjZzpLKkODXD9wnMFxniKcpT6bzkQ6+hgMcVeJsKHZva4oDOKicLzY5M5pC17R++q0zGXCkb5QKBgQDjFUTKDhI1OEfbNbeYbVEE5DT3ObUt8ahWAxFuu4r4eZ1McN/K301QoV0fXkXGvIweFEDqUiePb5/XM5Od7ndh4BWejCvXbE1v0DlzBMPNQCNHgIC1bpsfb1dZCqu8cP0DYSoiBInBUDXYJSC6C2g6iKdj1eqaqbjjXa1qRLtYdQKBgQC43GGcpkMko52/ZzkYwju032YtPGzOIxdjGpWGQE4Nn7+Ij3PvXVz0Qsu7yo93aMSTEkRC23k2Z0yuaoey2eiNLguUxYdLabSLxlJb8LtQ/82u0LvsPNqc2MuowBPI1dDCnFNWexP+Qv3wKgRwUVK4wNtylqcZLlTK2EckUrGXHQKBgFnm37cG3xqGz5vvpmIIVV0UZAvEowAvfi+fQ1WNljVNIINU5KTSxy8200FJ92H435hA+HpMUDEvRh7S4oxSDp2HM8fzQqAk1nt/+l6Y8lPeIpl6PHqX8X3+fJxZ5yfRq7mczCtvlIIeGVMbT9uYDImv9GVIGXtl2jbZrYA2+dzJAoGAVUNOnaTm09EmZnXD3d7oxixWLKXMu7rgJVLzTiN/qrUO5/qJJVEDPJ1ZX0tsyy/JbeLOwincj0J7JbU3ljtPEXXqrR7Rv3mTzVef1TqxP8qOjaz+xRGpBK4PuV3J2Few7id6hAr7SCDHIkfFr25dmRwfa5A6zdPgajLmnkE5CBk=";
            byte[] keyBytes = Convert.FromBase64String(privateKey);

            RsaPrivateCrtKeyParameters rsaPrivateKey = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(keyBytes);
            ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", rsaPrivateKey);
            // Sign the certificate with the root private key
            var cert = certGenerator.Generate(signatureFactory);

            // Convert the certificate to X509Certificate2
            var x509Certificate = new X509Certificate2(cert.GetEncoded());

            tcu.Thumbprint = x509Certificate.Thumbprint;
            tcu.IsValidated = true;

            return File(
                x509Certificate.Export(X509ContentType.Cert),
                "application/x-x509-ca-cert",
                "cert.cer");
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
